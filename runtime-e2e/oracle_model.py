# SPDX-License-Identifier: Apache-2.0
"""Shared evidence model for the core-topology oracles (money M1-M14, order O1-O12).

A *core sample* is one JSON document collected at a two-sample quiescence barrier. Every amount
is an exact int in 1e-8 units. Keys (all required unless marked optional):

  version          "core-sample-v2"
  markets          {"<marketId>": {"base": assetId, "quote": assetId}}
  risk             {"<marketId>": {"slippage_bps": n}}  the RiskConfigSet values the drill sent (stop-BUY estimate)
  genesis          {"verified": true, "balances": [], "holds": [], "live_orders": [], "last_applied_trade_id": 0}
  funding          [{"request": [hi, lo], "kind": "deposit"|"withdraw", "user", "asset", "amount",
                     "outcome": "ACK"|"REJECT"|"UNKNOWN", "gate": "OPEN"|"SUSPENDED"}]
  creates          [{"request": [hi, lo], "user", "market", "side": "BUY"|"SELL", "type", "tif", "price",
                     "quantity", "budget", "stop_price", "display_qty",
                     "reply": {"outcome": "ACK", "order", "duplicate", "hold_asset", "hold_amount"}
                            | {"outcome": "REJECT", "reason"} | {"outcome": "UNKNOWN"}}]
  amends           [{"request", "user", "order", "new_price", "new_quantity", "reply": {...}}]
  cancels          [{"request", "user", "order", "reply": {...}}]
  core             {"balances": [{"user","asset","available","locked"}], "holds": [{"order","user","asset","remaining"}],
                    "live_orders": [{"order","user","market","status","side","type","price","quantity","filled",
                                     "remaining","hold_asset","hold_amount","me_order_id", ...}],
                    "last_applied_trade_id", "pending_dispatch": {"count", "head"}}
  core_events      [{"seq","order","kind","status","filled","quantity","hold_remaining", ...}]  OrderEvent tap (orders channel)
  admission        [{"market","state","reason","log_position"}]                     AdmissionState tap (control)
  dispatch_tap     [{"seq","id_high","id_low","kind","order","user","old_leg","market","price","quantity","budget","at_ms"}]
  me_journal       normalized events from journal_decode (type trade|terminal|outcome|release|engine_config)
  me_journal_seq   true when the ME journal profile carries journalSeq/meEpoch (schema 4), else false
  me_open_legs     [{"leg","order", "user" (optional)}]                             ME OpenOrdersSnapshot (27)

Ownership is anchored on the probe's own create log: an ME trade, a dispatch or a resting leg naming a
user other than the creating user is a FAIL (M2, O4). Holds are recomputed from the create intent
(M5), never read back from the engine's ACK.
  money_journal    [{"seq","kind": "deposit"|"withdraw"|"settle", "user","asset","amount",
                     "trade","buyer","seller","market","price","quantity", "me_epoch" (optional)}]
  money_journal_legs [{"seq","user","asset" or null,"role" or null,"balance_after"}]
  faults           {"settle_fault", "settle_rejected", "order_fault", "quarantined"}  observed counts
  counters         optional {"stale_outcomes","redundant_outcomes","stale_terminals","conflicts"} (G6 export)
  declared         {"settle_fault","settle_rejected","order_fault","quarantined","halt","fault_open",
                    "forwarder_absent","gate_sequence": [[state, reason], ...] | null, "epochs": [e, ...]}
  barrier          {"input_closed": true, "samples": [obs, obs]} with obs.<collection>_digest = fingerprint
"""
from collections import defaultdict

from contracts import FP, Inconclusive, Violation, fingerprint, integer

TERMINAL = {'FILLED', 'CANCELLED', 'REJECTED', 'EXPIRED'}
PENDING = {'PENDING_NEW', 'PENDING_CANCEL', 'PENDING_REPLACE'}
KIND_CODES = {'CREATE': 0, 'CANCEL': 1, 'AMEND': 2}
BARRIER_COLLECTIONS = ['core', 'core_events', 'dispatch_tap', 'me_journal', 'me_open_legs', 'money_journal',
                       'money_journal_legs']


def quote(price, quantity):
    """Exact quote amount, floored, as FixedPoint.multiply for non-negative operands."""
    return integer(price) * integer(quantity) // FP


def request_key(value):
    if not isinstance(value, list) or len(value) != 2 or any(type(v) is not int for v in value):
        raise Inconclusive('request id must be [high, low] exact integers')
    if value == [0, 0]:
        raise Violation('request id 0/0 is MISSING_REQUEST_ID and cannot be acknowledged')
    return tuple(value)


def check_barrier(sample):
    if sample.get('version') != 'core-sample-v2':
        raise Inconclusive('unknown core sample version')
    missing = [k for k in ['markets', 'risk', 'genesis', 'funding', 'creates', 'amends', 'cancels', 'core', 'core_events',
                           'admission', 'dispatch_tap', 'me_journal', 'me_journal_seq', 'me_open_legs',
                           'money_journal', 'money_journal_legs', 'faults', 'declared', 'barrier'] if k not in sample]
    if missing:
        raise Inconclusive('core sample lacks evidence: ' + ', '.join(missing))
    if sample['genesis'].get('verified') is not True:
        raise Inconclusive('empty genesis not verified')
    genesis = sample['genesis']
    if genesis['balances'] or genesis['holds'] or genesis['live_orders'] or genesis['last_applied_trade_id'] != 0:
        raise Violation('fixture did not start from an empty financial and order genesis')
    barrier = sample['barrier']
    samples = barrier.get('samples', [])
    if barrier.get('input_closed') is not True or len(samples) != 2 or samples[0] != samples[1]:
        raise Inconclusive('no stable two-sample quiescence barrier after input closed')
    for name in BARRIER_COLLECTIONS:
        if samples[1].get(name + '_digest') != fingerprint(sample[name]):
            raise Inconclusive('observation does not belong to the barrier: ' + name)


class Model:
    """Indexes built once; rules read them and never mutate."""

    def __init__(self, sample):
        self.s = sample
        self.markets = {int(k): v for k, v in sample['markets'].items()}
        self.declared = sample['declared']
        self.journal = sample['me_journal']
        self.trades = [e for e in self.journal if e['type'] == 'trade']
        self.terminals = [e for e in self.journal if e['type'] == 'terminal']
        self.outcomes = [e for e in self.journal if e['type'] == 'outcome']
        self.live = {}
        for row in sample['core']['live_orders']:
            oid = integer(row['order'])
            if oid in self.live:
                raise Violation('core order snapshot repeats order ' + str(oid))
            self.live[oid] = row
        # Accepted creates: first non-duplicate ACK per requestId defines the order.
        self.orders = {}
        self.create_by_request = {}
        for create in sample['creates']:
            reply = create['reply']
            if reply.get('outcome') != 'ACK':
                continue
            key = request_key(create['request'])
            oid = integer(reply['order'])
            if key not in self.create_by_request:
                self.create_by_request[key] = oid
                if oid in self.orders:
                    continue  # O1 reports a second requestId sharing an order id
                self.orders[oid] = create
        self.order_requests = defaultdict(set)
        for key, oid in self.create_by_request.items():
            self.order_requests[oid].add(key)
        self.fills = defaultdict(int)
        self.quote = defaultdict(int)
        self.trade_legs = defaultdict(set)
        self.trade_prices = defaultdict(list)
        for trade in self.trades:
            for order, leg, buy in [(trade['taker_order'], trade['taker_leg'], trade['taker_is_buy']),
                                    (trade['maker_order'], trade['maker_leg'], not trade['taker_is_buy'])]:
                self.fills[order] += integer(trade['quantity'])
                self.quote[order] += quote(trade['price'], trade['quantity'])
                self.trade_legs[order].add(leg)
                self.trade_prices[order].append((integer(trade['price']), buy))
        self.tap = {}
        for row in sample['dispatch_tap']:
            key = (integer(row['id_high']), integer(row['id_low']))
            if key in self.tap:
                raise Violation('dispatch tap saw command id twice as a new dispatch: ' + str(key))
            self.tap[key] = row
        self.first_outcome = {}
        self.outcome_copies = defaultdict(list)
        for event in self.outcomes:
            key = (integer(event['command_id_high']), integer(event['command_id_low']))
            self.outcome_copies[key].append(event)
            self.first_outcome.setdefault(key, event)

    def check_ownership(self):
        """Every ME trade leg, dispatch and resting leg belongs to the user who created the order."""
        for trade in self.trades:
            for order, user in [(trade['taker_order'], trade['taker_user']), (trade['maker_order'], trade['maker_user'])]:
                create = self.orders.get(order)
                if create is None:
                    raise Violation(f'ME trade {trade["trade_id"]} on order {order} that no accepted request created')
                if create['user'] != user:
                    raise Violation(f'ME trade {trade["trade_id"]}: order {order} belongs to {create["user"]}, trade says {user}')
        for row in self.s['dispatch_tap']:
            create = self.orders.get(row['order'])
            if create is not None and create['user'] != row['user']:
                raise Violation(f'dispatch {row["seq"]}: order {row["order"]} belongs to {create["user"]}, dispatch says {row["user"]}')
        for row in self.s['me_open_legs']:
            create = self.orders.get(row['order'])
            if create is not None and 'user' in row and create['user'] != row['user']:
                raise Violation(f'ME leg {row["leg"]}: order {row["order"]} belongs to {create["user"]}, ME says {row["user"]}')

    def buyer_seller(self, trade):
        taker = (trade['taker_user'], trade['taker_order'])
        maker = (trade['maker_user'], trade['maker_order'])
        return (taker, maker) if trade['taker_is_buy'] else (maker, taker)

    def market(self, market_id):
        market = self.markets.get(int(market_id))
        if market is None:
            raise Inconclusive('missing market/asset mapping for market ' + str(market_id))
        return market

    def hold_asset(self, create):
        market = self.market(create['market'])
        return market['quote'] if create['side'] == 'BUY' else market['base']

    def amend_chain(self, oid):
        """Resolved amends of one order in submission order: (new_price, new_qty, delta, applied, resolved)."""
        create = self.orders[oid]
        price, qty = create['price'], create['quantity']
        dispatches = sorted((row for row in self.s['dispatch_tap'] if row['order'] == oid and row['kind'] == 'AMEND'),
                            key=lambda row: row['seq'])
        acked = [a for a in self.s['amends'] if a['order'] == oid and a['reply'].get('outcome') == 'ACK'
                 and not a['reply'].get('duplicate')]
        if len(acked) != len(dispatches):
            raise Inconclusive(f'order {oid}: {len(acked)} accepted amends but {len(dispatches)} AMEND dispatches tapped')
        chain = []
        for amend, dispatch in zip(acked, dispatches):
            new_price = amend['new_price'] or price
            new_qty = amend['new_quantity'] or qty
            filled_at_submit = new_qty - integer(dispatch['quantity'])
            if create['side'] == 'BUY':
                delta = quote(new_price, new_qty - filled_at_submit) - quote(price, qty - filled_at_submit)
            else:
                delta = new_qty - qty
            outcome = self.first_outcome.get((integer(dispatch['id_high']), integer(dispatch['id_low'])))
            applied = outcome is not None and outcome['result'] == 0
            chain.append({'new_price': new_price, 'new_qty': new_qty, 'delta': delta,
                          'applied': applied, 'resolved': outcome is not None})
            if applied:
                price, qty = new_price, new_qty
        return chain, price, qty
