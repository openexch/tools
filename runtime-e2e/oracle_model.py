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
  counters         optional {"stale_outcomes","redundant_outcomes","stale_terminals","conflicts"} (the AE counter export)
  declared         {"settle_fault","settle_rejected","order_fault","quarantined","halt","fault_open",
                    "forwarder_absent","gate_sequence": [[state, reason], ...] | null, "epochs": [e, ...],
                    "ordering_exception": null | {"me_term", "until_seq", "from_journal_seq" (optional)},
                    "untappable": optional {"reason", "dispatch": [[a, b], ...], "events": [[a, b], ...]}: windows the
                    tap could not observe (its session closed across a declared quorum loss or a recorded leader
                    election and reconnected after); a dispatch gap inside one may stay short of backfill and an
                    order whose terminal falls in one is recorded, not judged (Model.tap_closed, order_oracle.o5)}
  tap_continuity   optional {"transitions": [CoreProbe tap session notes], "summary": {...}}; the dispatch
                   density is computed from the rows themselves against core.pending_dispatch.head
  story rows       request rows may carry "id", "resolves" and "resolved_by": an UNKNOWN original resolved by
                   a same-requestId re-send counts as the re-send's verdict (Model.creates/amends/cancels)
  dispatch_tap rows of kind RELEASE_ID carry a create's command id again; rows with
                   "source": "backfill" were rebuilt at the barrier from pending-dump (seq known) or from the ME journal
                   outcome (seq null)
  barrier          {"input_closed": true, "samples": [obs, obs]} with obs.<collection>_digest = fingerprint
"""
from collections import defaultdict

from contracts import FP, Inconclusive, Violation, fingerprint, integer

TERMINAL = {'FILLED', 'CANCELLED', 'REJECTED', 'EXPIRED'}
RELEASE_KIND = 'RELEASE_ID'           # money-schema DispatchKind 3: forwarder-only, carries a create's command id again
RESULT_RELEASED = 7                   # me-journal-schema CommandOutcome.result 7 RELEASED
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


def resolve_requests(rows):
    """Returns (effective rows in submission order, unresolved UNKNOWN originals).

    An UNKNOWN original whose same-requestId re-send got a duplicate ACK was committed at its own position: it stands as
    that ACK (``source: replay``, the replay reports the order's CURRENT hold, so M5 does not compare it with the
    intent). A fresh ACK or a REJECT of the re-send means the original never committed: the original is dropped and the
    re-send stands at its own position. The duplicate re-send itself is the replay of the original and is dropped.
    Rows without story ids (smoke, synthetic samples) pass unchanged.
    """
    by_id = {}
    for row in rows:
        if 'id' in row:
            if row['id'] in by_id:
                raise Inconclusive(f'story row id {row["id"]} repeats')
            by_id[row['id']] = row
    effective, unresolved = [], []
    for row in rows:
        reply = row['reply']
        if 'resolves' in row:
            original = by_id.get(row['resolves'])
            if original is None or original.get('resolved_by') != row.get('id') or original['request'] != row['request']:
                raise Inconclusive(f'resolution row {row.get("id")} does not name an UNKNOWN original with its requestId')
            if reply.get('outcome') == 'ACK' and reply.get('duplicate'):
                continue
            if reply.get('outcome') not in {'ACK', 'REJECT'}:
                raise Inconclusive(f'resolution row {row.get("id")} carries no verdict')
            effective.append(row)
            continue
        if reply.get('outcome') == 'UNKNOWN':
            resolver = by_id.get(row.get('resolved_by')) if row.get('resolved_by') is not None else None
            if row.get('resolved_by') is not None and (resolver is None or resolver.get('resolves') != row.get('id')):
                raise Inconclusive(f'UNKNOWN row {row.get("id")} names resolver {row.get("resolved_by")} that does not resolve it')
            if resolver is None:
                unresolved.append(row)
            elif resolver['reply'].get('outcome') == 'ACK' and resolver['reply'].get('duplicate'):
                effective.append(dict(row, reply=dict(resolver['reply'], duplicate=False, source='replay'),
                                      resolution={'by': resolver['id'], 'committed': True}))
            continue
        effective.append(row)
    return effective, unresolved


def attempt(row):
    return integer(row['id_low']) >> 2


def seq_gaps(seqs, low, high):
    """Inclusive [a, b] ranges of the integers in [low, high] that ``seqs`` does not contain."""
    gaps, expected = [], low
    for seq in sorted(set(seqs)):
        if seq < low or seq > high:
            continue
        if seq > expected:
            gaps.append([expected, seq - 1])
        expected = seq + 1
    if expected <= high:
        gaps.append([expected, high])
    return gaps


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
        # UNKNOWN replies resolved by their same-requestId re-send; the rules read these, never the raw lists.
        self.creates, unresolved_creates = resolve_requests(sample['creates'])
        self.amends, unresolved_amends = resolve_requests(sample['amends'])
        self.cancels, unresolved_cancels = resolve_requests(sample['cancels'])
        self.unresolved = unresolved_creates + unresolved_amends + unresolved_cancels
        # Accepted creates: first non-duplicate ACK per requestId defines the order.
        self.orders = {}
        self.create_by_request = {}
        for create in self.creates:
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
        # The command dispatches, keyed by command id. RELEASE_ID rows repeat a create's id by design:
        # they are kept apart, keyed by (id, kind), and never count as a second dispatch of the command.
        self.tap, self.release_dispatches = {}, {}
        for row in sample['dispatch_tap']:
            key = (integer(row['id_high']), integer(row['id_low']))
            if row['kind'] == RELEASE_KIND:
                if key in self.release_dispatches:
                    raise Violation('dispatch tap saw a RELEASE_ID twice for command id ' + str(key))
                self.release_dispatches[key] = row
                continue
            if key in self.tap:
                raise Violation('dispatch tap saw command id twice as a new dispatch: ' + str(key))
            self.tap[key] = row
        self.first_outcome = {}
        self.outcome_copies = defaultdict(list)
        self.released_repeats = []
        released_before = set()
        for event in self.journal:
            if event['type'] == 'release':
                released_before.update(integer(entry['commandIdHigh']) for entry in event.get('releases') or [])
                continue
            if event['type'] != 'outcome':
                continue
            key = (integer(event['command_id_high']), integer(event['command_id_low']))
            if key in self.first_outcome and event['result'] == RESULT_RELEASED:
                # A frame offered after its order was released journals RELEASED and creates nothing
                if event['leg']:
                    raise Violation(f'command {key}: RELEASED repeat carries leg {event["leg"]}')
                if key[0] not in released_before:
                    raise Violation(f'command {key}: RELEASED outcome without an earlier release of order {key[0]}')
                self.released_repeats.append(event)
            self.outcome_copies[key].append(event)
            self.first_outcome.setdefault(key, event)
        self.continuity = self._continuity(sample)

    def _continuity(self, sample):
        """Dispatch gaps (the tap's own rows against [1, core head]) and order-event loss windows."""
        tapped = [integer(r['seq']) for r in sample['dispatch_tap'] if r.get('source') != 'backfill']
        head = sample['core'].get('pending_dispatch', {}).get('head')
        high = max([head if type(head) is int else 0] + tapped) if tapped or type(head) is int else 0
        gaps = seq_gaps(tapped, 1, high)
        backfill = [r for r in sample['dispatch_tap'] if r.get('source') == 'backfill']
        events = [integer(e['seq']) for e in sample['core_events']]
        windows = seq_gaps(events, min(events), max(events)) if events else []
        for note in (sample.get('tap_continuity') or {}).get('transitions', []):
            if note.get('event') in {'registered'}:
                continue
            last = note.get('last_event_seq', 0)
            after = [s for s in events if s > last]
            windows.append([last + 1, min(after) - 1] if after else [last + 1, None])
        windows = [w for w in windows if w[1] is None or w[1] >= w[0]]
        return {'gaps': gaps, 'backfill': backfill, 'event_windows': windows, 'head': head}

    def untappable(self, kind):
        """The declared untappable windows of ``kind`` ('dispatch' or 'events'), [] when none is declared."""
        return [list(w) for w in ((self.s.get('declared') or {}).get('untappable') or {}).get(kind) or []]

    def tap_closed(self):
        """None when every dispatch gap is accounted for by backfill rows (count over the gap), else the first open gap.

        A backfill row with a known seq must sit inside a gap; rows without a seq (resolved at the ME, rebuilt from its
        journal) are pooled across the gaps, so the check is: for every gap, known rows <= its size, and the pooled
        rows cover the remainder exactly. A gap inside a declared untappable window may stay short: the shortfall is
        recorded in ``self.untapped`` and the gap counts as closed; pooled rows still may not exceed the deficit."""
        self.untapped = []
        gaps, backfill = self.continuity['gaps'], self.continuity['backfill']
        declared = self.untappable('dispatch')
        known = [integer(r['seq']) for r in backfill if r.get('seq') is not None]
        pooled = sum(1 for r in backfill if r.get('seq') is None)
        deficit, first_open = 0, None
        for a, b in gaps:
            inside = sum(1 for seq in known if a <= seq <= b)
            missing = (b - a + 1) - inside
            if missing and first_open is None:
                first_open = [a, b]
            deficit += missing
        stray = [seq for seq in known if not any(a <= seq <= b for a, b in gaps)]
        if stray:
            raise Inconclusive(f'backfill rows at seqs {stray[:5]} that the tap did not miss')
        if pooled > deficit:
            raise Inconclusive(f'{pooled} backfill rows without a seq but only {deficit} missing dispatch seqs')
        if deficit == pooled:
            return None
        open_gaps = [[a, b] for a, b in gaps if (b - a + 1) - sum(1 for seq in known if a <= seq <= b)]
        if declared and all(any(lo <= a and b <= hi for lo, hi in declared) for a, b in open_gaps):
            self.untapped = [{'gaps': open_gaps, 'short': deficit - pooled,
                              'reason': (self.s.get('declared') or {}).get('untappable', {}).get('reason')}]
            return None
        return first_open

    def require_tap_closed(self):
        gap = self.tap_closed()
        if gap is not None:
            raise Inconclusive(f'tap gap [{gap[0]}, {gap[1]}] not closed')

    def in_event_window(self, last_seen):
        """True when an order whose last tapped event seq is ``last_seen`` could have lost a later event in a window."""
        return any(b is None or b > last_seen for a, b in self.continuity['event_windows'])

    def only_untappable_after(self, last_seen):
        """True when every event window after ``last_seen`` lies inside a declared untappable window."""
        after = [w for w in self.continuity['event_windows'] if w[1] is None or w[1] > last_seen]
        declared = self.untappable('events')
        return bool(after) and bool(declared) and all(
            w[1] is not None and any(lo <= w[0] and w[1] <= hi for lo, hi in declared) for w in after)

    def unaccounted(self, text):
        """An order no accepted request created is a FAIL, unless a gateway reply is still unresolved
        (that request may be the one that committed it): then the run is INCONCLUSIVE, never a false FAIL."""
        if self.unresolved:
            return Inconclusive(f'unresolved gateway reply ({len(self.unresolved)}): {text}')
        return Violation(text)

    def check_ownership(self):
        """Every ME trade leg, dispatch and resting leg belongs to the user who created the order."""
        for trade in self.trades:
            for order, user in [(trade['taker_order'], trade['taker_user']), (trade['maker_order'], trade['maker_user'])]:
                create = self.orders.get(order)
                if create is None:
                    raise self.unaccounted(f'ME trade {trade["trade_id"]} on order {order} that no accepted request created')
                if create['user'] != user:
                    raise Violation(f'ME trade {trade["trade_id"]}: order {order} belongs to {create["user"]}, trade says {user}')
        for row in self.tap.values():   # a RELEASE_ID row carries only the command id (order 0, user 0)
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
        # attempt order == mint order, and it is known for a backfilled row whose seq is not
        dispatches = sorted((row for row in self.tap.values() if row['order'] == oid and row['kind'] == 'AMEND'), key=attempt)
        acked = [a for a in self.amends if a['order'] == oid and a['reply'].get('outcome') == 'ACK'
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
