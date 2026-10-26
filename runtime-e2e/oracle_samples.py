# SPDX-License-Identifier: Apache-2.0
"""Synthetic core samples for the oracle unit tests and the cross-language mirror (H1).

``clean_sample()`` is one self-consistent lifecycle: funding while the gate is still at GENESIS,
a price-improved taker fill, a resting partial, an amend with hold top-up, a cancel, an iceberg
refill, a triggered stop whose market child spends exactly its budget and a replayed create.
Every derived collection (balances, holds, legs, money journal, barrier digests) is computed
from the event stream, so a negative control edits the stream and calls ``seal()`` again.
``python3 oracle_samples.py <dir>`` writes the clean samples as JSON for the Java mirror.
"""
import copy
import json
from pathlib import Path
import sys

from contracts import FP, fingerprint
from oracle_model import BARRIER_COLLECTIONS

Q = FP // 100          # 0.01 base
BUYER, SELLER = 71001, 71002


def P(units):
    return units * FP


def q(price, qty):
    return price * qty // FP


def _create(req, user, side, type_, price, qty, order, hold_asset, hold_amount, display=0, budget=0, stop=0,
            duplicate=False):
    return {'request': [1, req], 'user': user, 'market': 1, 'side': side, 'type': type_, 'tif': 'GTC',
            'price': price, 'quantity': qty, 'budget': budget, 'stop_price': stop, 'display_qty': display,
            'reply': {'outcome': 'ACK', 'order': order, 'duplicate': duplicate, 'hold_asset': hold_asset,
                      'hold_amount': hold_amount}}


def _tap(seq, order, attempt, kind, user, price, qty, old_leg=0, budget=0):
    code = {'CREATE': 0, 'CANCEL': 1, 'AMEND': 2}[kind]
    return {'seq': seq, 'id_high': order, 'id_low': attempt << 2 | code, 'kind': kind, 'order': order, 'user': user,
            'old_leg': old_leg, 'market': 1, 'price': price, 'quantity': qty, 'budget': budget, 'at_ms': 1_000 + seq}


def _outcome(tap, leg, result=0, position=None):
    return {'type': 'outcome', 'command_id_high': tap['id_high'], 'command_id_low': tap['id_low'], 'user': tap['user'],
            'order': tap['order'], 'old_leg': tap['old_leg'], 'market': 1, 'kind': tap['id_low'] & 3,
            'applied_position': position if position is not None else 10_000 + tap['seq'] * 64, 'leg': leg,
            'status': 0, 'reason': 0, 'result': result, 'price': tap['price'], 'quantity': tap['quantity']}


def _trade(trade_id, price, qty, taker, maker, taker_is_buy):
    return {'type': 'trade', 'trade_id': trade_id, 'market': 1, 'price': price, 'quantity': qty,
            'taker_leg': taker[2], 'taker_user': taker[0], 'taker_order': taker[1],
            'maker_leg': maker[2], 'maker_user': maker[0], 'maker_order': maker[1], 'taker_is_buy': taker_is_buy}


def _terminal(leg, user, order, status):
    return {'type': 'terminal', 'leg': leg, 'user': user, 'market': 1, 'status': status, 'order': order}


def clean_sample():
    creates = [
        _create(1, SELLER, 'SELL', 'LIMIT', P(100), 2 * Q, 1001, 1, 2 * Q),
        _create(2, BUYER, 'BUY', 'LIMIT', P(101), Q, 1002, 0, q(P(101), Q)),
        _create(3, BUYER, 'BUY', 'LIMIT', P(90), 2 * Q, 1003, 0, q(P(90), 2 * Q)),
        _create(5, SELLER, 'SELL', 'LIMIT', P(200), Q, 1004, 1, Q),
        _create(7, SELLER, 'SELL', 'ICEBERG', P(99), 2 * Q, 1005, 1, 2 * Q, display=Q),
        _create(8, BUYER, 'BUY', 'LIMIT', P(99), Q, 1006, 0, q(P(99), Q)),
        _create(9, BUYER, 'BUY', 'STOP_LOSS', 0, Q, 1007, 0, P(1), stop=P(98), budget=P(1)),
        _create(2, BUYER, 'BUY', 'LIMIT', P(101), Q, 1002, 0, q(P(101), Q), duplicate=True),
    ]
    amends = [{'request': [1, 4], 'user': BUYER, 'order': 1003, 'new_price': P(95), 'new_quantity': 3 * Q,
               'reply': {'outcome': 'ACK', 'order': 1003, 'duplicate': False}}]
    cancels = [{'request': [1, 6], 'user': SELLER, 'order': 1004, 'reply': {'outcome': 'ACK', 'order': 1004}}]
    tap = [
        _tap(1, 1001, 0, 'CREATE', SELLER, P(100), 2 * Q),
        _tap(2, 1002, 0, 'CREATE', BUYER, P(101), Q),
        _tap(3, 1003, 0, 'CREATE', BUYER, P(90), 2 * Q),
        _tap(4, 1003, 1, 'AMEND', BUYER, P(95), 3 * Q, old_leg=5003),
        _tap(5, 1004, 0, 'CREATE', SELLER, P(200), Q),
        _tap(6, 1004, 1, 'CANCEL', SELLER, 0, 0, old_leg=5005),
        _tap(7, 1005, 0, 'CREATE', SELLER, P(99), Q),
        _tap(8, 1006, 0, 'CREATE', BUYER, P(99), Q),
        _tap(9, 1005, 1, 'CREATE', SELLER, P(99), Q),
        _tap(10, 1007, 0, 'CREATE', BUYER, 0, Q, budget=P(1)),
    ]
    t = {row['seq']: row for row in tap}
    journal = [
        _outcome(t[1], 5001), _outcome(t[2], 5002),
        _trade(1, P(100), Q, (BUYER, 1002, 5002), (SELLER, 1001, 5001), True),
        _terminal(5002, BUYER, 1002, 'FILLED'),
        _outcome(t[3], 5003), _outcome(t[4], 5004),
        _outcome(t[5], 5005), _outcome(t[6], 5005), _terminal(5005, SELLER, 1004, 'CANCELLED'),
        _outcome(t[7], 5006), _outcome(t[8], 5007),
        _trade(2, P(99), Q, (BUYER, 1006, 5007), (SELLER, 1005, 5006), True),
        _terminal(5007, BUYER, 1006, 'FILLED'), _terminal(5006, SELLER, 1005, 'FILLED'),
        _outcome(t[9], 5008),
        _outcome(t[10], 5009),
        _trade(3, P(100), Q, (BUYER, 1007, 5009), (SELLER, 1001, 5001), True),
        _terminal(5009, BUYER, 1007, 'FILLED'), _terminal(5001, SELLER, 1001, 'FILLED'),
    ]
    for event in journal:
        event.setdefault('journal_seq', None); event.setdefault('me_epoch', None)
    funding = [
        {'request': [2, 1], 'kind': 'deposit', 'user': BUYER, 'asset': 0, 'amount': P(10), 'outcome': 'ACK', 'gate': 'SUSPENDED'},
        {'request': [2, 2], 'kind': 'deposit', 'user': SELLER, 'asset': 1, 'amount': P(1), 'outcome': 'ACK', 'gate': 'OPEN'},
        {'request': [2, 3], 'kind': 'withdraw', 'user': BUYER, 'asset': 0, 'amount': P(1) // 2, 'outcome': 'ACK', 'gate': 'OPEN'},
    ]
    live = [
        {'order': 1003, 'user': BUYER, 'market': 1, 'status': 'NEW', 'side': 'BUY', 'type': 'LIMIT', 'price': P(95),
         'quantity': 3 * Q, 'filled': 0, 'remaining': 3 * Q, 'hold_asset': 0, 'hold_amount': q(P(95), 3 * Q),
         'me_order_id': 5004, 'hidden_qty': 0},
        {'order': 1005, 'user': SELLER, 'market': 1, 'status': 'PARTIALLY_FILLED', 'side': 'SELL', 'type': 'ICEBERG',
         'price': P(99), 'quantity': 2 * Q, 'filled': Q, 'remaining': Q, 'hold_asset': 1, 'hold_amount': 2 * Q,
         'me_order_id': 5008, 'hidden_qty': 0},
    ]
    events = [
        {'seq': 1, 'order': 1001, 'kind': 'ACK_NEW', 'status': 'NEW', 'filled': 0, 'quantity': 2 * Q},
        {'seq': 2, 'order': 1002, 'kind': 'FILL', 'status': 'FILLED', 'filled': Q, 'quantity': Q},
        {'seq': 3, 'order': 1003, 'kind': 'REPLACED', 'status': 'NEW', 'filled': 0, 'quantity': 3 * Q},
        {'seq': 4, 'order': 1004, 'kind': 'CANCELLED', 'status': 'CANCELLED', 'filled': 0, 'quantity': Q},
        {'seq': 5, 'order': 1006, 'kind': 'FILL', 'status': 'FILLED', 'filled': Q, 'quantity': Q},
        {'seq': 6, 'order': 1005, 'kind': 'SLICE_SUBMITTED', 'status': 'PARTIALLY_FILLED', 'filled': Q, 'quantity': 2 * Q},
        {'seq': 7, 'order': 1007, 'kind': 'TRIGGERED', 'status': 'NEW', 'filled': 0, 'quantity': Q, 'hold_remaining': P(1)},
        {'seq': 8, 'order': 1007, 'kind': 'FILL', 'status': 'FILLED', 'filled': Q, 'quantity': Q},
        {'seq': 9, 'order': 1001, 'kind': 'FILL', 'status': 'FILLED', 'filled': 2 * Q, 'quantity': 2 * Q},
    ]
    sample = {
        'version': 'core-sample-v2',
        'markets': {'1': {'base': 1, 'quote': 0}}, 'risk': {'1': {'slippage_bps': 500}},
        'genesis': {'verified': True, 'balances': [], 'holds': [], 'live_orders': [], 'last_applied_trade_id': 0},
        'funding': funding, 'creates': creates, 'amends': amends, 'cancels': cancels,
        'core': {'live_orders': live, 'pending_dispatch': {'count': 0, 'head': 10}},
        'core_events': events,
        'admission': [{'market': 0, 'state': 'SUSPENDED', 'reason': 'GENESIS', 'log_position': 0},
                      {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN', 'log_position': 4096}],
        'dispatch_tap': tap, 'me_journal': journal, 'me_journal_seq': False,
        'me_open_legs': [{'leg': 5004, 'order': 1003, 'user': BUYER, 'market': 1},
                         {'leg': 5008, 'order': 1005, 'user': SELLER, 'market': 1}],
        'faults': {'settle_fault': 0, 'settle_rejected': 0, 'order_fault': 0, 'quarantined': 0},
        'counters': {'stale_outcomes': 0, 'redundant_outcomes': 0, 'stale_terminals': 0, 'conflicts': 0},
        'declared': {'settle_fault': 0, 'settle_rejected': 0, 'order_fault': 0, 'quarantined': 0, 'halt': False,
                     'fault_open': False, 'forwarder_absent': False,
                     'gate_sequence': [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']], 'epochs': [None]},
    }
    derive_money(sample)
    return seal(sample)


def derive_money(sample, settle_epochs=True):
    """Balances, holds, money journal and legs implied by funding + ME trades + live residuals."""
    totals, journal, legs = {}, [], []

    def add(key, amount):
        totals[key] = totals.get(key, 0) + amount
        return totals[key]

    funding = [f for f in sample['funding'] if f['outcome'] == 'ACK']
    trades = [e for e in sample['me_journal'] if e['type'] == 'trade']
    # Journal order: the deposits, the trades, then the withdrawals (the order the clean sample submits them).
    steps = [('f', f) for f in funding if f['kind'] == 'deposit'] + [('t', t) for t in trades] + \
            [('f', f) for f in funding if f['kind'] == 'withdraw']
    for kind, row in steps:
        seq = len(journal) + 1
        if kind == 'f':
            sign = 1 if row['kind'] == 'deposit' else -1
            after = add((row['user'], row['asset']), sign * row['amount'])
            journal.append({'seq': seq, 'kind': row['kind'], 'user': row['user'], 'asset': row['asset'], 'amount': row['amount']})
            legs.append({'seq': seq, 'user': row['user'], 'asset': row['asset'], 'role': None, 'balance_after': after})
        else:
            buyer = row['taker_user'] if row['taker_is_buy'] else row['maker_user']
            seller = row['maker_user'] if row['taker_is_buy'] else row['taker_user']
            amount = q(row['price'], row['quantity'])
            entry = {'seq': seq, 'kind': 'settle', 'trade': row['trade_id'], 'buyer': buyer, 'seller': seller,
                     'market': 1, 'price': row['price'], 'quantity': row['quantity']}
            if settle_epochs and row.get('me_epoch') is not None:
                entry['me_epoch'] = row['me_epoch']
            journal.append(entry)
            for user, role, delta in [(buyer, 0, row['quantity']), (buyer, 1, -amount),
                                      (seller, 0, -row['quantity']), (seller, 1, amount)]:
                asset = 1 if role == 0 else 0
                legs.append({'seq': seq, 'user': user, 'asset': None, 'role': role, 'balance_after': add((user, asset), delta)})
    holds = []
    for row in sample['core']['live_orders']:
        oid = row['order']
        if row['side'] == 'SELL':
            remaining = row['quantity'] - row['filled']
        else:
            remaining = row['hold_amount'] - sum(q(t['price'], t['quantity']) for t in trades
                                                 if oid in (t['taker_order'], t['maker_order']))
        holds.append({'order': oid, 'user': row['user'], 'asset': row['hold_asset'], 'remaining': remaining})
    locked = {}
    for h in holds:
        locked[(h['user'], h['asset'])] = locked.get((h['user'], h['asset']), 0) + h['remaining']
    sample['core']['holds'] = holds
    sample['core']['balances'] = [{'user': u, 'asset': a, 'available': total - locked.get((u, a), 0),
                                   'locked': locked.get((u, a), 0)} for (u, a), total in sorted(totals.items())]
    sample['core']['last_applied_trade_id'] = max((t['trade_id'] for t in trades), default=0)
    sample['money_journal'] = journal
    sample['money_journal_legs'] = legs
    return sample


def seal(sample):
    observation = {name + '_digest': fingerprint(sample[name]) for name in BARRIER_COLLECTIONS}
    sample['barrier'] = {'input_closed': True, 'samples': [dict(observation), dict(observation)]}
    return sample


def schema4_sample(epoch=77):
    """The clean sample as the schema 4 journal would carry it: journalSeq dense, one meEpoch."""
    sample = clean_sample()
    for index, event in enumerate(sample['me_journal'], start=1):
        event['journal_seq'] = index; event['me_epoch'] = epoch
    sample['me_journal_seq'] = True
    sample['declared']['epochs'] = [epoch]
    derive_money(sample)
    return seal(sample)


def variant(sample, edit):
    clone = copy.deepcopy(sample)
    edit(clone)
    return seal(clone)


if __name__ == '__main__':
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=False)
    (out / 'clean-legacy-journal.json').write_text(json.dumps(clean_sample(), indent=1) + '\n')
    (out / 'clean-schema4-journal.json').write_text(json.dumps(schema4_sample(), indent=1) + '\n')
