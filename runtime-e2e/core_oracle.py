# SPDX-License-Identifier: Apache-2.0
"""Money oracle v2 for the core topology (rc2-rcs-harness.md 2.5, rules M1-M14).

Replaces ``contracts.reconcile`` for the core topology. Exact integer units, fail closed: an
unexplained row is FAIL, missing evidence is INCONCLUSIVE. Each rule reports separately so a
drill witness names the broken invariant; the overall decision is FAIL > INCONCLUSIVE > PASS.
"""
from collections import Counter, defaultdict

from contracts import FP, Inconclusive, Violation, integer
from oracle_model import TERMINAL, Model, check_barrier, quote


def _funding_key(row):
    return row['kind'], integer(row['user']), integer(row['asset']), integer(row['amount'])


def _external(m):
    """Per (user, asset): ACKed deposits minus ACKed withdrawals."""
    totals = defaultdict(int)
    for row in m.s['funding']:
        if row['kind'] not in {'deposit', 'withdraw'} or integer(row['amount']) <= 0:
            raise Violation('invalid external money movement')
        if row['outcome'] == 'UNKNOWN':
            raise Inconclusive('funding outcome unknown; no exact external total')
        if row['outcome'] == 'ACK':
            totals[(row['user'], row['asset'])] += row['amount'] if row['kind'] == 'deposit' else -row['amount']
    return totals


def _trade_deltas(m):
    deltas = defaultdict(int)
    for trade in m.trades:
        market = m.market(trade['market'])
        (buyer, _), (seller, _) = m.buyer_seller(trade)
        amount = quote(trade['price'], trade['quantity'])
        deltas[(buyer, market['base'])] += trade['quantity']
        deltas[(buyer, market['quote'])] -= amount
        deltas[(seller, market['base'])] -= trade['quantity']
        deltas[(seller, market['quote'])] += amount
    return deltas


def _balances(m):
    out = {}
    for row in m.s['core']['balances']:
        key = integer(row['user']), integer(row['asset'])
        if key in out:
            raise Violation('core balance snapshot repeats ' + str(key))
        out[key] = integer(row['available']), integer(row['locked'])
    return out


def _holds(m):
    out = {}
    for row in m.s['core']['holds']:
        oid = integer(row['order'])
        if oid in out:
            raise Violation('core hold snapshot repeats order ' + str(oid))
        out[oid] = integer(row['user']), integer(row['asset']), integer(row['remaining'])
    return out


def m1(m):
    external = defaultdict(int)
    for (_, asset), amount in _external(m).items():
        external[asset] += amount
    observed = defaultdict(int)
    for (_, asset), (available, locked) in _balances(m).items():
        observed[asset] += available + locked
    for asset in set(external) | set(observed):
        if observed[asset] != external[asset]:
            raise Violation(f'asset {asset}: sum(available + locked) {observed[asset]} != deposits - withdrawals {external[asset]}')


def m2(m):
    m.check_ownership()   # trade deltas below are keyed on users the create log confirms
    expected = defaultdict(int)
    for key, amount in _external(m).items():
        expected[key] += amount
    for key, amount in _trade_deltas(m).items():
        expected[key] += amount
    actual = _balances(m)
    for key in set(expected) | set(actual):
        available, locked = actual.get(key, (0, 0))
        if available < 0 or locked < 0:
            raise Violation(f'{key}: negative available/locked ({available}, {locked})')
        if available + locked != expected[key]:
            raise Violation(f'{key}: total {available + locked} != genesis + funding + trades {expected[key]}')


def m3(m):
    locked = defaultdict(int)
    for user, asset, remaining in _holds(m).values():
        if remaining < 0:
            raise Violation('negative hold remaining')
        locked[(user, asset)] += remaining
    for key, (_, held) in _balances(m).items():
        if held != locked[key]:
            raise Violation(f'{key}: locked {held} != sum of live hold residuals {locked[key]}')
    for key, amount in locked.items():
        if amount and key not in _balances(m):
            raise Violation(f'{key}: holds {amount} but no balance row')


def m4(m):
    for oid, (user, asset, remaining) in _holds(m).items():
        order = m.live.get(oid)
        if order is None:
            raise Violation(f'hold for order {oid} which is not live (terminal orders hold nothing)')
        create = m.orders.get(oid)
        if create is None:
            raise Violation(f'hold for order {oid} that no accepted request created')
        side_asset = m.hold_asset(create)
        if order['user'] != user or order['hold_asset'] != asset or asset != side_asset or user != create['user']:
            raise Violation(f'hold for order {oid} sits on ({user}, {asset}); order says ({order["user"]}, '
                            f'{order["hold_asset"]}), create log says ({create["user"]}, {side_asset})')
    for oid in m.live:
        if oid not in _holds(m):
            raise Violation(f'live order {oid} has no hold')


def expected_create_hold(m, oid):
    """The create hold recomputed from the intent (OrderEngine.create, S6 contract section 1).

    SELL locks the base quantity. BUY locks the quote notional: a priced type (LIMIT, LIMIT_MAKER,
    ICEBERG, STOP_LIMIT) price x quantity; a price-less type (MARKET, STOP_LOSS, TRAILING_STOP) its
    explicit budget, else the engine's estimate. Only the STOP_LOSS estimate is independent of the
    book (stop x (1 + slippage bps) x quantity, FixedPoint.multiply twice); MARKET and TRAILING_STOP
    estimate from bestAsk, which no sample witnesses, so they are INCONCLUSIVE without a budget.
    """
    create = m.orders[oid]
    if create['side'] == 'SELL':
        return integer(create['quantity'])
    kind = create['type']
    if kind in {'LIMIT', 'LIMIT_MAKER', 'ICEBERG', 'STOP_LIMIT'}:
        return quote(create['price'], create['quantity'])
    if kind in {'MARKET', 'STOP_LOSS', 'TRAILING_STOP'}:
        budget = integer(create.get('budget') or 0)
        if budget > 0:
            return budget
        if kind == 'STOP_LOSS':
            risk = m.s['risk'].get(str(create['market']))
            if risk is None or type(risk.get('slippage_bps')) is not int:
                raise Inconclusive(f'order {oid}: stop-BUY estimate needs the market slippage the drill configured')
            slip = FP + risk['slippage_bps'] * 10_000
            return quote(quote(create['stop_price'], slip), create['quantity'])
        raise Inconclusive(f'order {oid}: budget-less {kind} BUY is estimated from bestAsk; declare a budget')
    raise Inconclusive(f'order {oid}: unknown order type {kind}')


def _create_hold(m, oid):
    create = m.orders[oid]
    reply = create['reply']
    if reply['hold_asset'] != m.hold_asset(create):
        raise Violation(f'order {oid}: hold asset {reply["hold_asset"]} is not the side\'s asset')
    expected = expected_create_hold(m, oid)
    if integer(reply['hold_amount']) != expected:
        raise Violation(f'order {oid}: {create["side"]} {create["type"]} create hold {reply["hold_amount"]} '
                        f'!= recomputed from the intent {expected}')
    return expected


def residual(m, oid):
    """Bookkept hold residual: create hold + resolved amend deltas - fill draws (record formula)."""
    create = m.orders.get(oid)
    if create is None:
        raise Violation(f'live order {oid} was never accepted by a create request')
    create_hold = _create_hold(m, oid)   # recomputed from the intent, never the engine's ACK
    chain, _, qty = m.amend_chain(oid)
    pending = [link for link in chain if not link['resolved']]
    top_up = 0
    if pending:
        # Contract 3.4 / LifecycleInvariants.expectedResidual: while REPLACE_PENDING the hold already
        # carries the positive top-up of the one open amend; any other unresolved shape is unjudgeable.
        if len(pending) != 1 or pending[0] is not chain[-1] or m.live[oid]['status'] != 'PENDING_REPLACE':
            raise Inconclusive(f'order {oid}: amend outcome not resolved at the barrier')
        link = pending[0]
        top_up = max(link['delta'], 0) if create['side'] == 'BUY' else max(link['new_qty'] - qty, 0)
    if create['side'] == 'SELL':
        return qty + top_up - m.fills[oid]
    adds = create_hold + sum(link['delta'] for link in chain if link['applied']) + top_up
    return adds - m.quote[oid]


def m5(m):
    holds = _holds(m)
    for oid in m.orders:
        _create_hold(m, oid)   # every accepted create, live or terminal: the ACK's hold equals the intent's
    for oid in m.live:
        expected = residual(m, oid)
        if oid in holds and holds[oid][1] != m.hold_asset(m.orders[oid]):
            raise Violation(f'order {oid}: hold on asset {holds[oid][1]}, its side holds {m.hold_asset(m.orders[oid])}')
        if oid not in holds or holds[oid][2] != expected:
            raise Violation(f'order {oid}: hold remaining {holds.get(oid, (0, 0, None))[2]} != recomputed residual {expected}')


def m6(m):
    """No trade crosses its order's limits, and no terminal BUY drew more than its hold without a declared
    OrderFault. (Surplus released at terminal is M2 + M3 + M4: a terminal order holds nothing.)"""
    for oid, prices in m.trade_prices.items():
        create = m.orders.get(oid)
        if create is None or create['type'] not in {'LIMIT', 'LIMIT_MAKER', 'ICEBERG'}:
            continue
        limits = [create['price']] + [link['new_price'] for link in m.amend_chain(oid)[0] if link['applied']]
        lowest_limit, highest_limit = min(limits), max(limits)
        for price, buy in prices:
            if buy and price > highest_limit or not buy and price < lowest_limit:
                raise Violation(f'order {oid}: trade at {price} crosses its limit (no improvement, hold overdrawn)')
    for oid, create in m.orders.items():
        if oid in m.live or create['side'] != 'BUY':
            continue
        chain, _, _ = m.amend_chain(oid)
        left = expected_create_hold(m, oid) + sum(l['delta'] for l in chain if l['applied']) - m.quote[oid]
        if left < 0 and not m.declared.get('order_fault'):
            raise Violation(f'terminal order {oid} drew {-left} more than it held without a declared OrderFault')


def m7(m):
    by_trade = {}
    for row in m.s['money_journal']:
        if row['kind'] == 'settle':
            by_trade.setdefault((row.get('me_epoch'), integer(row['trade'])), row)
    for trade in m.trades:
        if integer(trade['price']) <= 0 or integer(trade['quantity']) <= 0:
            raise Violation('ME trade with non-positive price/quantity')
        row = by_trade.get((trade['me_epoch'], trade['trade_id']))
        if row is None:
            continue  # M8 reports the missing settle
        (buyer, _), (seller, _) = m.buyer_seller(trade)
        expected = {'buyer': buyer, 'seller': seller, 'price': trade['price'], 'quantity': trade['quantity'],
                    'market': trade['market']}
        diff = {k: (row.get(k), v) for k, v in expected.items() if row.get(k) != v}
        if diff:
            raise Violation(f'trade {trade["trade_id"]}: money journal settle differs from the ME trade {diff}')


def m8(m):
    settles = Counter((row.get('me_epoch'), integer(row['trade'])) for row in m.s['money_journal'] if row['kind'] == 'settle')
    dup = [k for k, n in settles.items() if n > 1]
    if dup:
        raise Violation(f'duplicate settle rows for trades {dup[:5]}')
    me = Counter((t['me_epoch'], t['trade_id']) for t in m.trades)
    if [k for k, n in me.items() if n > 1]:
        raise Violation('ME journal repeats a trade id within an epoch')
    if set(settles) != set(me):
        raise Violation(f'settle set != ME trade set: missing {sorted(set(me) - set(settles))[:5]} '
                        f'extra {sorted(set(settles) - set(me))[:5]}')
    if not m.declared.get('halt'):
        by_epoch = defaultdict(list)
        for epoch, trade in me:
            by_epoch[epoch].append(trade)
        for epoch, ids in by_epoch.items():
            if sorted(ids) != list(range(1, len(ids) + 1)):
                raise Violation(f'epoch {epoch}: ME trade ids are not dense from 1')


def m9(m):
    """Funding exactly once, matched as a (kind, user, asset, amount) multiset: the projection carries no
    requestId, so two identical movements are indistinguishable (money is still exact in that case)."""
    if any(r['outcome'] == 'UNKNOWN' for r in m.s['funding']):
        raise Inconclusive('funding outcome unknown; exactly-once cannot be judged')
    expected = Counter(_funding_key(r) for r in m.s['funding'] if r['outcome'] == 'ACK')
    observed = Counter(_funding_key(r) for r in m.s['money_journal'] if r['kind'] in {'deposit', 'withdraw'})
    if expected != observed:
        raise Violation(f'funding journal rows != acknowledged funding (lost {expected - observed}, extra {observed - expected})')
    for row in m.s['funding']:
        if row['gate'] == 'SUSPENDED' and row['outcome'] != 'ACK':
            raise Violation('funding refused while the order gate was closed; money commands must continue')


def m10(m):
    if not m.trades:
        if m.s['core']['last_applied_trade_id'] != 0:
            raise Violation('core applied trades the ME never journaled')
        return
    epoch = m.trades[-1]['me_epoch']
    top = max(t['trade_id'] for t in m.trades if t['me_epoch'] == epoch)
    if m.s['core']['last_applied_trade_id'] != top:
        raise Violation(f'lastAppliedTradeId {m.s["core"]["last_applied_trade_id"]} != max ME trade id {top}')


def m11(m):
    for name in ['settle_fault', 'settle_rejected', 'order_fault']:
        observed, declared = m.s['faults'].get(name), m.declared.get(name, 0)
        if type(observed) is not int:
            raise Inconclusive('missing fault counter ' + name)
        if observed != declared:
            raise Violation(f'{name}: observed {observed} != declared {declared}')


def m12(m):
    declared = m.declared.get('epochs')
    epochs = [e['me_epoch'] for e in m.journal]
    if not m.s['me_journal_seq']:
        if declared and len(declared) > 1:
            raise Inconclusive('per-epoch partition needs the schema 4 journal (journalSeq + meEpoch)')
        return 'NOT_APPLICABLE'
    if declared is None:
        raise Inconclusive('drill did not declare its ME epochs')
    seen = list(dict.fromkeys(epochs))
    if seen != declared:
        raise Violation(f'ME epochs in journal order {seen} != declared {declared}')
    expected_seq = defaultdict(int)
    for event in m.journal:
        expected_seq[event['me_epoch']] += 1
        if event['journal_seq'] != expected_seq[event['me_epoch']]:
            raise Violation(f'epoch {event["me_epoch"]}: journalSeq {event["journal_seq"]} breaks density')
    settled = {(r.get('me_epoch'), r['trade']) for r in m.s['money_journal'] if r['kind'] == 'settle'}
    for trade in m.trades:
        if (trade['me_epoch'], trade['trade_id']) not in settled:
            raise Violation(f'epoch {trade["me_epoch"]} trade {trade["trade_id"]} swallowed (old id after re-genesis?)')


def m13(m):
    seq = 1
    for row in m.s['money_journal']:
        if integer(row['seq']) != seq:
            raise Violation('money journal gap, duplicate or out-of-order record')
        seq += 1


def m14(m):
    """Replay every money-journal movement in seq order: each leg's balance_after must equal the
    replayed total at that seq, and the replayed totals must equal the core's available + locked."""
    legs = defaultdict(dict)
    for leg in m.s['money_journal_legs']:
        key = (integer(leg['user']), leg['asset'], leg['role'])
        if key in legs[integer(leg['seq'])]:
            raise Violation(f'money journal seq {leg["seq"]} repeats leg {key}')
        legs[integer(leg['seq'])][key] = integer(leg['balance_after'])
    totals = defaultdict(int)
    for row in sorted(m.s['money_journal'], key=lambda r: integer(r['seq'])):
        seq = integer(row['seq'])
        if row['kind'] in {'deposit', 'withdraw'}:
            key = (row['user'], row['asset'])
            totals[key] += row['amount'] if row['kind'] == 'deposit' else -row['amount']
            expected = {(row['user'], row['asset'], None): totals[key]}
        elif row['kind'] == 'settle':
            market = m.market(row['market'])
            amount = quote(row['price'], row['quantity'])
            for user, base, quote_delta in [(row['buyer'], row['quantity'], -amount), (row['seller'], -row['quantity'], amount)]:
                totals[(user, market['base'])] += base
                totals[(user, market['quote'])] += quote_delta
            expected = {(user, None, role): totals[(user, market['base'] if role == 0 else market['quote'])]
                        for user in (row['buyer'], row['seller']) for role in (0, 1)}
        else:
            raise Inconclusive('unmodelled money journal movement ' + str(row['kind']))
        claimed = legs.pop(seq, {})
        if claimed != expected:
            raise Violation(f'seq {seq}: journal legs {claimed} != replayed balances {expected}')
    if legs:
        raise Violation(f'money journal legs for seqs {sorted(legs)[:5]} without a movement')
    actual = {k: a + l for k, (a, l) in _balances(m).items()}
    for key in set(totals) | set(actual):
        if totals.get(key, 0) != actual.get(key, 0):
            raise Violation(f'{key}: core total {actual.get(key, 0)} != money-journal replay {totals.get(key, 0)}')


RULES = [('M1', m1), ('M2', m2), ('M3', m3), ('M4', m4), ('M5', m5), ('M6', m6), ('M7', m7),
         ('M8', m8), ('M9', m9), ('M10', m10), ('M11', m11), ('M12', m12), ('M13', m13), ('M14', m14)]


def run_rules(sample, rules):
    try:
        check_barrier(sample)
        model = Model(sample)
    except Violation as error:
        return {'status': 'FAIL', 'rules': {}, 'error': str(error)}
    except (Inconclusive, KeyError, TypeError) as error:
        return {'status': 'INCONCLUSIVE', 'rules': {}, 'error': str(error)}
    results = {}
    for name, rule in rules:
        try:
            outcome = rule(model)
            results[name] = {'status': outcome or 'PASS'}
        except Violation as error:
            results[name] = {'status': 'FAIL', 'detail': str(error)}
        except (Inconclusive, KeyError, TypeError, ValueError) as error:
            results[name] = {'status': 'INCONCLUSIVE', 'detail': f'{type(error).__name__}: {error}'}
    statuses = {r['status'] for r in results.values()}
    status = 'FAIL' if 'FAIL' in statuses else 'INCONCLUSIVE' if 'INCONCLUSIVE' in statuses else 'PASS'
    return {'status': status, 'rules': results}


def judge(sample):
    return run_rules(sample, RULES)
