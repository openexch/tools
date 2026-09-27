# SPDX-License-Identifier: Apache-2.0
"""Read exact fixture evidence. No tolerance, schema guessing or missing-data defaults."""
import json
import time

from contracts import Inconclusive, Violation, fingerprint, reconcile
from fixture import JAVA


def ae_dump(fixture):
    result = fixture.execute('probe', JAVA + ['-jar', '/artifacts/bridge.jar', 'dump'],
                             environment=fixture.bridge_env('probe'), timeout=45)
    return json.loads(result.stdout)


def sql_rows(fixture, database, query):
    return json.loads(fixture.psql(database, 'SELECT COALESCE(json_agg(t), \'[]\'::json) FROM (' + query + ') t'))


def collect(fixture):
    # Each collection has a deterministic ordering. A later second full observation must agree.
    orders = sql_rows(fixture, 'r01_oms', '''SELECT oms_order_id AS id, user_id AS "user",
        market_id AS market, side, status, price, quantity, filled_qty AS filled
        FROM orders ORDER BY oms_order_id''')
    executions = sql_rows(fixture, 'r01_oms', '''SELECT trade_id AS trade, oms_order_id AS "order",
        user_id AS "user", market_id AS market, side, price, quantity
        FROM executions ORDER BY trade_id, oms_order_id, execution_id''')
    raw_journal = sql_rows(fixture, 'r01_money', 'SELECT * FROM money_journal ORDER BY journal_seq')
    raw_legs = sql_rows(fixture, 'r01_money', 'SELECT * FROM money_journal_leg ORDER BY journal_seq, leg_no')
    journal = []
    for row in raw_journal:
        entry = {'seq': row['journal_seq']}
        if row['movement_type'] in (2, 3):
            entry.update(kind={2: 'deposit', 3: 'withdraw'}[row['movement_type']],
                         user=row['user_id'], asset=row['asset_id'], amount=row['amount'])
        elif row['movement_type'] == 4:
            entry.update(kind='settle', trade=row['trade_id'], buyer=row['buyer_user_id'],
                         seller=row['seller_user_id'], market=row['market_id'],
                         price=row['price'], quantity=row['quantity'])
        else:
            raise Inconclusive('unexpected journal epoch/movement in known-empty fixture')
        journal.append(entry)
    ae = ae_dump(fixture)
    balances = sorted([{'user': r['userId'], 'asset': r['assetId'], 'available': r['available'],
                        'locked': r['locked']} for r in ae['balances']], key=lambda r: (r['user'], r['asset']))
    holds = sorted([{'order': r['orderId'], 'user': r['userId'], 'asset': r['assetId'],
                    'remaining': r['remaining']} for r in ae['holds']], key=lambda r: r['order'])
    state = {'orders': orders, 'executions': executions, 'journal': journal,
             'balances': balances, 'holds': holds}
    observation = {name + '_digest': fingerprint(rows) for name, rows in state.items()}
    observation.update(ae_position=ae['consumePosition'], last_trade=ae['lastAppliedTradeId'],
                       journal_seq=journal[-1]['seq'] if journal else 0,
                       journal_legs_digest=fingerprint(raw_legs))
    return {'state': state, 'observation': observation, 'raw_ae': ae,
            'raw_journal': raw_journal, 'raw_legs': raw_legs, 'observed_ns': time.time_ns()}


def verify_genesis(fixture, users):
    first = collect(fixture); time.sleep(.5); second = collect(fixture)
    (fixture.root / 'genesis.json').write_text(json.dumps([first, second], indent=2) + '\n')
    if first['observation'] != second['observation']:
        raise Inconclusive('changing genesis')
    if any(second['state'].values()) or second['raw_legs'] or second['raw_ae']['consumePosition'] != 0 or second['raw_ae']['lastAppliedTradeId'] != 0:
        raise Violation('fixture is not an empty financial genesis')
    return [{'user': u, 'asset': a, 'total': 0} for u in users for a in (0, 1)]


def stable_sample(fixture, initial, funding, accepted, expected_trades, timeout=30):
    deadline = time.monotonic() + timeout
    previous = None
    observations = fixture.root / 'observations.jsonl'
    while time.monotonic() < deadline:
        current = collect(fixture)
        with observations.open('a') as out:
            out.write(json.dumps(current) + '\n')
        state = current['state']
        pending = sum(o['status'] not in {'NEW','PARTIALLY_FILLED','FILLED','CANCELLED','CANCELED','REJECTED','EXPIRED'} for o in state['orders'])
        if (previous and previous['observation'] == current['observation'] and not pending
                and len(state['orders']) == len(accepted)
                and len(state['executions']) == 2 * expected_trades
                and len(state['journal']) == len(funding) + expected_trades):
            if current['observation']['last_trade'] != max(e['trade'] for e in state['executions']):
                raise Inconclusive('AE has not applied the last committed trade')
            sample = {**state, 'initial_balances': initial, 'initial_snapshot_verified': True,
                      'funding': funding, 'accepted_order_ids': accepted, 'journal_first_seq': 1,
                      'markets': {'1': {'base': 1, 'quote': 0}},
                      'barrier': {'input_closed': True, 'pending_orders': 0,
                                  'samples': [previous['observation'], current['observation']]}}
            (fixture.root / 'money-sample.json').write_text(json.dumps(sample, indent=2) + '\n')
            return sample, reconcile(sample)
        previous = current
        time.sleep(.5)
    raise Inconclusive('exact committed/settled work did not reach a stable observation barrier')
