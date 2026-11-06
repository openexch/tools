# SPDX-License-Identifier: Apache-2.0
"""Read exact fixture evidence. No tolerance, schema guessing or missing-data defaults."""
import json
import re
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
    orders = sql_rows(fixture, 'r01_oms', '''SELECT oms_order_id AS id, client_order_id AS client, user_id AS "user",
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


def request_intents(path):
    specs = []
    def fixed(value):
        if type(value) is not str or not re.fullmatch(r'[0-9]+\.[0-9]{8}', value):
            raise Inconclusive('request price/quantity is not the declared exact decimal format')
        return int(value.replace('.', ''))
    for line in path.read_text().splitlines():
        req = json.loads(line)
        if req['method'] != 'POST' or req['path'] != '/api/v1/orders': continue
        reply = json.loads(req['response'].get('body', '{}'))
        if reply.get('accepted') is not True: continue
        value = reply['omsOrderId']
        if not (type(value) is int or type(value) is str and re.fullmatch(r'[1-9][0-9]*', value)):
            raise Inconclusive('invalid accepted request identity')
        body = req['request']
        specs.append({'id': int(value), 'user': req['user'], 'market': body['marketId'],
                      'client': body['clientOrderId'], 'side': body['side'],
                      'price': fixed(body['price']), 'quantity': fixed(body['quantity'])})
    return specs


def request_outcomes(path, orders):
    """Bind non-acknowledged database rows to the actual HTTP request, never infer acceptance."""
    by_client = {row['client']: row for row in orders}
    if len(by_client) != len(orders): raise Violation('duplicate persisted client order identity')
    rejected, uncertain, unseen = [], [], []
    seen = set()
    for line in path.read_text().splitlines():
        req = json.loads(line)
        if req['method'] != 'POST' or req['path'] != '/api/v1/orders': continue
        body = req['request']; client = body['clientOrderId']
        if client in seen: raise Violation('duplicate submitted client order identity')
        seen.add(client)
        status = req['response']['status']
        reply = json.loads(req['response'].get('body', '{}'))
        if status in (200, 201) and reply.get('accepted') is True: continue
        definitive = 400 <= status < 500 and reply.get('accepted') is False
        if not definitive and status != 0 and status < 500:
            raise Inconclusive('unmodelled HTTP order outcome')
        row = by_client.get(client)
        if row is None:
            if not definitive: unseen.append(client)
            continue
        def fixed(value):
            if type(value) is not str or not re.fullmatch(r'[0-9]+\.[0-9]{8}', value):
                raise Inconclusive('unmodelled request decimal')
            return int(value.replace('.', ''))
        spec = {'id': row['id'], 'client': client, 'user': req['user'], 'market': body['marketId'],
                'side': body['side'], 'price': fixed(body['price']), 'quantity': fixed(body['quantity'])}
        (rejected if definitive else uncertain).append(spec)
    return {'rejected_order_specs': rejected, 'unacknowledged_order_specs': uncertain,
            'unobserved_ambiguous_requests': unseen}


def request_cancellations(path):
    ids = []
    for line in path.read_text().splitlines():
        request = json.loads(line)
        if request['method'] != 'DELETE': continue
        match = re.fullmatch(r'/api/v1/orders/([1-9][0-9]*)', request['path'])
        if match and request['response']['status'] in (200, 201):
            response = json.loads(request['response']['body'])
            if response.get('accepted') is True: ids.append(int(match.group(1)))
    return ids


def sample_from_stable_observations(fixture, initial, funding, accepted, first, second):
    if first['observation'] != second['observation']:
        raise Inconclusive('changing observations cannot establish financial correctness')
    state = second['state']
    pending = sum(o['status'] not in {'NEW','PARTIALLY_FILLED','FILLED','CANCELLED','CANCELED','REJECTED','EXPIRED'} for o in state['orders'])
    if pending: raise Inconclusive('financial outcome still pending')
    specs = request_intents(fixture.root / 'requests.jsonl')
    outcomes = request_outcomes(fixture.root / 'requests.jsonl', state['orders'])
    if outcomes['unobserved_ambiguous_requests']:
        raise Inconclusive('HTTP response lost and no durable outcome observed')
    sample = {**state, 'initial_balances': initial, 'initial_snapshot_verified': True,
              'funding': funding, 'accepted_order_ids': accepted, 'journal_first_seq': 1,
              'accepted_order_specs': specs, **outcomes,
              'cancelled_order_ids': request_cancellations(fixture.root / 'requests.jsonl'),
              'markets': {'1': {'base': 1, 'quote': 0}},
              'barrier': {'input_closed': True, 'pending_orders': 0,
                          'samples': [first['observation'], second['observation']]}}
    (fixture.root / 'money-sample.json').write_text(json.dumps(sample, indent=2) + '\n')
    exact = reconcile(sample)
    if second['observation']['last_trade'] != max(e['trade'] for e in state['executions']):
        raise Inconclusive('AE checkpoint differs from exact committed trade set')
    return sample, exact


def stable_sample(fixture, initial, funding, accepted, expected_trades, timeout=30):
    deadline = time.monotonic() + timeout
    previous = None
    stable_pair = None
    observations = fixture.root / 'observations.jsonl'
    while time.monotonic() < deadline:
        current = collect(fixture)
        with observations.open('a') as out:
            out.write(json.dumps(current) + '\n')
        state = current['state']
        pending = sum(o['status'] not in {'NEW','PARTIALLY_FILLED','FILLED','CANCELLED','CANCELED','REJECTED','EXPIRED'} for o in state['orders'])
        stable_pair = (previous, current) if previous and previous['observation'] == current['observation'] and not pending else None
        if (stable_pair
                and set(accepted).issubset({o['id'] for o in state['orders']})
                and len(state['executions']) == 2 * expected_trades
                and len(state['journal']) == len(funding) + expected_trades):
            return sample_from_stable_observations(fixture, initial, funding, accepted, *stable_pair)
        previous = current
        time.sleep(.5)
    if stable_pair:
        # A stable but WRONG terminal state is not missing data. Wait out the declared drain
        # budget first, then let the exact oracle expose lost fills, extra money or wrong cancels.
        sample, exact = sample_from_stable_observations(fixture, initial, funding, accepted, *stable_pair)
        if exact['trades'] != expected_trades:
            raise Violation('stable completed trade count differs from the declared workload')
        return sample, exact
    raise Inconclusive('exact committed/settled work did not reach a stable observation barrier')
