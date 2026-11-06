# SPDX-License-Identifier: Apache-2.0
import json
import re
import time

from contracts import FP, Inconclusive, Violation
from observe import stable_sample, verify_genesis


def money(value):
    return f'{value // FP}.{value % FP:08d}'


def order_id(value):
    # Public OMS JSON encodes int64 IDs as decimal strings to avoid JS precision loss.
    if type(value) is str and re.fullmatch(r'[1-9][0-9]{0,18}', value):
        value = int(value)
    if type(value) is not int or not 0 < value < 2**63:
        raise Inconclusive('missing or inexact int64 order identity')
    return value


def request(fixture, method, path, body=None, user=None):
    started = time.monotonic_ns()
    response = fixture.http('oms', 18080, path, method, body, user)
    with (fixture.root / 'requests.jsonl').open('a') as out:
        out.write(json.dumps({'method': method, 'path': path, 'request': body, 'user': user,
                              'response': response, 'elapsed_ns': time.monotonic_ns() - started}) + '\n')
    if response['status'] not in (200, 201):
        raise Inconclusive('fixture request failed: ' + json.dumps(response))
    return json.loads(response['body'])


def critical_path_smoke(fixture, pairs=12):
    if pairs <= 0:
        raise Inconclusive('zero-work smoke is not an acceptance run')
    buyer, seller = 71001, 71002
    initial = verify_genesis(fixture, (buyer, seller))
    funding = []

    def movement(kind, user, asset, amount):
        response = request(fixture, 'POST', f'/api/v1/accounts/{user}/{kind}',
                           {'assetId': asset, 'amount': money(amount)}, user)
        if response.get('success') is not True:
            raise Violation('funding was not acknowledged: ' + json.dumps(response))
        funding.append({'kind': kind, 'user': user, 'asset': asset, 'amount': amount})

    movement('deposit', buyer, 0, 50_000 * FP)
    movement('deposit', seller, 1, FP)
    accepted = []

    def submit(user, side):
        response = request(fixture, 'POST', '/api/v1/orders',
                           {'marketId': 1, 'side': side, 'orderType': 'LIMIT',
                            'price': '100000.00000000', 'quantity': '0.01000000',
                            'clientOrderId': fixture.run_id + '-' + str(len(accepted))}, user)
        if response.get('accepted') is not True:
            raise Violation('order was not accepted with an exact identity: ' + json.dumps(response))
        accepted.append(order_id(response.get('omsOrderId')))
        time.sleep(.15)
        return accepted[-1]

    for _ in range(pairs):
        submit(seller, 'SELL'); submit(buyer, 'BUY')
    # One cancellation and one live open order exercise exact held funds, not only totals.
    cancel_id = submit(seller, 'SELL')
    response = request(fixture, 'DELETE', '/api/v1/orders/' + str(cancel_id), user=seller)
    if response.get('accepted') is not True:
        raise Violation('cancel was not accepted: ' + json.dumps(response))
    submit(seller, 'SELL')
    movement('withdraw', buyer, 0, FP)
    movement('withdraw', seller, 1, FP // 10)
    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': pairs, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, pairs)
    return {'status': 'PASS', 'assertions': 9, 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'open_holds': len(sample['holds']),
            'failure_domain': fixture.m['failure_domain'], 'scope': 'exact critical-path smoke; no latency/HA acceptance'}
