# SPDX-License-Identifier: Apache-2.0
"""R02 functional acceptance scenarios (A04-A09) on the journal cutover topology."""
import json
import time

from contracts import Inconclusive, Violation
from journal_cutover import BUYER, PRICE, QUANTITY, _probe, _scalar, admission, fund, wait_admission
from observe import stable_sample


def _evidence(fixture, name):
    evidence = {}
    save = lambda: (fixture.root / (name + '.json')).write_text(json.dumps(evidence, indent=2) + '\n')
    return evidence, save


def _rejected_without_effect(fixture, client):
    """A request refused at admission must leave no durable order behind."""
    reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST',
                         {'marketId': 1, 'side': 'BUY', 'orderType': 'LIMIT', 'price': PRICE,
                          'quantity': QUANTITY, 'clientOrderId': client}, BUYER)
    rows = _scalar(fixture, f"SELECT count(*) FROM orders WHERE client_order_id = '{client}'")
    return {'client': client, 'status': reply['status'], 'body': reply.get('body', reply.get('error')),
            'durable_rows': rows}


def oms_recovery_admission(fixture):
    """R02-A09: admission is closed while the projection is unverified or risk recovery failed."""
    if not fixture.m.get('journal_cutover'):
        raise Inconclusive('A09 requires the journal cutover topology')
    evidence, save = _evidence(fixture, 'oms-recovery-admission')
    initial, funding = fund(fixture)
    _, accepted = _probe(fixture, 'pre', 4, poll=False)
    if admission(fixture) != 1: raise Violation('admission closed on a healthy, caught-up stack')

    # 1. Unverified projection: a frozen projector goes stale and must close admission.
    xp = fixture.registry['containers']['xprojector']
    fixture.command(['docker', 'pause', xp]); evidence['projector_paused'] = True; save()
    try:
        evidence['stale_close_ms'] = wait_admission(fixture, 0, 15)
        evidence['stale_request'] = _rejected_without_effect(fixture, fixture.run_id + '-stale')
    finally:
        fixture.command(['docker', 'unpause', xp]); evidence['projector_unpaused'] = True; save()
    if evidence['stale_request']['status'] in (200, 201) or evidence['stale_request']['durable_rows'] != 0:
        raise Violation('an order was admitted or persisted while the projection was stale')
    evidence['fresh_open_ms'] = wait_admission(fixture, 1, 30); save()
    _, more = _probe(fixture, 'mid', 2, poll=False); accepted += more

    # 2. Failed risk read at startup is not an empty install: the OMS must stay closed.
    evidence['fault'] = fixture.kill('oms'); save()
    fixture.psql('r01_oms', 'ALTER TABLE oms_risk_positions RENAME TO oms_risk_positions_withheld')
    oms = fixture.registry['containers']['oms']
    try:
        fixture.command(['docker', 'start', oms])
        observed, deadline = [], time.monotonic() + 30
        while time.monotonic() < deadline:
            state = fixture.inspect('container', oms)['State']
            gauge = admission(fixture) if state['Running'] else None
            observed.append({'running': state['Running'], 'exit': state['ExitCode'], 'admission': gauge})
            if gauge == 1: break
            if not state['Running']: break
            time.sleep(.5)
        evidence['failed_read'] = {'samples': len(observed), 'last': observed[-1],
                                   'ever_admitted': any(o['admission'] == 1 for o in observed)}
        save()
        if evidence['failed_read']['ever_admitted']:
            raise Violation('admission opened although risk positions could not be read')
        evidence['failed_read_request'] = _rejected_without_effect(fixture, fixture.run_id + '-noread') \
            if observed[-1]['running'] else {'oms_exited': observed[-1]['exit']}
        save()
    finally:
        fixture.psql('r01_oms', 'ALTER TABLE oms_risk_positions_withheld RENAME TO oms_risk_positions')
    # 3. Recovery: the same state now reads, and admission opens.
    if fixture.inspect('container', oms)['State']['Running']:
        fixture.command(['docker', 'kill', '--signal=KILL', oms])
    fixture.command(['docker', 'start', oms])
    evidence['recovered_open_ms'] = wait_admission(fixture, 1, 120); save()
    _, more = _probe(fixture, 'post', 2, poll=False); accepted += more

    pairs = len(accepted) // 2
    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': pairs, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, pairs)
    return {'status': 'PASS', 'assertions': 6, 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'fault': evidence['fault'],
            'stale_close_ms': evidence['stale_close_ms'], 'fresh_open_ms': evidence['fresh_open_ms'],
            'failed_read': evidence['failed_read'], 'recovered_open_ms': evidence['recovered_open_ms'],
            'failure_domain': fixture.m['failure_domain'],
            'scope': 'R02-A09 admission gate: stale projection, failed risk read, recovery'}


# Runs inside the probe container: the same request from several threads released together.
CONCURRENT = r'''import json,sys,threading,urllib.request,urllib.error
job=json.loads(sys.stdin.read()); gate=threading.Barrier(job["threads"]); out=[None]*job["threads"]
def send(i):
    headers={"Content-Type":"application/json","Authorization":"Bearer dev:"+str(job["user"])}
    req=urllib.request.Request(job["url"],data=json.dumps(job["body"]).encode(),headers=headers,method="POST")
    gate.wait()
    try:
        r=urllib.request.urlopen(req,timeout=10); out[i]={"status":r.status,"body":r.read().decode()}
    except urllib.error.HTTPError as e: out[i]={"status":e.code,"body":e.read().decode()}
    except Exception as e: out[i]={"status":0,"error":str(e)}
ts=[threading.Thread(target=send,args=(i,)) for i in range(job["threads"])]
[t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps(out))
'''


def _order_body(fixture, label, side, quantity=QUANTITY, request_id=None):
    body = {'marketId': 1, 'side': side, 'orderType': 'LIMIT', 'price': PRICE, 'quantity': quantity,
            'clientOrderId': f'{fixture.run_id}-{label}'}
    if request_id: body['requestId'] = request_id
    return body


def _log_request(fixture, body, user, response):
    with (fixture.root / 'requests.jsonl').open('a') as log:
        log.write(json.dumps({'method': 'POST', 'path': '/api/v1/orders', 'request': body, 'user': user,
                              'response': response, 'elapsed_ns': 0}) + '\n')


def _reply(response):
    try: return json.loads(response.get('body') or '{}')
    except ValueError: return {}


def oms_durable_request_id(fixture, threads=8):
    """R02-A08: one durable outcome per requestId across concurrency, restart and payload change."""
    from journal_cutover import SELLER
    if not fixture.m.get('journal_cutover'):
        raise Inconclusive('A08 requires the journal cutover topology')
    evidence, save = _evidence(fixture, 'oms-durable-request-id')
    initial, funding = fund(fixture)
    _, accepted = _probe(fixture, 'pre', 2, poll=False)

    # 1. Concurrent identical requests: exactly one order, every answer names it.
    r1 = _order_body(fixture, 'r1', 'SELL', request_id=fixture.run_id + '-req-1')
    job = {'url': f'http://{fixture.m["nodes"]["oms"]}:18080/api/v1/orders', 'user': SELLER,
           'threads': threads, 'body': r1}
    answers = json.loads(fixture.execute('probe', ['python3', '-c', CONCURRENT], input=json.dumps(job), timeout=60).stdout)
    ids = {_reply(a).get('omsOrderId') for a in answers}
    fresh = [a for a in answers if a['status'] in (200, 201) and _reply(a).get('accepted') is True and not _reply(a).get('duplicate')]
    rows = _scalar(fixture, f"SELECT count(*) FROM orders WHERE client_order_id = '{r1['clientOrderId']}'")
    evidence['concurrent'] = {'threads': threads, 'statuses': [a['status'] for a in answers],
                              'distinct_ids': sorted(map(str, ids)), 'fresh': len(fresh), 'durable_rows': rows}
    save()
    if len(ids) != 1 or None in ids or len(fresh) != 1 or rows != 1:
        raise Violation('concurrent requests with one requestId did not resolve to exactly one order')
    _log_request(fixture, r1, SELLER, fresh[0]); accepted.append(int(next(iter(ids))))
    b1 = _order_body(fixture, 'b1', 'BUY'); reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST', b1, BUYER)
    if _reply(reply).get('accepted') is not True: raise Violation('crossing order was not accepted')
    _log_request(fixture, b1, BUYER, reply); accepted.append(int(_reply(reply)['omsOrderId']))

    # 2. Same requestId, different payload: refused, no second order.
    changed = dict(r1, quantity='0.02000000')
    reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST', changed, SELLER)
    rows = _scalar(fixture, f"SELECT count(*) FROM orders WHERE client_order_id = '{r1['clientOrderId']}'")
    evidence['changed_payload'] = {'status': reply['status'], 'body': reply.get('body'), 'durable_rows': rows}
    save()
    if _reply(reply).get('accepted') is True and not _reply(reply).get('duplicate') or rows != 1:
        raise Violation('a changed payload under an existing requestId produced a new order')
    if _reply(reply).get('accepted') is True:
        raise Violation('a changed payload under an existing requestId was answered as accepted')

    # 3. Retry after the OMS is killed right after acceptance: same order, no second one.
    r2 = _order_body(fixture, 'r2', 'SELL', request_id=fixture.run_id + '-req-2')
    first = fixture.http('oms', 18080, '/api/v1/orders', 'POST', r2, SELLER)
    if _reply(first).get('accepted') is not True: raise Violation('retry subject was not accepted')
    evidence['fault'] = fixture.kill('oms'); save()
    fixture.command(['docker', 'start', fixture.registry['containers']['oms']])
    evidence['restart_open_ms'] = wait_admission(fixture, 1, 120)
    retry = fixture.http('oms', 18080, '/api/v1/orders', 'POST', r2, SELLER)
    rows = _scalar(fixture, f"SELECT count(*) FROM orders WHERE client_order_id = '{r2['clientOrderId']}'")
    evidence['retry_after_restart'] = {'first': _reply(first), 'retry_status': retry['status'],
                                       'retry': _reply(retry), 'durable_rows': rows}
    save()
    if (_reply(retry).get('omsOrderId') != _reply(first).get('omsOrderId') or rows != 1
            or _reply(retry).get('accepted') is not True):
        raise Violation('retry after restart did not return the original durable outcome')
    _log_request(fixture, r2, SELLER, first); accepted.append(int(_reply(first)['omsOrderId']))
    b2 = _order_body(fixture, 'b2', 'BUY'); reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST', b2, BUYER)
    if _reply(reply).get('accepted') is not True: raise Violation('crossing order was not accepted')
    _log_request(fixture, b2, BUYER, reply); accepted.append(int(_reply(reply)['omsOrderId']))

    pairs = len(accepted) // 2
    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': pairs, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, pairs)
    return {'status': 'PASS', 'assertions': 6, 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'fault': evidence['fault'],
            'concurrent': evidence['concurrent'], 'changed_payload_status': evidence['changed_payload']['status'],
            'failure_domain': fixture.m['failure_domain'],
            'scope': 'R02-A08 durable requestId: concurrency, changed payload, retry after OMS SIGKILL'}


def _projector_last_trade(fixture):
    return _scalar(fixture, 'SELECT last_trade_id FROM execution_projector_checkpoint')


def _wait_projector(fixture, trades, timeout=60):
    deadline = time.monotonic() + timeout
    while _projector_last_trade(fixture) < trades:
        state = fixture.inspect('container', fixture.registry['containers']['xprojector'])['State']
        if not state['Running']: return {'exited': state['ExitCode']}
        if time.monotonic() > deadline: raise Violation('projector did not catch up after the fault')
        time.sleep(.2)
    return {'caught_up': trades}


def execution_projector_replay_crash(fixture, rounds=(0.0, 0.02, 0.1), batch=6):
    """R02-A05: the projector loses or doubles nothing across SIGKILL mid catch-up and a dropped DB session."""
    if not fixture.m.get('journal_cutover'):
        raise Inconclusive('A05 requires the journal cutover topology')
    evidence, save = _evidence(fixture, 'execution-projector-replay-crash')
    evidence['faults'] = []
    initial, funding = fund(fixture)
    _, accepted = _probe(fixture, 'pre', 2, poll=False)
    xp = fixture.registry['containers']['xprojector']
    trades = _wait_projector(fixture, len(accepted) // 2) and len(accepted) // 2

    def backlog(label):
        fixture.command(['docker', 'pause', xp])
        try:
            _, more = _probe(fixture, label, batch, poll=False)
        finally:
            fixture.command(['docker', 'unpause', xp])
        accepted.extend(more)
        return trades + batch

    # 1. SIGKILL while catching up on a committed backlog, at three points into the catch-up.
    for n, delay in enumerate(rounds):
        target = backlog(f'k{n}')
        time.sleep(delay)
        before = _projector_last_trade(fixture)
        proof = fixture.kill('xprojector')
        fixture.command(['docker', 'start', xp])
        outcome = _wait_projector(fixture, target)
        evidence['faults'].append({'kind': 'sigkill', 'delay_s': delay, 'checkpoint_before': before,
                                   'target': target, 'proof': proof, 'outcome': outcome}); save()
        if 'exited' in outcome: raise Violation('projector exited after restart: ' + json.dumps(outcome))
        trades = target

    # 2. Database session terminated during catch-up: no partial commit, resume from checkpoint.
    target = backlog('db')
    node = fixture.m['nodes']['xprojector']
    killed = fixture.psql('r01_oms', "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                                     f"WHERE datname='r01_oms' AND client_addr='{node}'")
    time.sleep(1)
    state = fixture.inspect('container', xp)['State']
    restarted = False
    if not state['Running']:
        # A supervisor restarts a worker that stops on a lost session; the fixture plays that role.
        fixture.command(['docker', 'start', xp]); restarted = True
    outcome = _wait_projector(fixture, target)
    evidence['faults'].append({'kind': 'pg_terminate_backend', 'sessions': int(killed), 'exit_code': state['ExitCode'],
                               'process_stopped': not state['Running'], 'restarted': restarted, 'outcome': outcome})
    save()
    if int(killed) < 1: raise Inconclusive('no projector database session was found to terminate')
    if 'exited' in outcome: raise Violation('projector did not resume after the database fault')
    trades = target

    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': trades, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, trades)
    duplicates = _scalar(fixture, 'SELECT count(*) FROM (SELECT trade_id, oms_order_id FROM executions '
                                  'GROUP BY 1, 2 HAVING count(*) > 1) d')
    evidence.update(final_checkpoint_trade=_projector_last_trade(fixture), duplicate_legs=duplicates); save()
    if duplicates != 0: raise Violation('duplicate execution legs after projector faults')
    if evidence['final_checkpoint_trade'] != trades: raise Violation('projector checkpoint differs from committed trades')
    return {'status': 'PASS', 'assertions': 4 + len(evidence['faults']), 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'fault': evidence['faults'][0]['proof'],
            'faults': evidence['faults'], 'failure_domain': fixture.m['failure_domain'],
            'scope': 'R02-A05 C++ projector: SIGKILL during catch-up x3, database session loss'}


def oms_hold_release_authority(fixture, resting=3):
    """R02-A07: lost acks, an OMS restart and a reconcile sweep release no hold; only a terminal does."""
    from journal_cutover import SELLER
    from scenarios import request
    if not fixture.m.get('journal_cutover'):
        raise Inconclusive('A07 requires the journal cutover topology')
    evidence, save = _evidence(fixture, 'oms-hold-release-authority')
    initial, funding = fund(fixture)
    _, accepted = _probe(fixture, 'pre', 2, poll=False)
    me = [fixture.registry['containers'][f'me{i}'] for i in range(3)]

    # 1. Freeze the matching cluster: holds are placed, ME commands are written but never acknowledged.
    sells = []
    fixture.command(['docker', 'pause', *me]); evidence['me_paused'] = True; save()
    try:
        for n in range(resting):
            body = _order_body(fixture, f'rest-{n}', 'SELL')
            reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST', body, SELLER)
            if _reply(reply).get('accepted') is not True: raise Violation('order not accepted while ME was frozen')
            _log_request(fixture, body, SELLER, reply); sells.append(int(_reply(reply)['omsOrderId']))
        evidence['unacknowledged_commands'] = _scalar(fixture, "SELECT count(*) FROM oms_me_commands WHERE state <> 'RESOLVED'")
        evidence['fault'] = fixture.kill('oms')
    finally:
        fixture.command(['docker', 'unpause', *me]); evidence['me_unpaused'] = True; save()
    accepted += sells

    # 2. Restart: the outbox resends, the reconciler sweeps; resting holds must be untouched.
    fixture.command(['docker', 'start', fixture.registry['containers']['oms']])
    evidence['restart_open_ms'] = wait_admission(fixture, 1, 120)
    time.sleep(10)
    logs = fixture.command(['docker', 'logs', fixture.registry['containers']['oms']], check=False)
    text = logs.stdout + logs.stderr
    evidence['reconciler_armed'] = 'AssetsHoldReconciler' in text and 'arm' in text.lower()
    evidence['unresolved_after_restart'] = _scalar(fixture, "SELECT count(*) FROM oms_me_commands WHERE state <> 'RESOLVED'")
    save()
    if evidence['unacknowledged_commands'] < 1:
        raise Inconclusive('no ME command was left unacknowledged; lost-ack path not exercised')

    # 3. Only authoritative terminals resolve the reservations: one cancel, the rest fill.
    response = request(fixture, 'DELETE', '/api/v1/orders/' + str(sells[0]), user=SELLER)
    if response.get('accepted') is not True: raise Violation('cancel was not accepted')
    for n in range(1, resting):
        body = _order_body(fixture, f'take-{n}', 'BUY')
        reply = fixture.http('oms', 18080, '/api/v1/orders', 'POST', body, BUYER)
        if _reply(reply).get('accepted') is not True: raise Violation('crossing order not accepted')
        _log_request(fixture, body, BUYER, reply); accepted.append(int(_reply(reply)['omsOrderId']))

    trades = 2 + resting - 1
    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': trades, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, trades)
    commands = json.loads(fixture.psql('r01_oms', "SELECT json_build_object('total',count(*),"
        "'resolved',count(*) FILTER (WHERE state='RESOLVED'),'orders',count(DISTINCT oms_order_id)) FROM oms_me_commands"))
    evidence['me_commands'] = commands; save()
    if commands['resolved'] != commands['total']: raise Violation('ME commands left unresolved')
    if not evidence['reconciler_armed']: raise Inconclusive('hold reconciler never armed after restart')
    return {'status': 'PASS', 'assertions': 5, 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'fault': evidence['fault'],
            'unacknowledged_commands': evidence['unacknowledged_commands'], 'me_commands': commands,
            'failure_domain': fixture.m['failure_domain'],
            'scope': 'R02-A07 hold release authority: frozen ME, lost acks, OMS SIGKILL, reconcile sweep'}
