# SPDX-License-Identifier: Apache-2.0
"""Readiness fault evidence and a fail-closed, fixture-only rolling restart gate."""
import json
import time
from contracts import Inconclusive, Violation
from faults import counter, false_ready, local_ready, probe
from observe import stable_sample
from scenarios import request, order_id


def fields(response):
    try:
        values = dict(part.split('=', 1) for part in response['body'].split())
        for name in ['source', 'term', 'elections', 'applied', 'commit', 'checkpoint', 'observationAgeMs']:
            values[name] = int(values[name])
        return values
    except (KeyError, ValueError, TypeError) as error:
        raise Inconclusive('readiness response lacks verifiable checkpoint evidence') from error


def authorize_next_restart(engine, recovering, observations, now_ns):
    """Pure certificate check. Caller alone owns and performs Docker mutations."""
    names = {engine + str(i) for i in range(3)}
    if set(observations) != names or recovering not in names:
        raise Inconclusive('missing member identity for rolling restart')
    parsed = {}
    for name, observation in observations.items():
        age = now_ns - observation['observed_ns']
        if age < 0 or age > 1_000_000_000 or observation['ready']['status'] != 200:
            raise Inconclusive('member not freshly ready: ' + name)
        value = fields(observation['ready'])
        if (value['recovery'] != 'ready' or value['role'] not in {'LEADER', 'FOLLOWER'}
                or min(value['source'], value['term'], value['applied'], value['commit'], value['checkpoint']) < 0
                or not 0 <= value['observationAgeMs'] < 1000):
            raise Inconclusive('member proof is incomplete: ' + name)
        parsed[name] = value
    leaders = [name for name, value in parsed.items() if value['role'] == 'LEADER']
    if len(leaders) != 1 or len({v['term'] for v in parsed.values()}) != 1:
        raise Inconclusive('leader or term is not coherent')
    leader = leaders[0]
    checkpoint = parsed[leader]['commit']
    if parsed[recovering]['applied'] < checkpoint:
        raise Inconclusive('recovering replica has not applied the observed leader checkpoint')
    return {'leader': leader, 'term': parsed[leader]['term'], 'leader_source': parsed[leader]['source'],
            'checkpoint': checkpoint, 'recovering': recovering, 'replica_source': parsed[recovering]['source'],
            'replica_applied': parsed[recovering]['applied'], 'authorized_at_ns': now_ns}


def observations(fixture, engine):
    # One owned probe subprocess, bounded HTTP calls. The certificate refers to
    # the observed leader checkpoint, never a guessed future position.
    code = '''import json,sys,time,urllib.request,urllib.error
nodes=json.load(sys.stdin);result={}
for name,url in nodes.items():
 try:
  r=urllib.request.urlopen(url,timeout=.2);reply={'status':r.status,'body':r.read().decode()}
 except urllib.error.HTTPError as e:reply={'status':e.code,'body':e.read().decode()}
 except Exception as e:reply={'status':0,'error':str(e)}
 result[name]={'ready':reply}
print(json.dumps(result))
'''
    port = 19500 if engine == 'me' else 19700
    started = time.monotonic_ns()
    result = json.loads(fixture.execute('probe', ['python3', '-c', code], input=json.dumps({
        engine + str(i): f'http://{fixture.m["nodes"][engine + str(i)]}:{port}/ready' for i in range(3)
    }), timeout=10).stdout)
    # Conservative request-start timestamp also includes container and HTTP time.
    for value in result.values(): value['observed_ns'] = started
    return result


def readiness_scenario(fixture, engine):
    evidence = {'engine': engine, 'samples': [], 'restart_decisions': []}
    path = fixture.root / ('readiness-' + engine + '.json')
    def save(): path.write_text(json.dumps(evidence, indent=2) + '\n')
    def sample(stage):
        value = observations(fixture, engine)
        evidence['samples'].append({'stage': stage, 'members': value}); save()
        return value
    def await_certificate(recovering, stage):
        deadline = time.monotonic() + fixture.m['budgets']['maximum_recovery_seconds']
        while time.monotonic() < deadline:
            current = sample(stage)
            try: certificate = authorize_next_restart(engine, recovering, current, time.monotonic_ns())
            except Inconclusive:
                time.sleep(.2); continue
            evidence['restart_decisions'].append({'decision': 'ALLOW', **certificate}); save()
            return certificate
        raise Violation('replica did not become verifiably ready within recovery budget')

    # No business traffic is necessary for service/consensus liveness.
    port = 19500 if engine == 'me' else 19700
    for i in range(6):
        current = sample('idle')
        if any(v['ready']['status'] != 200 for v in current.values()):
            raise Violation('healthy idle member is permanently unready')
        for name in current:
            health = fixture.http(name, port, '/health')
            if health['status'] != 200: raise Violation('healthy idle member is not live')
        time.sleep(1)

    # Exactly the original regression: real partition, independently proven lag,
    # committed/settled work on quorum, and local HTTP from the isolated node.
    def deny_next_restart(target):
        before_pids = {name: fixture.inspect('container', cid)['State']['Pid']
                       for name, cid in fixture.registry['containers'].items() if name.startswith(engine)}
        current = observations(fixture, engine)  # sampled while the partition is still active
        try: authorize_next_restart(engine, target, current, time.monotonic_ns())
        except Inconclusive as error:
            after_pids = {name: fixture.inspect('container', fixture.registry['containers'][name])['State']['Pid']
                          for name in before_pids}
            if before_pids != after_pids: raise Violation('a process changed during denied restart')
            evidence['restart_decisions'].append({'decision': 'DENY', 'recovering': target,
                'reason': str(error), 'next_restart_executed': False, 'observations': current,
                'pids_before': before_pids, 'pids_after': after_pids})
            save()
        else: raise Violation('rollout gate accepted an unverified recovering replica')

    partition_result = false_ready(fixture, engine, on_partition=deny_next_restart)
    partition_path = fixture.root / ('false-ready.json' if engine == 'me' else 'false-ready-ae.json')
    partition = json.loads(partition_path.read_text())
    evidence['partition'] = partition; save()
    target = partition['target']
    certificate = await_certificate(target, 'partition-rejoin')

    # Force a real leadership change, retaining the old member's state for rejoin.
    leader = certificate['leader']
    before = probe(fixture, leader)
    if counter(before, 201) != 2: raise Inconclusive('leadership changed before fault injection')
    evidence['leader_kill'] = fixture.kill(leader); save()
    old_term = certificate['term']
    deadline = time.monotonic() + fixture.m['budgets']['maximum_failover_seconds']
    replacement = None
    while time.monotonic() < deadline:
        current = sample('leader-loss')
        for name, value in current.items():
            if name == leader or value['ready']['status'] != 200: continue
            body = fields(value['ready'])
            if body['role'] == 'LEADER' and body['term'] > old_term: replacement = name
        if replacement: break
        time.sleep(.2)
    if replacement is None: raise Violation('no ready replacement leader within failover budget')
    evidence['replacement_leader'] = replacement; save()
    cid = fixture.registry['containers'][leader]; fixture.inspect('container', cid)
    fixture.command(['docker', 'start', cid])
    after = await_certificate(leader, 'leader-rejoin')
    if after['term'] <= old_term: raise Violation('new leadership term was not observed')

    # Sustained nonzero request work with exact finances; full capacity/latency
    # acceptance remains the separately budgeted benchmark scenario.
    financial = json.loads((fixture.root / 'money-sample.json').read_text())
    accepted = list(financial['accepted_order_ids'])
    trades = partition['after_fault_money']['trades']
    ready_counts = {engine + str(i): 0 for i in range(3)}
    for i in range(20):
        for side, user in [('SELL', 71002), ('BUY', 71001)]:
            reply = request(fixture, 'POST', '/api/v1/orders', {'marketId': 1, 'side': side,
                'orderType': 'LIMIT', 'price': '100000.00000000', 'quantity': '0.01000000',
                'clientOrderId': fixture.run_id + '-readiness-' + str(i) + '-' + side}, user)
            if reply.get('accepted') is not True: raise Violation('readiness workload rejected')
            accepted.append(order_id(reply['omsOrderId']))
        for name, value in sample('request-work').items():
            if value['ready']['status'] == 200: ready_counts[name] += 1
    _, money = stable_sample(fixture, financial['initial_balances'], financial['funding'], accepted, trades + 20)
    evidence['money'] = money; evidence['ready_samples_under_work'] = ready_counts; save()
    if min(ready_counts.values()) < 15: raise Violation('member remained unready under request work')
    await_certificate(leader, 'final')
    evidence['status'] = 'PASS'; save()
    return {'status': 'PASS', 'assertions': 30, 'processed': money['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': money, 'fault': evidence['leader_kill'],
            'scope': 'idle, partition, checkpoint-gated rollout, leader loss and request work for ' + engine,
            'partition_assertions': partition_result['assertions']}
