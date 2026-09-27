# SPDX-License-Identifier: Apache-2.0
"""Real faults restricted to owned fixture resources; raw fault witnesses are mandatory."""
import json
from pathlib import Path
import re
import stat
import time

from contracts import Inconclusive, Violation
from fixture import JAVA
from observe import stable_sample
from scenarios import critical_path_smoke, request, order_id


def probe(fixture, node, command='counters'):
    if node not in {'me0', 'me1', 'me2', 'ae0', 'ae1', 'ae2'}:
        raise Violation('probe target is not a fixture engine')
    if not fixture.m.get('test_helper'):
        raise Inconclusive('hash-pinned test probe is required')
    engine, index = node[:2], node[2:]
    directory = '/dev/shm/aeron-' + ('assets-' if engine == 'ae' else '') + index + '-driver'
    response = fixture.execute(node, JAVA + ['-Daeron.dir=' + directory, '-cp',
        '/artifacts/' + engine + '.jar:/artifacts/fixture-probe.jar', 'FixtureProbe', command])
    return json.loads(response.stdout)


def counter(observation, type_id):
    found = [c['value'] for c in observation['counters'] if c['type'] == type_id]
    if len(found) != 1:
        raise Inconclusive('missing/ambiguous independent counter: ' + str(type_id))
    return found[0]


def local_ready(fixture, node):
    port = 19500 if node.startswith('me') else 19700
    code = '''import urllib.request,urllib.error,json
try:
 r=urllib.request.urlopen('http://127.0.0.1:PORT/ready',timeout=3)
 print(json.dumps({'status':r.status,'body':r.read().decode()}))
except urllib.error.HTTPError as e:print(json.dumps({'status':e.code,'body':e.read().decode()}))
'''.replace('PORT', str(port))
    return json.loads(fixture.execute(node, ['python3', '-c', code]).stdout)


def false_ready(fixture, engine='me'):
    if engine not in {'me', 'ae'}:
        raise Violation('false-ready target must be a fixture engine')
    baseline = critical_path_smoke(fixture)
    sample = json.loads((fixture.root / 'money-sample.json').read_text())
    before = {name: probe(fixture, name) for name in [engine + str(i) for i in range(3)]}
    leaders = [name for name, obs in before.items() if counter(obs, 201) == 2]
    followers = [name for name, obs in before.items() if counter(obs, 201) == 0]
    if len(leaders) != 1 or len(followers) != 2:
        raise Inconclusive('expected a healthy three-member quorum before fault')
    target, leader = followers[-1], leaders[0]
    network = fixture.registry['network_id']; cid = fixture.registry['containers'][target]
    fixture.inspect('network', network); original = fixture.inspect('container', cid)
    if not original['State']['Running'] or not original['NetworkSettings']['Networks']:
        raise Inconclusive('fault target was not running and connected')
    evidence = {'target': target, 'leader': leader, 'before_counters': before,
                'baseline_money': baseline['money'], 'samples': [], 'reconnected': False}
    path = fixture.root / ('false-ready.json' if engine == 'me' else 'false-ready-ae.json')
    def save(): path.write_text(json.dumps(evidence, indent=2) + '\n')
    try:
        fixture.command(['docker', 'network', 'disconnect', network, cid])
        detached = fixture.inspect('container', cid)
        evidence['fault'] = {'kind': 'network_disconnect', 'before_networks': original['NetworkSettings']['Networks'],
            'after_networks': detached['NetworkSettings']['Networks'], 'running_after': detached['State']['Running']}
        save()
        if detached['NetworkSettings']['Networks'] or not detached['State']['Running']:
            raise Inconclusive('network fault was not observed on a live follower')
        # The pre-fault smoke left one SELL open. This new BUY must commit and settle while isolated.
        reply = request(fixture, 'POST', '/api/v1/orders', {'marketId': 1, 'side': 'BUY',
            'orderType': 'LIMIT', 'price': '100000.00000000', 'quantity': '0.01000000',
            'clientOrderId': fixture.run_id + '-after-partition'}, 71001)
        if reply.get('accepted') is not True: raise Inconclusive('quorum did not accept fault workload')
        accepted = sample['accepted_order_ids'] + [order_id(reply['omsOrderId'])]
        _, counts = stable_sample(fixture, sample['initial_balances'], sample['funding'], accepted, 13)
        evidence['after_fault_money'] = counts; save()
        for _ in range(5):
            low = probe(fixture, target); high = probe(fixture, leader); ready = local_ready(fixture, target)
            observation = {'target': low, 'leader': high, 'ready': ready, 'at_ns': time.time_ns(),
                           'target_commit': counter(low, 203), 'leader_commit': counter(high, 203)}
            evidence['samples'].append(observation); save()
            if observation['target_commit'] < observation['leader_commit'] and ready['status'] == 200:
                evidence['status'] = 'FAIL'; evidence['known_product_red'] = True
                evidence['reason'] = 'isolated follower advertises ready after quorum committed and settled new work beyond its log'
                save()
                raise Violation(evidence['reason'])
            time.sleep(1)
        if not any(s['target_commit'] < s['leader_commit'] for s in evidence['samples']):
            raise Inconclusive('fault did not produce independently observed replication lag')
        evidence['status'] = 'PASS'; save()
        return {'status': 'PASS', 'assertions': 5, 'processed': counts['trades'], 'skipped': 0,
                'child_exit_codes': [0], 'fault': evidence['fault'], 'scope': 'false-ready partition behavior'}
    finally:
        fixture.inspect('network', network); fixture.inspect('container', cid)
        fixture.command(['docker', 'network', 'connect', '--ip', fixture.m['nodes'][target], network, cid])
        evidence['reconnected'] = bool(fixture.inspect('container', cid)['NetworkSettings']['Networks']); save()


def threads(fixture, node):
    code = 'import pathlib,json; print(json.dumps({p.parent.name:p.read_text().strip() for p in pathlib.Path("/proc/1/task").glob("*/comm")}))'
    return json.loads(fixture.execute(node, ['python3', '-c', code]).stdout)


def node_log(fixture, node):
    cid = fixture.registry['containers'][node]; fixture.inspect('container', cid)
    result = fixture.command(['docker', 'logs', cid])
    return result.stdout + result.stderr


def pruner_exception(fixture):
    before = {name: probe(fixture, name) for name in ['me0', 'me1', 'me2']}
    leaders = [n for n, o in before.items() if counter(o, 201) == 2]
    followers = [n for n, o in before.items() if counter(o, 201) == 0]
    if len(leaders) != 1 or len(followers) != 2:
        raise Inconclusive('pruner fault requires healthy three-node quorum')
    target, leader = followers[0], leaders[0]
    before_threads = threads(fixture, target)
    if sum(n.startswith('snapshot-log-pr') for n in before_threads.values()) != 1:
        raise Inconclusive('pruner was not alive before fault')
    recording = fixture.root / 'state' / target / 'state/cluster/recording.log'
    if recording.is_symlink() or not recording.resolve().is_relative_to(fixture.root / 'state' / target):
        raise Violation('recording path escaped owned fixture')
    original_mode = stat.S_IMODE(recording.stat().st_mode)
    evidence = {'target': target, 'leader': leader, 'before_counters': before,
                'before_threads': before_threads, 'original_mode': oct(original_mode),
                'fault_restored': False, 'snapshots': []}
    path = fixture.root / 'pruner-exception.json'
    def save(): path.write_text(json.dumps(evidence, indent=2) + '\n')
    def wait_snapshot(node, old):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            now = probe(fixture, node)
            if counter(now, 205) > old:
                evidence['snapshots'].append(now); save(); return now
            time.sleep(.5)
        raise Inconclusive('requested snapshot did not complete')
    try:
        recording.chmod(0)
        # Exercise actual OS denial under the same uid as the engine. A fake flag is insufficient.
        code = '''import json
try:
 f=open('/data/state/cluster/recording.log','rb');f.close();print(json.dumps({'denied':False}))
except PermissionError as e:print(json.dumps({'denied':True,'errno':e.errno}))
'''
        evidence['denial'] = json.loads(fixture.execute(target, ['python3', '-c', code]).stdout); save()
        if evidence['denial'] != {'denied': True, 'errno': 13}:
            raise Inconclusive('permission fault was not observed')
        probe(fixture, leader, 'snapshot')
        wait_snapshot(target, counter(before[target], 205))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            logs = node_log(fixture, target)
            if 'SnapshotLogPruner' in logs and 'AccessDeniedException' in logs:
                evidence['injected_error_observed'] = True; save(); break
            time.sleep(.5)
        else:
            raise Inconclusive('pruner did not encounter the injected transient file error')
    finally:
        recording.chmod(original_mode)
        evidence['fault_restored'] = stat.S_IMODE(recording.stat().st_mode) == original_mode; save()
    first = counter(evidence['snapshots'][-1], 205)
    probe(fixture, leader, 'snapshot'); wait_snapshot(target, first)
    # Three original poll intervals. Thread existence plus a completed new snapshot independently
    # separates a permanently dead pruner from a quiet but retrying one.
    time.sleep(15)
    evidence['after_threads'] = threads(fixture, target)
    evidence['after_ready'] = local_ready(fixture, target)
    evidence['after_counters'] = probe(fixture, target)
    logs = node_log(fixture, target)
    (fixture.root / 'pruner-exception-target.log').write_text(logs)
    sample = json.loads((fixture.root / 'money-sample.json').read_text())
    trades = len({entry['trade'] for entry in sample['executions']})
    _, evidence['after_fault_money'] = stable_sample(fixture, sample['initial_balances'],
        sample['funding'], sample['accepted_order_ids'], trades)
    if not any(n.startswith('snapshot-log-pr') for n in evidence['after_threads'].values()):
        evidence.update(status='FAIL', known_product_red=True,
                        reason='pruner thread exited after a temporary permission error and did not resume after restoration and another completed snapshot')
        save(); raise Violation(evidence['reason'])
    # A candidate must also prove actual successful pruning after restoration, not just a live thread.
    if '[PRUNE] after snapshot ' + str(counter(evidence['after_counters'], 205)) not in logs:
        raise Inconclusive('pruner is alive but recovery was not demonstrated')
    evidence['status'] = 'PASS'; save()
    return {'status': 'PASS', 'assertions': 7, 'processed': trades, 'skipped': 0, 'child_exit_codes': [0],
            'scope': 'actual transient filesystem denial and completed-snapshot pruner recovery'}


def offline_purge(fixture):
    baseline = critical_path_smoke(fixture)
    sample = json.loads((fixture.root / 'money-sample.json').read_text())
    before = {n: probe(fixture, n) for n in ['me0', 'me1', 'me2']}
    leaders = [n for n, o in before.items() if counter(o, 201) == 2]
    followers = [n for n, o in before.items() if counter(o, 201) == 0]
    if len(leaders) != 1 or len(followers) != 2:
        raise Inconclusive('offline purge needs an independently observed healthy quorum')
    target, leader = followers[-1], leaders[0]
    evidence = {'target': target, 'leader': leader, 'before_counters': before,
                'baseline_money': baseline['money'], 'rejoin_samples': []}
    path = fixture.root / 'offline-purge.json'
    def save(): path.write_text(json.dumps(evidence, indent=2) + '\n')
    evidence['fault'] = fixture.kill(target); save()
    endpoints = ','.join(f'{i}={fixture.m["nodes"]["me"+str(i)]}:{9002+100*i}' for i in range(3))
    filled = fixture.execute('probe', JAVA + ['-cp', '/artifacts/me.jar:/artifacts/fixture-probe.jar',
        'FixtureProbe', 'fill-log', endpoints, fixture.m['nodes']['probe'], '900000'], timeout=380)
    evidence['diagnostic_log_fill'] = json.loads(filled.stdout); save()
    if evidence['diagnostic_log_fill']['processed'] != 900000 or evidence['diagnostic_log_fill']['uniqueResponses'] != 900000:
        raise Inconclusive('log fill did not demonstrably process the expected requests')
    evidence['after_fill'] = probe(fixture, leader); save()
    if counter(evidence['after_fill'], 203) - counter(before[target], 203) < 64 * 1024**2:
        raise Inconclusive('fixture did not cross the immutable engine archive segment size')
    archive = fixture.root / 'state' / leader / 'state/archive'
    evidence['segments_before'] = sorted(p.name for p in archive.glob('*.rec'))
    probe(fixture, leader, 'snapshot')
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        logs = node_log(fixture, leader)
        purges = re.findall(r'Purged (\d+) log segment\(s\): recordingId=(\d+) startPosition (\d+) -> (\d+)', logs)
        unsafe = [tuple(map(int, row)) for row in purges if int(row[3]) > counter(before[target], 203)]
        now = probe(fixture, leader)
        if counter(now, 205) > counter(evidence['after_fill'], 205):
            evidence['after_snapshot'] = now
            if unsafe:
                evidence['unsafe_purge'] = unsafe[-1]; break
            # A candidate that correctly holds the purge can still complete a normal rejoin.
            if '[PRUNE] after snapshot ' + str(counter(now, 205)) in logs:
                evidence['purge_held_below_offline_position'] = True; break
        time.sleep(.5)
    else:
        raise Inconclusive('snapshot/purge outcome did not become observable')
    evidence['segments_after'] = sorted(p.name for p in archive.glob('*.rec'))
    (fixture.root / 'offline-purge-leader.log').write_text(logs); save()
    cid = fixture.registry['containers'][target]; fixture.inspect('container', cid)
    fixture.command(['docker', 'start', cid]); evidence['restart_requested'] = True; save()
    goal = counter(evidence['after_fill'], 203)
    deadline = time.monotonic() + fixture.m['budgets']['maximum_recovery_seconds']
    recovered = False
    while time.monotonic() < deadline:
        process = fixture.inspect('container', cid)['State']
        observation = {'process': process, 'at_ns': time.time_ns()}
        if process['Running']:
            try:
                observation['counters'] = probe(fixture, target)
                observation['ready'] = local_ready(fixture, target)
                recovered = counter(observation['counters'], 203) >= goal and observation['ready']['status'] == 200
            except Inconclusive as error:
                observation['probe_error'] = str(error)
        evidence['rejoin_samples'].append(observation); save()
        if recovered or not process['Running']: break
        time.sleep(2)
    _, evidence['after_fault_money'] = stable_sample(fixture, sample['initial_balances'], sample['funding'], sample['accepted_order_ids'], 12)
    (fixture.root / 'offline-purge-target.log').write_text(node_log(fixture, target))
    evidence['recovered'] = recovered; save()
    if evidence.get('unsafe_purge'):
        evidence.update(status='FAIL', known_product_red=True,
                        reason='snapshot purge advanced beyond the offline member recovery position',
                        rejoin_outcome='RECOVERED' if recovered else 'FAILED_WITHIN_DECLARED_BUDGET')
        save(); raise Violation(evidence['reason'])
    if not recovered:
        raise Violation('offline member failed to rejoin within the declared recovery budget')
    evidence['status'] = 'PASS'; save()
    return {'status': 'PASS', 'assertions': 7, 'processed': 12, 'skipped': 0, 'child_exit_codes': [0],
            'fault': evidence['fault'], 'scope': 'offline follower/snapshot/purge/rejoin plus exact money'}
