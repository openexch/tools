# SPDX-License-Identifier: Apache-2.0
"""Drop only an owned follower's log UDP port, leaving consensus/HTTP intact."""
import hashlib
import json
from pathlib import Path
import time

from contracts import Inconclusive, Violation
from fixture import LABEL
from faults import counter, local_ready, probe
from readiness import fields
from observe import stable_sample
from scenarios import critical_path_smoke, request, order_id


def filter_arguments(manifest, target, action):
    if target not in {e + str(i) for e in ('me', 'ae') for i in range(3)}:
        raise Violation('log filter requires an explicit fixture engine member')
    if action not in {'add', 'delete', 'counters'}:
        raise Violation('unsupported log filter operation')
    if action == 'counters': return ['-L', 'INPUT', '-n', '-v', '-x']
    port = manifest['ports'][target[:2] + '_base'] + int(target[2:]) * manifest['ports']['stride'] + 4
    return ['-w', '2', '-A' if action == 'add' else '-D', 'INPUT', '-p', 'udp',
            '--dport', str(port), '-j', 'DROP']


def log_filter(fixture, target, action):
    arguments = filter_arguments(fixture.m, target, action)
    cid = fixture.registry['containers'][target]
    target_state = fixture.inspect('container', cid)
    if not target_state['State']['Running'] or target_state['HostConfig']['NetworkMode'] != fixture.registry['network_id']:
        raise Inconclusive('log filter target is not in its owned private network')
    fixture.inspect('network', fixture.registry['network_id'])
    helper = fixture.m.get('netfilter_helper')
    if not helper: raise Inconclusive('hash-pinned netfilter helper required')
    root = Path(helper['path']).resolve()
    for name, entry in helper['files'].items():
        source = (root / name).resolve()
        if not source.is_relative_to(root) or hashlib.sha256(source.read_bytes()).hexdigest() != entry['sha256']:
            raise Violation('netfilter helper digest or path mismatch')
    name = 'log-filter'
    if name in fixture.registry['containers']: raise Violation('another filter helper is active')
    # NET_ADMIN/NET_RAW apply only inside the already-owned target's namespace.
    # No host PID/network namespace, writable host mounts, or privileged mode.
    argv = ['docker', 'create', '--name', fixture.run_id + '-' + name,
        '--network', 'container:' + cid, '--label', LABEL + '=' + fixture.run_id,
        '--label', LABEL + '.token=' + fixture.token, '--user', '0', '--read-only',
        '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
        '--security-opt', 'no-new-privileges', '--pids-limit', '16', '--memory', '64m',
        '--memory-swap', '64m', '--cpus', '0.25', '--tmpfs', '/tmp:rw,nosuid,size=1m',
        '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
        '--env', 'XTABLES_LIBDIR=/tool/extensions', '--env', 'XTABLES_LOCKFILE=/tmp/xtables.lock',
        '--mount', 'type=bind,src=' + str(root) + ',dst=/tool,readonly',
        '--entrypoint', '/tool/ld.so', fixture.m['image'], '--library-path', '/tool',
        '/tool/iptables-legacy', *arguments]
    helper_id = fixture.command(argv).stdout.strip()
    fixture.registry['containers'][name] = helper_id; fixture.save()
    try:
        fixture.inspect('container', helper_id)
        output = fixture.command(['docker', 'start', '-a', helper_id], timeout=15)
        state = fixture.inspect('container', helper_id)['State']
        if state['Running'] or state['ExitCode'] != 0:
            raise Inconclusive('netfilter helper did not finish successfully')
        return output.stdout
    finally:
        fixture.inspect('container', helper_id)
        fixture.command(['docker', 'rm', '-f', helper_id])
        del fixture.registry['containers'][name]; fixture.save()


def log_channel_lag(fixture, engine):
    baseline = critical_path_smoke(fixture)
    money = json.loads((fixture.root / 'money-sample.json').read_text())
    before = {engine + str(i): probe(fixture, engine + str(i)) for i in range(3)}
    leaders = [n for n, p in before.items() if counter(p, 201) == 2]
    followers = [n for n, p in before.items() if counter(p, 201) == 0]
    if len(leaders) != 1 or len(followers) != 2:
        raise Inconclusive('selective log fault requires healthy three-member quorum')
    leader, target = leaders[0], followers[-1]
    path = fixture.root / ('log-channel-' + engine + '.json')
    evidence = {'target': target, 'leader': leader, 'before': before, 'samples': [],
                'baseline_money': baseline['money'], 'filter_removed': False}
    def save(): path.write_text(json.dumps(evidence, indent=2) + '\n')
    save()
    # The exact rule is removed even when subsequent verification raises.
    try:
        evidence['filter_add'] = log_filter(fixture, target, 'add'); save()
        reply = request(fixture, 'POST', '/api/v1/orders', {'marketId': 1, 'side': 'BUY',
            'orderType': 'LIMIT', 'price': '100000.00000000', 'quantity': '0.01000000',
            'clientOrderId': fixture.run_id + '-log-lag'}, 71001)
        if reply.get('accepted') is not True: raise Inconclusive('quorum rejected fault workload')
        accepted = money['accepted_order_ids'] + [order_id(reply['omsOrderId'])]
        _, counts = stable_sample(fixture, money['initial_balances'], money['funding'], accepted, 13)
        evidence['money'] = counts; save()
        time.sleep(2)  # Exceeds the declared 1 s application-checkpoint age bound.
        for _ in range(5):
            low, high = probe(fixture, target), probe(fixture, leader)
            ready = local_ready(fixture, target)
            evidence['samples'].append({'target': low, 'leader': high, 'ready': ready,
                'target_commit': counter(low, 203), 'leader_commit': counter(high, 203),
                'at_ns': time.time_ns()}); save()
            time.sleep(1)
        evidence['filter_counters'] = log_filter(fixture, target, 'counters'); save()
        drops = [line.split() for line in evidence['filter_counters'].splitlines() if 'DROP' in line]
        if len(drops) != 1 or int(drops[0][0]) <= 0:
            raise Inconclusive('selective log packet loss was not observed')
        qualified = [s for s in evidence['samples'] if s['target_commit'] < s['leader_commit']
            and counter(s['target'], 201) == 0 and counter(s['target'], 207) == 17
            and counter(s['leader'], 201) == 2 and counter(s['leader'], 207) == 17
            and counter(s['target'], 239) == counter(s['leader'], 239)
            and 0 <= int(fields(s['ready'])['consensusAgeMs']) < 5000]
        if len(qualified) < 3:
            raise Inconclusive('log lag with live consensus/closed election was not sustained')
        if any(s['ready']['status'] == 200 for s in qualified):
            evidence.update(status='FAIL', known_product_red=True,
                reason='follower is ready despite sustained log lag with live consensus in the current term')
            save(); raise Violation(evidence['reason'])
        if any(s['ready']['status'] != 503 for s in qualified):
            raise Inconclusive('readiness was unreachable rather than explicitly unready')
        evidence['status'] = 'PASS'; save()
        return {'status': 'PASS', 'assertions': len(qualified), 'processed': counts['trades'],
                'skipped': 0, 'child_exit_codes': [0], 'money': counts,
                'scope': 'selective log UDP loss with current-term closed election and committed financial work'}
    finally:
        evidence['filter_delete'] = log_filter(fixture, target, 'delete')
        evidence['filter_removed'] = True; save()
