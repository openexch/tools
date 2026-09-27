# SPDX-License-Identifier: Apache-2.0
"""Drop only an owned follower's log UDP port, leaving consensus/HTTP intact."""
import hashlib
import json
from pathlib import Path
import time

from contracts import Inconclusive, Violation
from fixture import LABEL
from faults import counter, local_ready, probe
from readiness import fields, observations, authorize_next_restart
from observe import stable_sample
from scenarios import critical_path_smoke, request, order_id


def qualified_lag_samples(samples):
    """Independent leader witnesses must exceed the predeclared byte/age bounds.

    Catch-up replay uses a different port and can legitimately advance the node
    while live log packets are dropped. Any instantaneous byte difference is
    therefore insufficient evidence of an unready node under the bounded policy.
    """
    qualified = []
    for index, sample in enumerate(samples):
        low, high = sample['target'], sample['leader']
        if (counter(low, 201) != 0 or counter(low, 207) != 17
                or counter(high, 201) != 2 or counter(high, 207) != 17
                or counter(low, 239) != counter(high, 239)):
            continue
        body = fields(sample['ready'])
        if not 0 <= int(body['consensusAgeMs']) < 5000: continue
        # Observations are sequential. Credit the furthest proven progress so a
        # replica that catches up between CNC and HTTP reads is not falsely RED.
        applied = max(sample['target_commit'], body['applied'])
        if sample['leader_commit'] <= applied: continue
        now = sample.get('observed_ns', sample['at_ns'])
        old_bound = any(
            1_000_000_000 <= now - old.get('observed_ns', old['at_ns'])
            and old['leader_commit'] > applied
            and counter(old['leader'], 201) == 2 and counter(old['leader'], 207) == 17
            and counter(old['leader'], 239) == counter(high, 239)
            for old in samples[:index])
        if sample['leader_commit'] - applied > 65536 or old_bound:
            qualified.append(sample)
    return qualified


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
        for _ in range(8):
            low, high = probe(fixture, target), probe(fixture, leader)
            ready = local_ready(fixture, target)
            evidence['samples'].append({'target': low, 'leader': high, 'ready': ready,
                'target_commit': counter(low, 203), 'leader_commit': counter(high, 203),
                'at_ns': time.time_ns(), 'observed_ns': time.monotonic_ns()}); save()
            time.sleep(1)
        evidence['filter_counters'] = log_filter(fixture, target, 'counters'); save()
        drops = [line.split() for line in evidence['filter_counters'].splitlines() if 'DROP' in line]
        if len(drops) != 1 or int(drops[0][0]) <= 0:
            raise Inconclusive('selective log packet loss was not observed')
        qualified = qualified_lag_samples(evidence['samples'])
        evidence['qualified_samples'] = len(qualified); save()
        # One independently proven safety violation is already FAIL. The minimum
        # coverage count is a requirement for PASS, never a way to hide a RED.
        if any(s['ready']['status'] == 200 for s in qualified):
            evidence.update(status='FAIL', known_product_red=True,
                reason='follower is ready despite sustained log lag with live consensus in the current term')
            save(); raise Violation(evidence['reason'])
        if len(qualified) < 3:
            raise Inconclusive('log lag with live consensus/closed election was not sustained')
        if any(s['ready']['status'] != 503 for s in qualified):
            raise Inconclusive('readiness was unreachable rather than explicitly unready')
    finally:
        evidence['filter_delete'] = log_filter(fixture, target, 'delete')
        evidence['filter_removed'] = True; save()
    recovery_start = time.monotonic()
    deadline = recovery_start + fixture.m['budgets']['maximum_recovery_seconds']
    evidence['recovery_samples'] = []
    while time.monotonic() < deadline:
        current = observations(fixture, engine)
        evidence['recovery_samples'].append(current); save()
        try: certificate = authorize_next_restart(engine, target, current, time.monotonic_ns())
        except Inconclusive:
            time.sleep(.2); continue
        evidence.update(status='PASS', recovery_certificate=certificate,
                        recovery_seconds=time.monotonic() - recovery_start); save()
        return {'status': 'PASS', 'assertions': len(qualified) + 1, 'processed': counts['trades'],
                'skipped': 0, 'child_exit_codes': [0], 'money': counts,
                'scope': 'selective log UDP loss with live consensus, exact finances and verified rejoin'}
    raise Violation('log-lagged follower did not recover after removing the filter')
