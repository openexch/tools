# SPDX-License-Identifier: Apache-2.0
"""The gateway and stream drills: scenario ids, their controls and their dry runs.

The five scenario ids are registered here and dispatched by runner.py on a core manifest that declares the gateway
roles: the drills themselves (gateway_scenarios.py) on a kind with the product binaries, a dry run on a dry-run kind.

Dry runs exercise a drill's story, oracle and bounds before the binary it tests runs in the fixture:

* ``stream-slow-consumer`` with ``slot_artifacts.st0 = session_stub``: ct_session_stub registers the stream's channel mask
  and pauses its poll while doWork() and the keepalives keep running; under the a01 story the core's per-session egress
  queue reaches the ceiling (``core.egress.max.capacity.bytes``, lowered by the kind) and the core closes the session.
  The run proves the close happens inside the bound, names every core counter that moved, checks that the commit
  position kept advancing, lifts the throttle and waits for the re-registration, then freezes the stub's container (no
  keepalives; an embedded driver freezes too) and records how the core closes a frozen session (the freeze bound).
* ``gateway-kill-restart`` with ``slot_artifacts.gw0 = gateway_stub``: the test-only HTTP shim (gateway_shim.py) in gw0
  and gw1; the gateway probe sends keyed orders across both, gw0 is SIGKILLed mid-flight and restarted, every key is
  retried with its key, a share of keys is resent after its answer, and the order oracle per key judges the core's open
  orders. The run records the story size, the oracle's heap, the keys provisioned and the kill window.

A control kind runs the same dry run with one rule switched off; the control passes only when its line fails with the
exact text of the contract (``CONTROL_TEXT``), which shows the drill can fail.

Every size, rate and bound is a setting (``SETTINGS``, overridden by an environment variable of the same name), recorded
with the run.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import time
import tracemalloc

from contracts import FP, Inconclusive, Violation
import core_contracts
import gateway_probe

SCENARIOS = ('gateway-kill-restart', 'stream-slow-consumer', 'gateway-session-timeout', 'fill-visibility-core',
             'tick-live-path')
# The control text of each drill (the contract's table): a control run passes only when its line fails with this text
CONTROL_TEXT = {
    'gateway-kill-restart': gateway_probe.SECOND_ORDER,
    'stream-slow-consumer': 'slow session not closed within bound',
    'gateway-session-timeout': 'frozen session not closed within bound',
    'fill-visibility-core': 'fill never visible',
    'tick-live-path': 'market order not completed',
}
SETTINGS = {
    # gateway dry run
    'GATEWAY_DRY_USERS': 4, 'GATEWAY_DRY_REQUESTS': 60, 'GATEWAY_DRY_CONCURRENCY': 4, 'GATEWAY_DRY_RESEND_EVERY': 4,
    'GATEWAY_DRY_KILL_AFTER_ATTEMPTS': 12, 'GATEWAY_DRY_DOWN_S': 5, 'GATEWAY_READY_BOUND_S': 120,
    'GATEWAY_LOAD_BOUND_S': 900, 'GATEWAY_RETRY_BOUND_S': 180,
    # stream dry run
    'SLOW_STORY_S': 120, 'SLOW_STORY_RATE': 80, 'SLOW_CLOSE_BOUND_S': 150, 'SLOW_REREGISTER_BOUND_S': 60,
    'FREEZE_S': 20, 'FREEZE_CLOSE_BOUND_S': 60, 'SAMPLE_S': 1,
    # gateway-kill-restart (gateway_scenarios.KillRestart): load with keys, the gw0 kill, the leader kill with cancels in
    # flight, the gate closed while stored keys are sent again
    'GW_USERS': 8, 'GW_REQUESTS': 720, 'GW_RATE': 8, 'GW_CONCURRENCY': 8, 'GW_RESEND_EVERY': 4, 'GW_KILL_AFTER_ATTEMPTS': 80,
    'GW_BURST_REQUESTS': 160, 'GW_BURST_KILL_AFTER': 40,
    'GW_DOWN_S': 5, 'GW_READY_BOUND_S': 60, 'GW_LOAD_BOUND_S': 900, 'GW_RETRY_BOUND_S': 180, 'GW_ATTEMPT_S': 30,
    'GW_TAP_S': 1800, 'GW_STREAM_USERS': 4, 'GW_P99_BOUND_MS': 1000, 'GW1_WINDOW_SLACK_S': 2, 'GW1_MIN_REQUESTS': 10,
    'GW_GATE_RESEND': 24, 'GW_GATE_FRESH': 4, 'GW_GATE_HOLD_S': 3, 'GW_GATE_SETTLE_BOUND_S': 60, 'CANCEL_USERS': 2, 'CANCEL_PER_USER': 6,
    'CANCEL_WINDOW_S': 3, 'CANCEL_KILL_AT_S': 1, 'REOFFER_CREATES_PER_USER': 6, 'ELECTION_BOUND_S': 60, 'CONVERGE_BOUND_S': 60,
    # stream-slow-consumer (SlowConsumer): st0's inbound core egress thinned on the network
    'SLOW_STREAM_USERS': 4, 'SLOW_THROTTLE_AFTER_S': 10, 'SLOW_DROP_PERCENT': 99,
    # resting orders per stream user that nothing in the story crosses, and how long st0 may take to show the close
    'SLOW_REST_PER_USER': 2, 'SLOW_ST0_CLOSE_SEEN_BOUND_S': 30,
    # gateway-session-timeout (SessionTimeout)
    'TIMEOUT_REQUESTS': 400, 'TIMEOUT_RATE': 4, 'TIMEOUT_FREEZE_AFTER_S': 15, 'TIMEOUT_FREEZE_S': 20,
    # fill-visibility-core (FillVisibility) and the fuzz that follows it
    'FILL_PAIRS': 200, 'FILL_VISIBLE_BOUND_S': 10, 'FILL_POLL_MS': 20, 'FILL_TAP_S': 1800, 'FUZZ_CASES': 300,
    # tick-live-path (TickLivePath)
    'TICK_TAP_S': 900, 'TICK_REFERENCE_BOUND_S': 60, 'TICK_COMPLETE_BOUND_S': 30, 'TICK_REQUEST_BOUND_S': 10,
}
GATEWAY_DRY_PRICE = 50 * FP          # inside the ME band of market 1; a BUY with no seller rests
GATEWAY_DRY_QTY_UNIT = FP // 1000
GATEWAY_DRY_FUNDING = 10_000 * FP    # USD per user (asset 0); the largest hold is price x the largest quantity
GATEWAY_DRY_USER_BASE = 81001
SLOW_COUNTER = 'core_resumable_sessions_closed_total'


def settings(environ=os.environ):
    """The settings in force: the defaults, each overridden by an environment variable of its name (a positive integer)."""
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
            continue
        if not value.isdigit() or int(value) < 1:
            raise Violation(f'{name} must be a positive integer, got {value!r}')
        out[name] = int(value)
    return out


def is_scenario(name):
    return name in SCENARIOS


def dry_run_of(manifest, name):
    """The dry run a manifest asks for with ``name``: 'stream' (st0 = session_stub), 'gateway' (gw0 = gateway_stub), or
    None (the real drill)."""
    slots = manifest.get('slot_artifacts') or {}
    if name == 'stream-slow-consumer' and slots.get('st0') == 'session_stub':
        return 'stream'
    if name == 'gateway-kill-restart' and slots.get('gw0') == 'gateway_stub':
        return 'gateway'
    return None


def control_of(manifest, dry):
    """The control a manifest declares (the dry run with one rule off), or None: the shim minting a fresh request id per
    attempt, or the slow-consumer kind whose ceiling is left at the core's default."""
    if dry == 'gateway':
        return 'gateway-kill-restart' if (manifest['artifacts'].get('gateway_stub') or {}).get('mode') == 'fresh-key' else None
    if dry == 'stream':
        lowered = (manifest.get('core_jvm_properties') or {}).get('core.egress.max.capacity.bytes')
        return None if lowered else 'stream-slow-consumer'
    return None


def check_scenario(manifest, name):
    """Before any container starts: an unknown id is refused, a gateway scenario needs a manifest that declares the
    gateway roles, a dry-run kind runs only its own drill's dry run, the drill needs the product binary in the slots it
    drives, and a control kind runs only the drill it controls. Returns the dry run ('stream', 'gateway') or None."""
    if not is_scenario(name):
        raise Inconclusive('unknown gateway scenario: ' + name)
    if not core_contracts.gateway_manifest(manifest):
        raise Inconclusive(f'{name} needs a manifest that declares the gateway roles (a gateway kind)')
    dry = dry_run_of(manifest, name)
    if dry is not None:
        return dry
    slots = manifest.get('slot_artifacts') or {}
    gateways = [slots.get('gw0'), slots.get('gw1')]
    if any(g not in ('gateway', 'gateway_nc') for g in gateways) or gateways.count('gateway_nc') > 1 \
            or slots.get('st0') != 'stream' or slots.get('st1') != 'stream':
        raise Inconclusive(f'{name} runs on oe-gateway in gw0 and gw1 and oe-stream in st0 and st1; this kind stages '
                           + ', '.join(f'{k}={v}' for k, v in sorted(slots.items()) if k in core_contracts.GATEWAY_SLOTS))
    import gateway_scenarios
    gateway_scenarios.control_of(manifest, name)          # a control kind of another drill is refused here
    return None


def scenario(fixture, name, out_dir):
    """runner.py entry for the gateway scenario ids."""
    dry = check_scenario(fixture.m, name)
    if dry is None:
        import gateway_scenarios
        return gateway_scenarios.run(fixture, name, Path(out_dir) / 'drill')
    run = (StreamDryRun if dry == 'stream' else GatewayDryRun)(fixture, name, Path(out_dir) / 'dry-run')
    result = run.run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} dry run ({dry}) on the gateway fixture; the drill itself is the next slice')


def line(holds, detail, text=None, inconclusive=False):
    out = {'holds': bool(holds) and not inconclusive, 'detail': detail}
    if not out['holds'] and text:
        out['text'] = text
    if inconclusive:
        out['inconclusive'] = True
    return out


def verdict(lines, control):
    """PASS when every line holds; a control run passes when its line fails with exactly the control text (the other
    lines are recorded). A line whose witness is missing makes the run INCONCLUSIVE, never PASS."""
    if control is not None:
        want = CONTROL_TEXT[control]
        failed = [k for k, v in lines.items() if not v['holds'] and v.get('text') == want]
        return ('PASS' if failed else 'FAIL'), {'control': control, 'expected_text': want, 'failed_lines': failed,
                                                'observed': {k: v.get('text') for k, v in lines.items() if not v['holds']}}
    if any(v.get('inconclusive') for v in lines.values()):
        return 'INCONCLUSIVE', None
    return ('PASS' if all(v['holds'] for v in lines.values()) else 'FAIL'), None


class DryRun:
    sleep = staticmethod(time.sleep)
    clock = staticmethod(time.monotonic)

    def __init__(self, fixture, name, out_dir):
        self.f, self.name, self.out = fixture, name, Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.s = settings()
        self.dry = dry_run_of(fixture.m, name)
        self.control = control_of(fixture.m, self.dry)
        self.record = {'scenario': name, 'dry_run': self.dry, 'control': self.control, 'settings': self.s,
                       'manifest_kind': fixture.m.get('manifest_kind'), 'driver': self.driver()}

    def driver(self):
        slot = 'st0' if self.dry == 'stream' else 'gw0'
        return (self.f.m['artifacts'].get(self.f.m['slot_artifacts'].get(slot)) or {}).get('driver')

    def metrics_all(self, roles):
        out = {}
        for role in roles:
            try:
                out[role] = self.f.metrics(role, self.f.m['ports']['ae_metrics'])
            except Inconclusive as error:
                out[role] = {'error': str(error)}
        return out

    def finish(self, lines):
        status, control = verdict(lines, self.control)
        result = {'status': status, 'lines': lines, 'record': self.record}
        if control:
            result['control'] = control
        failing = [v.get('text') or k for k, v in lines.items() if not v['holds']]
        if status != 'PASS' or control:
            result['error'] = '; '.join(failing) if failing else None
        (self.out / 'dry-run.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        return result


# ------------------------------------------------------------------ the stream dry run

def counters_moved(before, after, words=('session', 'egress', 'close', 'client')):
    """{role: {metric: delta}} of the core counters whose name holds one of ``words`` and whose value changed."""
    moved = {}
    for role, values in after.items():
        old = before.get(role) or {}
        if 'error' in values or 'error' in old:
            continue
        for key, value in values.items():
            if any(w in key for w in words) and key in old and value != old[key]:
                moved.setdefault(role, {})[key] = value - old[key]
    return moved


def total(snapshot, metric):
    """The sum of ``metric`` over the members that answered (a counter of the leader's apply; followers report 0 or the
    same value, so the maximum is taken), or None."""
    values = [v.get(metric) for v in snapshot.values() if isinstance(v, dict) and v.get(metric) is not None]
    return max(values) if values else None


# The slow-consumer story's users: a01-mix plans up to about 1.2 x rate x seconds / users requests per user and the core
# keeps at most 256 per user (RequestTable.DEFAULT_PER_USER_CAP), so the story spreads over 80 users
SLOW_USERS = list(range(75001, 75081))
GATEWAY_SESSIONS = 'core_sessions{class="GATEWAY"}'


class StreamDryRun(DryRun):
    def plan(self):
        tap_s = 60 + self.s['SLOW_STORY_S'] + self.s['SLOW_CLOSE_BOUND_S'] + self.s['FREEZE_S'] + 300
        return {'users': SLOW_USERS, 'markets': [1, 2, 3, 4, 5], 'funding_for': 'a01-mix', 'seed': self.f.m['seed'] & 0xFFFFFFFF,
                'risk': {'per_sec': 1000, 'max_open': 5000, 'slippage_bps': 100, 'collar_bps': 5000}, 'tap_ms': tap_s * 1000}

    def sample(self):
        snap = self.metrics_all(['ae0', 'ae1', 'ae2'])
        leader = next((r for r, v in snap.items() if isinstance(v, dict) and v.get('core_cluster_role') == 2.0), None)
        return {'at_ns': time.time_ns(), 'leader': leader, 'closed': total(snap, SLOW_COUNTER),
                'commit': (snap.get(leader) or {}).get('core_log_position') if leader else None,
                'gateway_sessions': (snap.get(leader) or {}).get(GATEWAY_SESSIONS) if leader else None}, snap

    def run(self):
        """Throttle phase (the ceiling close), the throttle lifted (re-registration), the story's end, then the freeze."""
        f, s = self.f, self.s
        f.start(self.plan())
        self.record['stub'] = f.slots.get('st0')
        first, before = self.sample()
        (self.out / 'metrics-before.json').write_text(json.dumps(before, indent=1) + '\n')
        stub_start = f.inspect('container', f.registry['containers']['st0'])['State']['StartedAt']
        f.stub_command('st0', 'throttle pause')
        throttled_ns = time.time_ns()
        story = f.start_story({'script': 'a01-mix', 'seed': f.m['seed'] & 0xFFFFFFFF, 'seconds': s['SLOW_STORY_S'],
                               'rate': s['SLOW_STORY_RATE'], 'users': ','.join(map(str, SLOW_USERS))}, name='story')
        samples = [first]
        closed_at = None
        deadline = self.clock() + s['SLOW_CLOSE_BOUND_S']
        while self.clock() < deadline:
            self.sleep(s['SAMPLE_S'])
            row, _ = self.sample()
            samples.append(row)
            if first['closed'] is not None and row['closed'] is not None and row['closed'] > first['closed']:
                closed_at = row['at_ns']
                break
        _, at_close = self.sample()
        (self.out / 'metrics-at-close.json').write_text(json.dumps(at_close, indent=1) + '\n')
        self.record['throttle'] = {'started_ns': throttled_ns, 'closed_ns': closed_at,
                                   'close_s': None if closed_at is None else round((closed_at - throttled_ns) / 1e9, 3),
                                   'bound_s': s['SLOW_CLOSE_BOUND_S'],
                                   'ceiling_bytes': (f.m.get('core_jvm_properties') or {}).get('core.egress.max.capacity.bytes',
                                                                                              'core default (16 MiB)'),
                                   'counters_moved': counters_moved(before, at_close)}
        lines = {}
        delta = None if first['closed'] is None or samples[-1]['closed'] is None else samples[-1]['closed'] - first['closed']
        lines['slow_session_closed'] = line(closed_at is not None and delta == 1,
                                            {'counter': SLOW_COUNTER, 'delta': delta, 'close_s': self.record['throttle']['close_s']},
                                            CONTROL_TEXT['stream-slow-consumer'])
        commits = [r['commit'] for r in samples if r['commit'] is not None]
        lines['commit_advances'] = line(len(commits) >= 2 and commits[-1] > commits[0],
                                        {'samples': len(commits), 'first': commits[0] if commits else None,
                                         'last': commits[-1] if commits else None,
                                         'flat_intervals': sum(1 for a, b in zip(commits, commits[1:]) if b <= a)},
                                        'core commit position stalled')
        # Lift the throttle: a stub whose session the core closed (reconnect on) opens a new one and registers again
        f.stub_command('st0', 'throttle off')
        if closed_at is not None:
            again = self.wait_stub(lambda e: e['event'] == 'registration' and e.get('state') == 'REGISTERED',
                                   s['SLOW_REREGISTER_BOUND_S'], since_ns=closed_at - 2_000_000_000, start=stub_start,
                                   after_close=True)
            lines['stub_reregistered'] = line(again is not None, {'event': again}, 'throttled stub did not register again')
        story_exit = self.wait_file(story['exit'], s['SLOW_STORY_S'] + 180)
        self.record['story'] = {'exit': story_exit, 'out_tail': _tail(story['out']), 'err_tail': _tail(story['err'])}
        lines['story_ran'] = line(story_exit == 0, {'exit': story_exit}, 'story did not finish', inconclusive=story_exit != 0)
        # The freeze, after the story: no poll and no keepalive, the embedded driver frozen with the process
        freeze = self.freeze()
        self.record['freeze'] = freeze
        lines['freeze_closed_by_timeout'] = line(freeze['session_dropped_while_frozen'] and freeze['ceiling_delta'] == 0,
                                                 {k: freeze[k] for k in ('session_dropped_while_frozen', 'ceiling_delta',
                                                                         'after_thaw')},
                                                 CONTROL_TEXT['gateway-session-timeout'])
        _, after = self.sample()
        (self.out / 'metrics-after.json').write_text(json.dumps(after, indent=1) + '\n')
        self.record['counters_moved'] = counters_moved(before, after)
        events = f.stub_events('st0')
        (self.out / 'stub-events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events))
        self.record['stub'] = dict(self.record['stub'] or {}, events=len(events),
                                   closes=[e for e in events if e['event'] == 'state' and 'close_reason' in e][:10])
        self.record['samples'] = samples
        return self.finish(lines)

    def freeze(self):
        """docker pause st0 for FREEZE_S (keepalives stop; an embedded driver freezes too), then thaw. The core closes a
        session that sends nothing by its session timeout: the leader's GATEWAY session gauge drops by one while frozen
        and the ceiling counter does not move. After the thaw the stub either reconnects or exits 70 on its own driver
        timeout guard (a freeze longer than the client's driver timeout); an exit is restarted and must register again."""
        f, s = self.f, self.s
        before_row, before = self.sample()
        f.pause('st0', duration_s=s['FREEZE_S'])
        paused_ns = time.time_ns()
        self.sleep(s['FREEZE_S'])
        during_row, during = self.sample()
        f.unpause('st0')
        thawed_ns = time.time_ns()
        cid = f.registry['containers']['st0']
        deadline = self.clock() + s['FREEZE_CLOSE_BOUND_S']
        outcome = None
        while self.clock() < deadline and outcome is None:
            state = f.inspect('container', cid)['State']
            if not state['Running']:
                outcome = {'exit_code': state['ExitCode']}
                break
            again = [e for e in f.stub_events('st0') if e['event'] == 'registration' and e.get('state') == 'REGISTERED'
                     and _ts_ns(e.get('ts')) >= thawed_ns]
            if again:
                outcome = {'reregistered': again[0]}
            self.sleep(1)
        if outcome and 'exit_code' in outcome:
            f.record_fault({'kind': 'exit', 'target': 'st0', 'exit_code': outcome['exit_code']})
            witness = f.restart('st0', ready_timeout=s['FREEZE_CLOSE_BOUND_S'])
            outcome['restarted'] = {k: witness.get(k) for k in ('started_at', 'ready')}
        else:
            f.close_fault('st0')
        after_row, after = self.sample()
        tail = [l for l in f.command(['docker', 'logs', '--since', '60s', cid], check=False).stderr.splitlines()
                if 'ct_session_stub:' in l][-3:]
        dropped = (before_row['gateway_sessions'] is not None and during_row['gateway_sessions'] is not None
                   and during_row['gateway_sessions'] == before_row['gateway_sessions'] - 1)
        return {'paused_s': s['FREEZE_S'], 'paused_ns': paused_ns, 'thawed_ns': thawed_ns,
                'gateway_sessions': [before_row['gateway_sessions'], during_row['gateway_sessions'], after_row['gateway_sessions']],
                'session_dropped_while_frozen': dropped,
                'ceiling_delta': (total(after, SLOW_COUNTER) or 0) - (total(before, SLOW_COUNTER) or 0),
                'after_thaw': outcome, 'stub_stderr': tail,
                'counters_moved_while_frozen': counters_moved(before, during), 'counters_moved': counters_moved(before, after)}

    def wait_stub(self, predicate, bound_s, since_ns, start, after_close=False):
        """The first stub event after ``since_ns`` that ``predicate`` accepts (``after_close``: and after the first
        session close in that span), or None at the bound."""
        deadline = self.clock() + bound_s
        while True:
            closed = not after_close
            for e in self.f.stub_events('st0', since=start):
                if _ts_ns(e.get('ts')) < since_ns:
                    continue
                if e['event'] == 'state' and e.get('to') == 'CLOSED':
                    closed = True
                if closed and predicate(e):
                    return e
            if self.clock() >= deadline:
                return None
            self.sleep(1)

    def wait_file(self, path, bound_s):
        deadline = self.clock() + bound_s
        while self.clock() < deadline:
            if Path(path).exists():
                text = Path(path).read_text().strip()
                return int(text) if text.lstrip('-').isdigit() else text
            self.sleep(1)
        return None


def _ts_ns(stamp):
    """A docker log timestamp (RFC 3339, nanoseconds, Z) as epoch ns; 0 when absent."""
    if not stamp:
        return 0
    import datetime
    head, _, frac = stamp.rstrip('Z').partition('.')
    base = datetime.datetime.strptime(head, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    return int(base.timestamp()) * 1_000_000_000 + int((frac + '0' * 9)[:9])


def _tail(path, n=5):
    p = Path(path)
    return p.read_text().splitlines()[-n:] if p.exists() else []


# ------------------------------------------------------------------ the gateway dry run

class GatewayDryRun(DryRun):
    def users(self):
        return list(range(GATEWAY_DRY_USER_BASE, GATEWAY_DRY_USER_BASE + self.s['GATEWAY_DRY_USERS']))

    def plan(self):
        users = self.users()
        return {'users': users, 'markets': [1],
                'funding': [{'user': u, 'asset': 0, 'amount': GATEWAY_DRY_FUNDING} for u in users],
                'risk': {'per_sec': 1000, 'max_open': 5000, 'slippage_bps': 100, 'collar_bps': 5000},
                'tap_ms': (600 + self.s['GATEWAY_LOAD_BOUND_S']) * 1000}

    def targets(self):
        nodes, port = self.f.m['nodes'], self.f.m['ports']['shim_http']
        return [f'{nodes[s]}:{port}' for s in ('gw0', 'gw1') if self.f.slot_artifact(s)]

    def run(self):
        f, s = self.f, self.s
        users = self.users()
        f.gateway_user_ids = users
        f.start(self.plan())
        self.record['slots'] = {k: f.slots.get(k) for k in ('gw0', 'gw1')}
        probe = f.root / 'state' / 'probe'
        shutil.copyfile(Path(__file__).with_name('gateway_probe.py'), probe / 'gateway_probe.py')
        rows = gateway_probe.story(s['GATEWAY_DRY_REQUESTS'], users, f.m['seed'], GATEWAY_DRY_QTY_UNIT, GATEWAY_DRY_PRICE,
                                   resend_every=s['GATEWAY_DRY_RESEND_EVERY'])
        (probe / 'gw-story.json').write_text(json.dumps(rows))
        (probe / 'gw-keys.json').write_text(json.dumps({str(u): k for u, k in f.keys.api_keys(users).items()}))
        f.secret_values = f.keys.secrets()
        lines = {'key_provisioning': self.key_provisioning(users)}
        attempts_path = probe / 'gw-attempts.jsonl'
        done = probe / 'gw-load.done'
        argv = ['python3', '-I', '/data/gateway_probe.py', 'load', '--targets', ','.join(self.targets()),
                '--keys', '/data/gw-keys.json', '--story', '/data/gw-story.json', '--out', '/data/gw-attempts.jsonl',
                '--done-file', '/data/gw-load.done', '--concurrency', str(s['GATEWAY_DRY_CONCURRENCY']),
                '--retry-bound-s', str(s['GATEWAY_RETRY_BOUND_S'])]
        cid = f.registry['containers']['probe']; f.inspect('container', cid)
        load_started = self.clock()
        f.command(['docker', 'exec', '-d', cid, 'sh', '-c', shlex.join(argv) + ' > /data/gw-load.out 2>&1'])
        kill = self.kill_window(attempts_path, done)
        deadline = load_started + s['GATEWAY_LOAD_BOUND_S']
        while not done.exists() and self.clock() < deadline:
            self.sleep(1)
        attempts = _jsonl(attempts_path)
        load = {'requests': len(rows), 'attempts': len(attempts), 'done': done.exists(),
                'elapsed_s': round(self.clock() - load_started, 1), 'concurrency': s['GATEWAY_DRY_CONCURRENCY']}
        load['attempts_per_s'] = round(len(attempts) / load['elapsed_s'], 3) if load['elapsed_s'] else None
        self.record['load'] = load
        self.record['kill_window'] = kill_window_report(kill, attempts)
        meaning, dump = f.core('order-dump', 'probe-admin', timeout=180)
        orders = (dump or {}).get('orders') or []
        tracemalloc.start()
        result = gateway_probe.key_oracle(rows, attempts, orders)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.record['oracle'] = dict(result, heap_peak_bytes=peak, heap_per_attempt_bytes=round(peak / max(1, len(attempts)), 1),
                                     order_dump=meaning, live_orders=len(orders))
        (self.out / 'attempts.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in attempts))
        (self.out / 'story.json').write_text(json.dumps(rows) + '\n')
        failures = result['failures']
        lines['key_oracle'] = line(result['verdict'] == 'PASS', {k: result[k] for k in ('verdict', 'keys', 'answered', 'failures')},
                                   failures[0] if failures else 'keys unanswered',
                                   inconclusive=result['verdict'] == 'INCONCLUSIVE' and self.control is None)
        lines['resends_answered_stored'] = line(result['resends'] > 0 and not result['split_keys'],
                                                {'resends': result['resends'], 'split_keys': result['split_keys']},
                                                'a resent key answered another decision')
        lines['load_finished'] = line(load['done'], load, 'load did not finish inside its bound', inconclusive=not load['done'])
        lines['gw0_ready_after_restart'] = line(kill.get('ready_s') is not None and kill['ready_s'] <= s['GATEWAY_READY_BOUND_S'],
                                                {k: kill.get(k) for k in ('ready_s', 'killed_at_attempts')},
                                                'gw0 not ready inside its bound after the restart')
        return self.finish(lines)

    def key_provisioning(self, users):
        """Both gateway slots hold one key per drill user (their /health), and an unknown key is refused 401."""
        f = self.f
        counts = {}
        for slot in ('gw0', 'gw1'):
            if f.slot_artifact(slot):
                body = f.http(slot, f.m['ports']['shim_http'], '/health').get('body') or '{}'
                counts[slot] = json.loads(body).get('users')
        code = ('import json,sys; sys.path.insert(0, "/data"); import gateway_probe as g; '
                f'print(json.dumps(g.post("{self.targets()[0]}", "/api/v2/orders", {{"X-API-Key": "0" * 64, '
                '"Idempotency-Key": "00000000-0000-4000-8000-000000000001"}, {}, 30)))')
        out = f.execute('probe', ['python3', '-I', '-c', code], timeout=60, check=False)
        try:
            refused = json.loads(out.stdout.strip().splitlines()[-1])[0]
        except (ValueError, IndexError):
            refused = None
        record = {'users': len(users), 'keys_loaded': counts, 'unknown_key_status': refused,
                  'credentials': f.keys.evidence().get('api_key_users')}
        self.record['key_provisioning'] = record
        return line(all(v == len(users) for v in counts.values()) and counts and refused == 401, record,
                    'gateway keys not provisioned')

    def kill_window(self, attempts_path, done):
        """SIGKILL gw0 once the load has sent ``GATEWAY_DRY_KILL_AFTER_ATTEMPTS`` attempts, hold it down, restart it and
        time its /ready. The attempts in flight on gw0 at the kill are read from the attempt log afterwards."""
        f, s = self.f, self.s
        deadline = self.clock() + s['GATEWAY_LOAD_BOUND_S']
        while self.clock() < deadline and not done.exists():
            if len(_jsonl(attempts_path)) >= s['GATEWAY_DRY_KILL_AFTER_ATTEMPTS']:
                break
            self.sleep(0.5)
        if done.exists():
            return {'killed': False, 'reason': 'the load finished before the kill point'}
        n = len(_jsonl(attempts_path))
        killed_ns = time.time_ns()
        f.kill('gw0')
        self.sleep(s['GATEWAY_DRY_DOWN_S'])
        start = self.clock()
        f.restart('gw0', ready_timeout=s['GATEWAY_READY_BOUND_S'])
        return {'killed': True, 'target': self.targets()[0], 'killed_ns': killed_ns, 'killed_at_attempts': n,
                'down_s': s['GATEWAY_DRY_DOWN_S'], 'ready_s': round(self.clock() - start, 3)}


def kill_window_report(kill, attempts):
    """The attempts gw0's kill cut (sent to gw0 before the kill, no HTTP answer) and how their keys ended."""
    if not kill.get('killed'):
        return kill
    cut = [a for a in attempts if a['target'] == kill['target'] and a['status'] == 0
           and a['sent_ns'] <= kill['killed_ns'] <= a['recv_ns']]
    keys = {a['key'] for a in cut}
    final = {}
    for a in attempts:
        if a['key'] in keys and gateway_probe.settled(a['status']):
            final[a['key']] = a['status']
    return dict(kill, in_flight_at_kill=len(cut), in_flight_keys_answered=len(final),
                in_flight_answers=sorted(set(final.values())))


def _jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for text in p.read_text().splitlines():
        try:
            rows.append(json.loads(text))
        except ValueError:
            continue        # a line the writer is still writing
    return rows
