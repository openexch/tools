# SPDX-License-Identifier: Apache-2.0
"""The observation verdict over planted sample sets: a clean set passes; each planted set fails on its own line and names
its own service only; V3 has one set per service kind; the vacuity control of every set (its line switched off) must
turn it into a pass, and the assertion of the set then fails with ``verdict line <Vn> is vacuous``.

The sets are written as sample files in the sampler's format (JSON lines with the running SHA-256 chain), so loading,
the chain check and the verdict are exercised together.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import observation

PERIOD_S = 60
N = 61                       # one hour at one sample a minute
T0 = 1_800_000_000_000
MB = 1 << 20

SERVICES = [  # name, kind
    ('core/ae0', 'core member'), ('core/ae1', 'core member'), ('core/ae2', 'core member'),
    ('match/me0', 'ME member'), ('match/me1', 'ME member'), ('match/me2', 'ME member'),
    ('ct-bridge/b0', 'ct-bridge'), ('ct-forwarder/f0', 'ct-forwarder'), ('money-projector/p0', 'money projector'),
    ('core-replica/r0', 'core-replica'), ('oe-projector/pj0', 'oe-projector'), ('oe-gateway/gw0', 'oe-gateway'),
    ('oe-stream/st0', 'oe-stream'), ('oe-marketdata/md0', 'oe-marketdata'), ('simulator/sim', 'simulator'),
]
DIRS = [
    {'name': 'ae0 order journal', 'path': '/s/ae0/journal', 'model': 'core_order_journal', 'service': 'core/ae0'},
    {'name': 'ae0 log', 'path': '/s/ae0/log', 'model': 'core_log', 'service': 'core/ae0'},
    {'name': 'me0 log', 'path': '/s/me0/log', 'model': 'me_log', 'service': 'match/me0'},
    {'name': 'me0 settlement journal', 'path': '/s/me0/journal', 'model': 'me_settlement_journal', 'service': 'match/me0'},
    {'name': 'replica archive', 'path': '/s/r0', 'model': 'replica_archive', 'follows': 'core/ae0'},
    {'name': 'money history', 'path': '-', 'model': 'money_db', 'db': 'r01_money', 'rows': 'money_rows', 'size': 'money_size'},
    {'name': 'pg wal', 'path': '-', 'model': 'pg_wal'},
    {'name': 'logs', 'path': '/s/logs', 'model': 'log_dir'},
    {'name': 'samples', 'path': '/s/obs', 'model': 'sampler_file'},
]
SETTINGS = {'OBS_WINDOW_S': 3600, 'OBS_SNAPSHOT_AGE_S': 1800}
INPUTS = {'snapshot_mode': 'shadow', 'me_driver_mode': 'external'}
CLEAN_Q = {'mode': 'core', 'status': 'OK', 'checks': [{'name': 'holds_live', 'status': 'PASS', 'drifts': []}],
           'residual_holds': [], 'violated': False, 'indeterminate': False}


def metrics_of(name, kind, i):
    """Clean series of one service at sample i: every counter moves with the load."""
    if kind == 'core member':
        m = {'core_log_position': 1000 * i, 'core_last_applied_trade_id': i, 'core_feed_cursor': i,
             'core_order_journal_seq': 5 * i, 'core_journal_seq': 3 * i, 'core_cluster_role': 2 if name == 'core/ae0' else 0,
             'core_snapshot_age_seconds': (i * PERIOD_S) % 600, 'core_release_backlog': 0, 'core_pending_commands': 0,
             'core_ingress_schema_rejects_total': 0, 'core_order_entry_gate': 1}
    elif kind == 'ME member':
        m = {'match_log_position': 500 * i, 'match_cluster_role': 2 if name == 'match/me0' else 0,
             'match_snapshot_age_seconds': (i * PERIOD_S) % 600, 'match_log_bytes_reclaimed_total': 0 if i < 30 else 4096,
             'match_engine_next_journal_seq': 2 * i, 'match_egress_queue_oms': 0, 'match_egress_queue_oms_bytes': 0,
             'match_dropped_oms_egress_total': 0 if name == 'match/me0' else i}
    elif kind == 'ct-bridge':
        m = {'bridge_core_cursor': 2 * i, 'bridge_forwarded_total': 2 * i, 'bridge_halted': 0}
    elif kind == 'ct-forwarder':
        m = {'forwarder_book_frames_total': 4 * i, 'forwarder_dispatch_sent_total': 10 * i,
             'forwarder_dispatch_received_total': 10 * i}
    elif kind == 'money projector':
        m = {'projector_last_journal_seq': 3 * i, 'projector_rows_projected_total': 3 * i}
    elif kind == 'core-replica':
        m = {'shadow_last_age_ms': 1000, 'shadow_log_purge_position': 4096 * (i // 10)}
    elif kind == 'oe-projector':
        m = {'projector_applied_seq': 5 * i, 'projector_records_applied_total': 5 * i, 'projector_lease_held': 1}
    elif kind == 'oe-gateway':
        m = {'gateway_requests_total{route="orders",code="200"}': 10 * i, 'gateway_history_age_ms': 200}
    elif kind == 'oe-stream':
        m = {'stream_ws_frames_sent_total': 7 * i, 'stream_ws_connections': 1}
    elif kind == 'oe-marketdata':
        m = {'md_ws_frames_sent_total{type="trades"}': 4 * i, 'md_ws_connections': 1, 'md_history_age_ms': 300}
    elif kind == 'simulator':
        m = {'sim_orders_placed_total': 10 * i}
    else:
        m = {'mystery_total': i}
    return m


class SampleSet:
    """A clean one-hour set; a planted set changes it through the hooks before it is written."""

    def __init__(self):
        self.services = list(SERVICES)
        self.metric_hooks = []     # f(name, kind, i, metrics) -> metrics or None (None: the read failed)
        self.svc_hooks = []        # f(name, kind, i, sample) -> sample
        self.rec_hooks = []        # f(i, record) -> record or None (None: the sample was not taken)
        self.quiesce = {'Q0': CLEAN_Q, 'Q2': CLEAN_Q}
        self.actions = []
        self.settings = dict(SETTINGS)

    def service(self, name, kind, i):
        pid = 1000 + self.services.index((name, kind))
        m = metrics_of(name, kind, i)
        for h in self.metric_hooks:
            m = h(name, kind, i, m)
        read = {'code': 200, 'ms': 2, 'series': m} if m is not None else {'code': 0, 'ms': 2000,
                                                                          'error': 'context deadline exceeded'}
        svc = {'kind': kind, 'supervisor': {'state': 'running', 'pid': pid, 'started_at': 'x'},
               'proc': {'alive': True, 'start_ticks': 5000 + pid, 'cpu_ticks': 6 * i, 'threads': 10, 'thread_states': {'S': 10}},
               'metrics': read, 'health': {'code': 200 if m is not None else 0, 'ms': 1},
               'ready': {'code': 200 if m is not None else 0, 'ms': 1}}
        for h in self.svc_hooks:
            svc = h(name, kind, i, svc)
        return svc

    def record(self, i):
        rows = 6 * i
        rec = {'type': 'sample', 'seq': i + 1, 'ts_ms': T0 + i * PERIOD_S * 1000, 'host': 'h1',
               'services': {n: self.service(n, k, i) for n, k in self.services},
               'volumes': {'/': {'total': 100 << 30, 'used': (10 << 30) + i * MB, 'avail': (90 << 30) - i * MB}},
               'dirs': {'ae0 order journal': {'bytes': 4096 + 5 * i * 256},
                        'ae0 log': {'bytes': (1 << 20) + 1000 * i + 6600 * PERIOD_S * i},
                        'me0 log': {'bytes': (1 << 20) + 500 * i - (0 if i < 30 else 4096)},
                        'me0 settlement journal': {'bytes': 4096 + 2 * i * 256},
                        'replica archive': {'bytes': (1 << 20) + 1000 * i + 6600 * PERIOD_S * i},
                        'logs': {'bytes': 1000 * i}, 'samples': {'bytes': 10000 * i}},
               'shm': {'/dev/shm': {'total': 1 << 30, 'used': 100 * MB, 'avail': 900 * MB, 'entries': {'aeron-core-0': 50 * MB}}},
               'pg': {'sizes': {'r01_money': 8_000_000 + rows * 200}, 'wal_bytes': 16 * MB + i * 1000,
                      'values': {'money_rows': str(rows), 'money_size': str(rows * 200 if rows else 0)}},
               'self': {'file_bytes': 10000 * i, 'lines': i + 1}}
        for h in self.rec_hooks:
            rec = h(i, rec)
            if rec is None:
                return None
        return rec

    def write(self, d):
        d = Path(d)
        start = {'type': 'start', 'ts_ms': T0 - 1000, 'host': 'h1', 'version': 'test', 'clk_tck': 100,
                 'settings': {'OBS_SAMPLE_S': PERIOD_S},
                 'config': {'host': 'h1', 'dirs': DIRS, 'volumes': ['/'], 'services': []}}
        prev, lines = '0' * 64, []
        for rec in [start] + [r for r in (self.record(i) for i in range(N)) if r is not None]:
            rec = dict(rec, prev=prev)
            body = json.dumps(rec, sort_keys=True, separators=(',', ':')).encode()
            prev = hashlib.sha256(body).hexdigest()
            lines.append(body[:-1] + b',"hash":"' + prev.encode() + b'"}')
        (d / 'samples-h1.jsonl').write_bytes(b'\n'.join(lines) + b'\n')
        (d / 'actions.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in self.actions))
        for k, v in self.quiesce.items():
            (d / f'{k}.json').write_text(json.dumps(v))
        (d / 'sampleset.json').write_text(json.dumps({
            'schema': observation.SCHEMA, 'hosts': {'h1': 'samples-h1.jsonl'}, 'actions': 'actions.jsonl',
            'quiesce': {k: f'{k}.json' for k in self.quiesce}, 'settings': self.settings, 'inputs': INPUTS}))
        return d


def flat_from(service, start, counters=None, value=None):
    """A hook: the service's counters stop at sample ``start`` (or the age gauge grows)."""
    def hook(name, kind, i, m):
        if name != service or m is None or i < start:
            return m
        frozen = metrics_of(name, kind, start)
        out = dict(m)
        for k in (counters or [k for k in m if k in frozen]):
            out[k] = frozen[k] if value is None else value(i)
        return out
    return hook


def dark_from(service, start):
    def hook(name, kind, i, m):
        return None if name == service and i >= start else m
    return hook


def series_at(service, key, value, samples):
    def hook(name, kind, i, m):
        if name == service and i in samples and m is not None:
            m = dict(m, **{key: value(i)})
        return m
    return hook


def judge_set(ss, disabled=()):
    with tempfile.TemporaryDirectory() as tmp:
        return observation.judge(observation.load_sample_set(ss.write(tmp)), disabled)


def assert_planted(verdict, line, text):
    """The assertion every planted set makes; its failure text is the vacuity control's text."""
    lines = {d['line']: d for d in verdict['lines']}
    texts = lines[line].get('fail', []) + (lines[line].get('inconclusive', []) if line == 'V1' else [])
    if text not in texts:
        raise AssertionError(f'verdict line {line} is vacuous')


V3_PICK = {'core member': 'core/ae1', 'ME member': 'match/me1'}


def plant_v3(kind):
    """A V3 set for one service kind: its work counters stop at sample 20 while its input keeps moving."""
    name = V3_PICK.get(kind) or next(n for n, k in SERVICES if k == kind)
    ss = SampleSet()
    work = observation.KINDS[kind]['work']
    if kind == 'core-replica':
        ss.metric_hooks.append(flat_from(name, 20, ['shadow_last_age_ms'], value=lambda i: 1000 + (i - 20) * PERIOD_S * 1000))
    else:
        keys = [k for k in metrics_of(name, kind, 1) if k.split('{')[0] in work]
        ss.metric_hooks.append(flat_from(name, 20, keys))
    return ss, f'healthy without progress: {name} {work[0].removeprefix("age:")}'


def planted_sets():
    """(label, line, sample set, the exact planted text)."""
    out = []
    ss = SampleSet()
    ss.rec_hooks.append(lambda i, r: None if 20 <= i < 25 else r)
    out.append(('gap', 'V1', ss, 'samples incomplete: gap 360 s'))

    ss = SampleSet()
    life = lambda i: min(i // 10, 3)       # killed and back at samples 10, 20 and 30
    ss.svc_hooks.append(lambda n, k, i, s: s if n != 'core/ae1' or i < 10 else
                        dict(s, supervisor=dict(s['supervisor'], pid=9000 + life(i)),
                             proc=dict(s['proc'], start_ticks=90000 + life(i), cpu_ticks=6 * (i - 10 * life(i)))))
    ss.metric_hooks.append(lambda n, k, i, m: m if n != 'core/ae1' or i < 10 else dict(m, core_snapshot_age_seconds=-1))
    out.append(('restart', 'V2', ss, 'repeated restart: core/ae1 x3'))

    ss = SampleSet()
    ss.svc_hooks.append(lambda n, k, i, s: s if n != 'ct-bridge/b0' or not 20 <= i < 23 else
                        dict(s, supervisor={'state': 'exited', 'pid': 0}, proc={'alive': False}, metrics={'code': 0, 'ms': 1, 'error': 'refused'}))
    ss.svc_hooks.append(lambda n, k, i, s: s if n != 'ct-bridge/b0' or i < 23 else
                        dict(s, supervisor=dict(s['supervisor'], pid=7777), proc=dict(s['proc'], start_ticks=77777)))
    out.append(('pid-gone', 'V2', ss, 'repeated restart: ct-bridge/b0 x1'))

    for kind in observation.KINDS:
        ss, text = plant_v3(kind)
        out.append((f'stall {kind}', 'V3', ss, text))
    ss = SampleSet()
    ss.metric_hooks.append(dark_from('ct-bridge/b0', 20))
    out.append(('dark bridge', 'V3', ss, 'alive and unreachable: ct-bridge/b0'))
    ss = SampleSet()
    ss.metric_hooks.append(dark_from('oe-projector/pj0', 20))
    out.append(('dark projector', 'V3', ss, 'alive and unreachable: oe-projector/pj0'))

    ss = SampleSet()
    ss.metric_hooks.append(series_at('core/ae0', 'core_cluster_role', lambda i: 0, {30, 31}))
    out.append(('no leader', 'V4', ss, 'no leader: core'))

    ss = SampleSet()
    ss.metric_hooks.append(lambda n, k, i, m: m if n != 'oe-stream/st0' else dict(m, stream_ws_connections=0, stream_ws_frames_sent_total=0))
    ss.svc_hooks.append(lambda n, k, i, s: s if n != 'oe-stream/st0' else dict(s, proc=dict(s['proc'], cpu_ticks=6 * i + (5400 * (i - 20) if i >= 20 else 0))))
    out.append(('spin', 'V5', ss, 'spin: oe-stream/st0'))

    ss = SampleSet()
    ss.metric_hooks.append(series_at('match/me1', 'match_snapshot_age_seconds', lambda i: 4000, {40}))
    out.append(('snapshot overdue', 'V6', ss, 'snapshot overdue: match/me1'))
    ss = SampleSet()
    ss.metric_hooks.append(lambda n, k, i, m: m if n != 'match/me2' else dict(m, match_log_bytes_reclaimed_total=0))
    out.append(('no reclaim', 'V6', ss, 'no reclaim in the window: match/me2'))

    ss = SampleSet()
    def grow(i, r):
        if i >= 50:
            r['dirs']['ae0 order journal'] = {'bytes': r['dirs']['ae0 order journal']['bytes'] + 512 * MB}
        return r
    ss.rec_hooks.append(grow)
    out.append(('disk', 'V7', ss, f'unexplained disk growth: ae0 order journal {512 * MB + 5 * 60 * 256}'))

    ss = SampleSet()
    ss.rec_hooks.append(lambda i, r: dict(r, shm={'/dev/shm': dict(r['shm']['/dev/shm'], used=100 * MB + i * 4 * MB)}))
    out.append(('shm rise', 'V8', ss, '/dev/shm did not return to baseline'))
    ss = SampleSet()
    ss.rec_hooks.append(lambda i, r: r if i < 50 else dict(r, shm={'/dev/shm': dict(
        r['shm']['/dev/shm'], entries=dict(r['shm']['/dev/shm']['entries'], **{'aeron-aedump-4242': 1 * MB}))}))
    out.append(('leftover dir', 'V8', ss, 'leftover driver directory: aeron-aedump-4242'))

    ss = SampleSet()
    ss.quiesce = {'Q0': CLEAN_Q, 'Q2': dict(CLEAN_Q, status='VIOLATED', violated=True,
                                            residual_holds=[{'userId': 900001, 'assetId': 0, 'actual': 500000000}])}
    out.append(('residual hold', 'V9', ss, 'residual hold: user 900001 asset 0 500000000'))

    ss = SampleSet()
    ss.metric_hooks.append(lambda n, k, i, m: m if k != 'core member' or i < 10 else dict(m, core_ingress_schema_rejects_total=3))
    out.append(('schema rejects', 'V10', ss, 'schema rejects: 3'))

    ss = SampleSet()
    ss.metric_hooks.append(lambda n, k, i, m: m if k != 'core member' or i not in (15, 16) else dict(m, core_order_entry_gate=0))
    out.append(('gate', 'V11', ss, 'gate closed without a recorded action'))

    ss = SampleSet()
    ss.metric_hooks.append(series_at('oe-gateway/gw0', 'gateway_history_age_ms', lambda i: 9000, {25}))
    out.append(('history', 'V12', ss, 'history stale outside a recorded window'))
    return out


class CleanSet(unittest.TestCase):
    def test_clean_set_passes(self):
        v = judge_set(SampleSet())
        self.assertEqual(v['status'], 'PASS', json.dumps(v['failures'] + v['inconclusive']))
        self.assertTrue(all(d['status'] == 'PASS' for d in v['lines']), v['lines'])
        self.assertEqual(v['side']['oms_lane_note'], observation.OMS_LANE_NOTE)

    def test_clean_set_with_any_line_disabled_still_passes(self):
        for line in observation.LINES:
            with self.subTest(line=line):
                self.assertEqual(judge_set(SampleSet(), {line})['status'], 'PASS')


class PlantedSets(unittest.TestCase):
    maxDiff = None

    def test_each_planted_set_fails_on_its_own_line_only(self):
        for label, line, ss, text in planted_sets():
            with self.subTest(label=label):
                v = judge_set(ss)
                want = 'INCONCLUSIVE' if line == 'V1' else 'FAIL'
                self.assertEqual(v['status'], want, f'{label}: {v["failures"]} {v["inconclusive"]}')
                assert_planted(v, line, text)
                others = [d for d in v['lines'] if d['line'] != line and d['status'] not in ('PASS', 'NA')]
                self.assertEqual(others, [], f'{label}: lines other than {line} did not pass')
                own = v['failures'] if line != 'V1' else v['inconclusive']
                self.assertEqual(own, [f'{line} {text}'], f'{label}: the set names more than its own service')

    def test_vacuity_control_each_line_switched_off(self):
        seen = set()
        for label, line, ss, text in planted_sets():
            with self.subTest(label=label):
                off = judge_set(ss, {line})
                self.assertEqual(off['status'], 'PASS', f'{label}: with {line} off: {off["failures"]} {off["inconclusive"]}')
                with self.assertRaises(AssertionError) as caught:
                    assert_planted(off, line, text)
                self.assertEqual(str(caught.exception), f'verdict line {line} is vacuous')
                if line not in seen:
                    print(f'\nCONTROL {label}: line {line} off -> {caught.exception}')
                    seen.add(line)
        self.assertEqual(seen, set(observation.LINES))

    def test_zero_hold_users_setting_requires_the_check_in_each_quiesce_document(self):
        users = [[900000, 900999]]
        check = {'name': 'zero_holds', 'status': 'PASS', 'drifts': [], 'users': users}
        with_check = dict(CLEAN_Q, checks=CLEAN_Q['checks'] + [check])

        def planted(q0, q2):
            ss = SampleSet()
            ss.settings['OBS_ZERO_HOLD_USERS'] = users
            ss.quiesce = {'Q0': q0, 'Q2': q2}
            return ss
        # the check ran at both points and passed: the set is clean
        self.assertEqual(judge_set(planted(with_check, with_check))['status'], 'PASS')
        # planted: Q2 was produced without --zero-hold-users. Nothing says the simulator holds nothing: INCONCLUSIVE
        text = ('zero-hold check missing at Q2: OBS_ZERO_HOLD_USERS is set and the money check ran without '
                '--zero-hold-users')
        ss = planted(with_check, CLEAN_Q)
        v = judge_set(ss)
        self.assertEqual((v['status'], v['failures'], v['inconclusive']), ('INCONCLUSIVE', [], [f'V9 {text}']))
        others = [d for d in v['lines'] if d['line'] != 'V9' and d['status'] not in ('PASS', 'NA')]
        self.assertEqual(others, [], 'lines other than V9 did not pass')
        # the check over other users, or not judged, is not the check the setting asks for
        for label, other, want in (
                ('other users', dict(check, users=[[1, 2]]), 'V9 zero-hold check at Q2 ran over other users: [[1, 2]], '
                                                             'OBS_ZERO_HOLD_USERS is [[900000, 900999]]'),
                ('not judged', dict(check, status='INDETERMINATE'), 'V9 zero-hold check not judged at Q2: INDETERMINATE')):
            with self.subTest(label=label):
                v = judge_set(planted(with_check, dict(CLEAN_Q, checks=CLEAN_Q['checks'] + [other])))
                self.assertEqual((v['status'], v['inconclusive']), ('INCONCLUSIVE', [want]))
        # a simulator hold at Q2 is the residual hold FAIL, named once
        failed = dict(CLEAN_Q, status='VIOLATED', violated=True, checks=CLEAN_Q['checks'] + [dict(check, status='FAIL')],
                      residual_holds=[{'userId': 900001, 'assetId': 0, 'actual': 500000000}])
        v = judge_set(planted(with_check, failed))
        self.assertEqual((v['status'], v['failures'], v['inconclusive']),
                         ('FAIL', ['V9 residual hold: user 900001 asset 0 500000000'], []))
        # vacuity control: with V9 off the missing check is not seen
        self.assertEqual(judge_set(ss, {'V9'})['status'], 'PASS')
        # without the setting the verdict asks for no such check (the clean set carries none)
        self.assertEqual(judge_set(SampleSet())['status'], 'PASS')
        print(f'\nV9 zero-hold check missing -> INCONCLUSIVE: {text}')

    def test_an_indeterminate_money_check_is_never_exact(self):
        ss = SampleSet()
        ss.quiesce = {'Q0': CLEAN_Q, 'Q2': dict(CLEAN_Q, status='INDETERMINATE', exit_code=4)}
        v = judge_set(ss)
        self.assertEqual((v['status'], v['inconclusive']), ('INCONCLUSIVE', ['V9 money check not exact at Q2: INDETERMINATE']))

    def test_every_v3_kind_has_a_set(self):
        kinds = {label.removeprefix('stall ') for label, line, _, _ in planted_sets() if label.startswith('stall ')}
        self.assertEqual(kinds, set(observation.KINDS))

    def test_a_failed_supervisor_read_is_not_a_service_down(self):
        ss = SampleSet()   # the last sample's supervisor reads failed (e.g. cut short at the stop): unknown, not down
        ss.svc_hooks.append(lambda n, k, i, s: s if i < N - 1 else dict(s, supervisor={'state': 'unknown', 'pid': 0,
                                                                                         'error': 'context canceled'}))
        self.assertEqual(judge_set(ss)['status'], 'PASS')

    def test_the_gate_is_the_leaders(self):
        ss = SampleSet()   # a restarted follower still replaying reports an older gate: not the cluster's gate
        ss.metric_hooks.append(series_at('core/ae2', 'core_order_entry_gate', lambda i: 0, {30}))
        self.assertEqual(judge_set(ss)['status'], 'PASS')

    def test_a_kind_without_a_row_is_inconclusive(self):
        ss = SampleSet()
        ss.services.append(('mystery/x0', 'mystery'))
        v = judge_set(ss)
        self.assertEqual(v['status'], 'INCONCLUSIVE')
        self.assertEqual(v['inconclusive'], ['V3 no work counter for mystery'])

    def test_unreadable_counter_with_a_live_pid_is_a_fail_never_inconclusive(self):
        ss = SampleSet()
        ss.metric_hooks.append(dark_from('ct-bridge/b0', 20))
        v = judge_set(ss)
        self.assertEqual((v['status'], v['inconclusive']), ('FAIL', []))
        self.assertIn('ct-bridge/b0 answered /ready 200 in 20 samples', v['side']['ready_on_failing'])

    def test_the_two_control_builds_change_the_frozen_bridge_outcome(self):
        ss = SampleSet()
        ss.metric_hooks.append(dark_from('ct-bridge/b0', 20))
        with tempfile.TemporaryDirectory() as tmp:
            loaded = observation.load_sample_set(ss.write(tmp))
        product = observation.judge(loaded)
        self.assertEqual(product['failures'], ['V3 alive and unreachable: ct-bridge/b0'])
        by_core = observation.judge(loaded, kinds=observation.BRIDGE_BY_CORE_POSITION)
        self.assertEqual(by_core['status'], 'PASS')     # the bridge judged by the core's position: the freeze is invisible
        as_gap = observation.judge(loaded, unreadable_as_gap=True)
        self.assertEqual((as_gap['status'], as_gap['failures']), ('INCONCLUSIVE', []))

    def test_a_recorded_action_explains_restart_gate_and_history(self):
        for label, line, ss, text in planted_sets():
            if label not in ('gate', 'history', 'pid-gone'):
                continue
            with self.subTest(label=label):
                service = {'gate': '*', 'history': '*', 'pid-gone': 'ct-bridge/b0'}[label]
                action = {'gate': 'gate', 'history': 'history', 'pid-gone': 'restart'}[label]
                at = {'gate': 15, 'history': 25, 'pid-gone': 21}[label]
                ss.actions = [{'ts_ms': T0 + at * PERIOD_S * 1000, 'until_ms': T0 + (at + 2) * PERIOD_S * 1000,
                               'service': service, 'action': action, 'note': 'planned'}]
                self.assertEqual(judge_set(ss)['status'], 'PASS')

    def test_no_sample_set_is_inconclusive(self):
        v = observation.judge_directory(None)
        self.assertEqual((v['status'], v['inconclusive']), ('INCONCLUSIVE', ['no sample set']))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(observation.judge_directory(tmp)['inconclusive'], ['no sample set'])

    def test_the_runner_judges_a_sample_set_and_refuses_none(self):
        import subprocess, sys
        here = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as tmp:
            d = SampleSet().write(Path(tmp))
            run = lambda manifest, out: subprocess.run([sys.executable, '-B', str(here / 'runner.py'), '--manifest', str(manifest),
                                                        '--scenario', 'demo-observation-24h', '--output', str(out)],
                                                       capture_output=True, text=True, timeout=120)
            ok = run(d / 'sampleset.json', Path(tmp) / 'out-ok')
            self.assertEqual(ok.returncode, 0, ok.stdout[-800:])
            self.assertEqual(json.loads((Path(tmp) / 'out-ok' / 'verdict.json').read_text())['status'], 'PASS')
            none = run(Path(tmp) / 'nothing-here', Path(tmp) / 'out-none')
            self.assertEqual(none.returncode, 2)
            result = json.loads((Path(tmp) / 'out-none' / 'result.json').read_text())
            self.assertEqual((result['status'], result['error']), ('INCONCLUSIVE', 'no sample set'))

    def test_a_broken_chain_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = SampleSet().write(tmp)
            lines = (d / 'samples-h1.jsonl').read_bytes().splitlines()
            lines[10] = lines[10].replace(b'"seq":10', b'"seq":99')
            (d / 'samples-h1.jsonl').write_bytes(b'\n'.join(lines) + b'\n')
            v = observation.judge(observation.load_sample_set(d))
        self.assertEqual(v['status'], 'INCONCLUSIVE')
        self.assertTrue(any('sample chain broken: h1 line 11' in t for t in v['inconclusive']), v['inconclusive'])

    def test_the_shadow_core_half_is_never_silent(self):
        ss = SampleSet()
        ss.metric_hooks.append(lambda n, k, i, m: {x: y for x, y in m.items() if x != 'shadow_log_purge_position'} if m else m)
        self.assertIn('V6 core purge position (shadow_log_purge_position) not read on any member',
                      judge_set(ss)['inconclusive'])


if __name__ == '__main__':
    unittest.main()
