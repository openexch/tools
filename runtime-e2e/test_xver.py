# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W3: the cross-version (new side), activation and rollback scenarios (contract 5.2, 6, 8.2, 10, 20.1). No Docker: the
case table, the settings, the refusal-site table with the W12 texts, the member classes and the 6.10 pass lines, the seed
witnesses, the X-7 pass line, the X-A and X-R judges, the active probe's answered rule, the runner dispatch."""
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import xver

NS = 1_000_000_000
T0 = 1_793_800_000 * NS
R0 = 'CRITICAL: principal-less session in log: pre-S6 history, clean genesis required ({}, clusterSessionId={}, logPosition={})'
QUORUM = ('me FATAL (exit 1): no cluster quorum observed within 120000 ms since the consensus module launched (election state '
          'CANVASS, elections 1) - node exiting, backstop in 5000 ms')
ME_ENVELOPE = ('CRITICAL: snapshot refused: snapshot envelope magic missing (length=282): refusing a bare or foreign snapshot image '
               '(1 byte(s) reassembled); this node will not serve an unverified state')
AE_ENVELOPE = ('FATAL snapshot refused: snapshot envelope magic missing (length=282): refusing a bare or foreign snapshot image; this '
               'node will not serve an unverified ledger')


def member(role, text, code=1, start_s=0.0, exit_s=2.0, running=False, ready=False):
    return {'role': role, 'running': running, 'exit_code': None if running else code, 'started_ns': T0 + int(start_s * NS),
            'finished_ns': None if running else T0 + int(exit_s * NS),
            'log': f'{"Match" if role[:2] == "me" else "Assets"} Engine node {role[2:]} starting: portBase=9000\n' + text + '\n',
            'ready_200': ready, 'restart_count': 0}


def log_only(engine='me', where='session open', positions=(256, 256)):
    return [member(f'{engine}0', R0.format(where, 1, positions[0]), start_s=0, exit_s=10.5),
            member(f'{engine}1', R0.format(where, 1, positions[1]), start_s=5, exit_s=10.05),
            member(f'{engine}2', QUORUM, start_s=10, exit_s=135)]


class CaseTableTest(unittest.TestCase):
    def test_seventeen_cases_on_their_scenarios_and_kinds(self):
        self.assertEqual(len(xver.CASES), 17)
        self.assertEqual(sorted(c for c in xver.CASES if c.startswith('X-1')),
                         ['X-1a-emb', 'X-1a-ext', 'X-1b-emb', 'X-1b-ext', 'X-1c-emb', 'X-1c-ext'])
        self.assertEqual(len([c for c in xver.CASES if c.startswith('X-3')]), 4)
        self.assertEqual(xver.case_for('core-xver-me-new-on-old-snapquiet', 's17-xver-ext'), 'X-1b-ext')
        self.assertEqual(xver.case_for('core-xver-ae-new-on-old-log', 's17-xver'), 'X-3b-emb')
        self.assertEqual(xver.case_for('core-xver-bridge-on-old-archive', 's17-xver'), 'X-7')
        self.assertEqual(xver.case_for('core-act-latemember', 's17-act'), 'X-A4')
        self.assertEqual(xver.case_for('core-act-toolkill-2', 's17-act'), 'X-A2')
        self.assertEqual(xver.case_for('core-rollback-old-line', 's17-rollback'), 'X-R')
        with self.assertRaisesRegex(Inconclusive, 'runs on the s17-xver or s17-xver-ext kinds'):
            xver.case_for('core-xver-me-new-on-old-log', 's17-ext')
        with self.assertRaisesRegex(Inconclusive, 'runs on the s17-act kind'):
            xver.case_for('core-act-nobridge', 's17-xver')
        with self.assertRaisesRegex(Inconclusive, 'unknown cross-version scenario'):
            xver.case_for('core-xver-me-old-on-new', 's17-xver')

    def test_no_scenario_puts_a_tag_jar_under_test(self):
        for case, spec in xver.CASES.items():
            self.assertNotIn('tag', spec.get('binary', 'rc2'), case)
        self.assertEqual({c['under_test'] for c in xver.CONTROLS.values()}, {'rc2', 'tag-seed-validity', 'rollback-restore'})

    def test_controls_are_named(self):
        self.assertEqual(set(xver.CONTROLS), {'core-xver-ctl-me-same', 'core-xver-ctl-ae-same', 'core-xver-ctl-x7-wiped',
                                              'core-xver-ctl-me-old-same-a', 'core-xver-ctl-me-old-same-b',
                                              'core-xver-ctl-me-old-same-c', 'core-xver-ctl-ae-old-same-a',
                                              'core-xver-ctl-ae-old-same-c',
                                              'core-rollback-ctl-omit-journal', 'core-rollback-ctl-omit-pgdump'})


class SettingsTest(unittest.TestCase):
    def test_defaults_are_the_po_values(self):
        s = xver.settings({})
        self.assertEqual((s['XVER_BOUND_S'], s['XVER_STAGGER_S'], s['XVER_TAIL_MIN'], s['ENGINE_QUORUM_WAIT_MS']),
                         (150, 5, 8, 120000))

    def test_probe_cadence_is_a_setting_and_measured(self):
        s = xver.settings({'XVER_PROBE_INTERVAL_S': '2'})
        self.assertEqual(s['XVER_PROBE_INTERVAL_S'], 2)
        rows = [{'started_ns': T0 + int(i * 3.3 * NS)} for i in range(4)]
        c = xver.probe_cadence(rows, s)
        self.assertEqual((c['attempts'], c['per_s'], c['interval_s']), (4, 0.303, 2))

    def test_settings_are_overridable_and_strict(self):
        self.assertEqual(xver.settings({'XVER_BOUND_S': '200'})['XVER_BOUND_S'], 200)
        with self.assertRaisesRegex(Violation, 'XVER_STAGGER_S must be a positive number'):
            xver.settings({'XVER_STAGGER_S': 'soon'})
        with self.assertRaisesRegex(Violation, 'XVER_BOUND_S 100 s cannot hold ENGINE_QUORUM_WAIT_MS'):
            xver.settings({'XVER_BOUND_S': '100'})

    def test_the_harness_never_shortens_the_quorum_wait(self):
        xver.check_engine_env({'CLUSTER_NODE': '0'})
        with self.assertRaisesRegex(Violation, 'never sets ENGINE_QUORUM_WAIT_MS'):
            xver.check_engine_env({'ENGINE_QUORUM_WAIT_MS': '5000'})


class RefusalSiteTest(unittest.TestCase):
    LINES = {
        'me-r0-restored': R0.format('restored session', 1, 13024),
        'me-r0-session-open': R0.format('session open', 1, 256),
        'me-r0-ingress': R0.format('ingress frame', -1, 4096),
        'me-envelope': ME_ENVELOPE,
        'me-lossy-restore': 'CRITICAL: snapshot refused: [SNAPSHOT] 1 order(s) dropped during restore (state loss)',
        'quorum': QUORUM,
    }

    def test_every_w12_text_maps_to_its_site_at_the_cut_commit(self):
        for key, line in self.LINES.items():
            with self.subTest(key=key):
                site = xver.match_site(line, 'me')
                self.assertEqual(site['key'], key)
                self.assertTrue(site['reads'] and site['commit'])
        ae = {'ae-r0-restored': R0.format('restored session', 3, -1), 'ae-r0-session-open': R0.format('session open', 1, 512),
              'ae-r0-ingress': R0.format('ingress frame', 4, 900), 'ae-envelope': AE_ENVELOPE}
        for key, line in ae.items():
            with self.subTest(key=key):
                self.assertEqual(xver.match_site(line, 'ae')['key'], key)
        self.assertIsNone(xver.match_site(R0.format('session open', 1, 256), 'bridge'))

    def test_restored_session_logposition_minus_one(self):
        site = xver.match_site(R0.format('restored session', 7, -1), 'ae')
        self.assertEqual((site['key'], site['logPosition']), ('ae-r0-restored', -1))

    def test_bridge_and_admin_ack_sites(self):
        self.assertEqual(xver.match_site('[WARN] foreign journal at the chain head of every source (journal schema 3, this bridge '
                                         'reads schema 4): no successor walk', 'bridge')['key'], 'bridge-foreign-head')
        self.assertEqual(xver.SITES['admin-ack-45']['code'], 45)
        self.assertEqual(xver.SITES['admin-ack-45']['name'], 'HALT_HOLDER_PENDING')
        self.assertEqual(xver.SITES['admin-ack-40']['name'], 'FEED_HALTED')
        self.assertEqual(xver.match_site('ADMIN OPEN GLOBAL never accepted: last reason 40 FEED_HALTED', 'driver')['key'],
                         'admin-ack-40')
        self.assertEqual(xver.match_site('ADMIN OPEN GLOBAL never accepted: last reason 45 HALT_HOLDER_PENDING', 'driver')['key'],
                         'admin-ack-45')


class MemberClassTest(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(xver.classify_member(member('me0', ME_ENVELOPE), {'me-envelope'})['class'], 'replay-halted')
        self.assertEqual(xver.classify_member(member('me2', QUORUM), {'me-envelope'})['class'], 'quorum-exited')
        other = xver.classify_member(member('me1', R0.format('restored session', 1, 1)), {'me-envelope'})
        self.assertEqual((other['class'], other['reason']), ('other', 'refusal at me-r0-restored, not a site of this case'))
        self.assertIn('exit 78', xver.classify_member(member('me0', ME_ENVELOPE, code=78), {'me-envelope'})['reason'])
        self.assertEqual(xver.classify_member(member('me0', '', running=True), set())['reason'], 'still Running')
        sub = xver.classify_member(member('me0', 'io.aeron.exceptions.AeronException: active Mark file detected'), set())
        self.assertEqual((sub['class'], sub['layer']), ('other', 'aeron substrate'))
        self.assertEqual(xver.classify_member(member('me0', 'Exception in thread main'), set())['reason'],
                         'exit 1 with no refusal text')


class StatePassLineTest(unittest.TestCase):
    def judge(self, case, members, probes=None, bound=150):
        if probes is None:              # review V5: one attempt in flight during every member's life
            probes = [{'answered': False, 'started_ns': T0, 'ended_ns': T0 + 400 * NS}]
        return xver.judge_state(case, members, list(probes), bound_s=bound, quorum_wait_ms=120000)

    def test_x1a_three_replay_halted(self):
        ms = [member(f'me{i}', R0.format('restored session', 1, 13024), start_s=5 * i, exit_s=5 * i + 1.5) for i in range(3)]
        v = self.judge('X-1a-emb', ms)
        self.assertEqual(v['verdict'], 'REFUSED', v['reasons'])
        self.assertEqual(v['classes'], {'replay-halted': 3, 'quorum-exited': 0, 'other': 0})

    def test_x1b_needs_the_envelope_text(self):
        ms = [member(f'me{i}', ME_ENVELOPE, start_s=5 * i, exit_s=5 * i + 1) for i in range(3)]
        self.assertEqual(self.judge('X-1b-ext', ms)['verdict'], 'REFUSED')
        ms[1] = member('me1', R0.format('restored session', 1, 1), start_s=5, exit_s=6)
        v = self.judge('X-1b-ext', ms)
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertIn('me1 other: refusal at me-r0-restored, not a site of this case', v['reasons'])

    def test_x1c_two_halts_and_one_quorum_exit(self):
        self.assertEqual(self.judge('X-1c-emb', log_only())['verdict'], 'REFUSED')
        ms = log_only(); ms[2] = member('me2', '', start_s=10, running=True)       # F-S17-20: Running and unready at the bound
        v = self.judge('X-1c-emb', ms)
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertIn('me2 other: still Running', v['reasons'])

    def test_class_counts_must_be_the_staggers_prediction(self):
        ms = [member(f'me{i}', R0.format('session open', 1, 256), start_s=5 * i, exit_s=5 * i + 5) for i in range(3)]
        v = self.judge('X-1c-emb', ms)
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertIn('class counts', ' '.join(v['reasons']))

    def test_an_exit_after_the_bound_is_inconclusive(self):
        ms = log_only(); ms[2]['finished_ns'] = T0 + 170 * NS
        v = self.judge('X-1c-emb', ms)
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertIn('me2 exited 160.0 s after the last member start, beyond XVER_BOUND_S 150', v['reasons'])

    def test_a_quorum_wait_other_than_the_setting_is_inconclusive(self):
        ms = log_only(); ms[2]['log'] = QUORUM.replace('120000', '5000')
        self.assertIn('me2 quorum wait 5000 ms != ENGINE_QUORUM_WAIT_MS 120000', self.judge('X-1c-emb', ms)['reasons'])

    def test_any_ready_or_answered_probe_is_guarded_silent(self):
        ms = log_only(); ms[0]['ready_200'] = True
        self.assertEqual(self.judge('X-1c-emb', ms)['verdict'], 'GUARDED-silent')
        v = self.judge('X-1c-emb', log_only(), probes=[{'answered': True, 'at_ns': T0 + 3 * NS, 'started_ns': T0}])
        self.assertEqual(v['verdict'], 'GUARDED-silent')
        self.assertEqual(xver.verdict_status(v['verdict']), 'FAIL')
        self.assertEqual(xver.verdict_status('REFUSED'), 'PASS')
        self.assertEqual(xver.verdict_status('INCONCLUSIVE'), 'INCONCLUSIVE')

    def test_x3a_kit_envelope_and_x3b_capture_witness(self):
        ms = [member(f'ae{i}', AE_ENVELOPE, start_s=5 * i, exit_s=5 * i + 1) for i in range(3)]
        self.assertEqual(self.judge('X-3a-emb', ms)['verdict'], 'REFUSED')
        v = self.judge('X-3b-ext', log_only('ae'))
        self.assertEqual(v['verdict'], 'REFUSED', v['reasons'])
        self.assertEqual(v['capture']['logPositions'], [256])
        ms = log_only('ae', positions=(256, 512))
        self.assertIn('the two replaying members name different logPositions [256, 512]', self.judge('X-3b-ext', ms)['reasons'])
        ms = log_only('ae')
        ms[0]['log'] = 'Assets Engine node 0 starting\nINGRESS DROP (schema): schemaId=2 version=4 templateId=32\n' + R0.format('session open', 1, 256)
        v = self.judge('X-3b-ext', ms)
        self.assertEqual(v['verdict'], 'FAIL')
        self.assertIn('ae0 dropped 1 frame(s) (INGRESS DROP) before its CRITICAL line', v['reasons'])


def seed_dir(root, shape, snapshot, tail=0, opens=0):
    root = Path(root) / shape
    witness = {'shape': shape, 'trees': {}, 'tail_requests_after_snapshot': tail, 'tail_session_opens': opens}
    import legacy_tag
    for m in ('me0', 'me1', 'me2', 'ae0', 'ae1', 'ae2'):
        c = root / m / 'state' / 'cluster'; c.mkdir(parents=True)
        entries = struct.pack('<qqqqqiI', 0, 0, 0, -1, 1, -1, 0) + b'\0' * 16
        if snapshot:
            entries += struct.pack('<qqqqqiI', 1, 0, 0, 4096, 1, 0, 1) + b'\0' * 16
        (c / 'recording.log').write_bytes(entries)
        (root / m / 'journal').mkdir()
        (root / m / 'journal' / 'x.rec').write_bytes(b'j')
        witness['trees'][m] = legacy_tag.tree_hash(root / m)
    (root / 'witness.json').write_text(json.dumps(witness))
    return root


class SeedWitnessTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def test_each_variant_needs_its_witness(self):
        a = seed_dir(self.temp.name, 'A', snapshot=True, tail=8, opens=1)
        w = xver.seed_witness('A', a, 'me0', tail_min=8)
        self.assertEqual((w['snapshot_recordings'], w['tail_requests_after_snapshot'], w['tail_session_opens']), (1, 8, 1))
        self.assertEqual(w['recorded_sha256'], json.loads((a / 'witness.json').read_text())['trees']['me0']['sha256'])
        b = seed_dir(self.temp.name, 'B', snapshot=True)
        self.assertEqual(xver.seed_witness('B', b, 'ae1', tail_min=8)['tail_requests_after_snapshot'], 0)
        c = seed_dir(self.temp.name, 'C', snapshot=False)
        self.assertEqual(xver.seed_witness('C', c, 'me2', tail_min=8)['snapshot_recordings'], 0)

    def test_a_seed_whose_witness_contradicts_its_variant_is_refused(self):
        no_snap = seed_dir(self.temp.name, 'A', snapshot=False, tail=8, opens=1)
        with self.assertRaisesRegex(Inconclusive, 'seed A me0: a snapshot variant needs a snapshot recording'):
            xver.seed_witness('A', no_snap, 'me0', tail_min=8)
        short = seed_dir(self.temp.name + '/s', 'A', snapshot=True, tail=3, opens=1)
        with self.assertRaisesRegex(Inconclusive, 'tail of 3 request'):
            xver.seed_witness('A', short, 'me0', tail_min=8)
        quiet_tail = seed_dir(self.temp.name + '/q', 'B', snapshot=True, tail=2)
        with self.assertRaisesRegex(Inconclusive, 'the empty-tail variant'):
            xver.seed_witness('B', quiet_tail, 'me0', tail_min=8)
        log_snap = seed_dir(self.temp.name + '/l', 'C', snapshot=True)
        with self.assertRaisesRegex(Inconclusive, 'a log-only variant forbids a snapshot'):
            xver.seed_witness('C', log_snap, 'me0', tail_min=8)


def x7_obs(**over):
    health = {'halted': True, 'haltReason': 'SOURCE_SCHEMA', 'haltDetail': 'FOREIGN_JOURNAL_HEAD', 'relistsSinceHalt': 0}
    samples = [{'at_ns': T0 + i * 2 * NS, 'me_running': {'me0': True, 'me1': True, 'me2': True},
                'bridges': {b: {'status': 503, 'health': dict(health)} for b in ('bridge0', 'bridge1')}} for i in range(31)]
    obs = {'samples': samples, 'sample_s': 60,
           'bridge_logs': {b: '[WARN] foreign journal at the chain head of every source\n' for b in ('bridge0', 'bridge1')},
           'money': [{'meEpoch': 0, 'lastAppliedJournalSeq': 0, 'feedHalted': True, 'haltReason': 'SOURCE_SCHEMA'}] * 2,
           'gate_rows': [['SUSPENDED', 'GENESIS'], ['SUSPENDED', 'BRIDGE_HALT']],
           'driver': {'exit': 1, 'out': 'CoreConfig 1 result 0\nCoreConfig 2 result 0\nCoreConfig 3 result 0\n'
                                         'DRIVER FAIL ADMIN OPEN GLOBAL never accepted: last reason 40 FEED_HALTED\n'},
           'probe_order': {'meaning': 'REFUSED', 'reply': {'replies': [{'t': 'OrderReject', 'reason': 'GATE_CLOSED'}]},
                           'after_bridge_halt': True},
           'probe_deposit': {'meaning': 'ANSWERED'}, 'tap_alive_after_sampling': True,
           'last_feedhalt_ack_ns': {b: T0 - NS for b in ('bridge0', 'bridge1')}}
    obs.update(over)
    return obs


class X7PassLineTest(unittest.TestCase):
    def test_the_refusal(self):
        v = xver.judge_x7(x7_obs())
        self.assertEqual(v['verdict'], 'REFUSED', v['reasons'])

    def test_an_unreachable_archive_is_inconclusive(self):
        obs = x7_obs()
        obs['samples'][3]['me_running']['me1'] = False
        v = xver.judge_x7(obs)
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertIn('an ME journal archive was unreachable during the sampling (me1)', v['reasons'])
        obs = x7_obs()
        for s in obs['samples']:
            s['bridges']['bridge0']['health']['haltDetail'] = 'NONE'
        obs['bridge_logs']['bridge0'] = 'verdict source 2 e 1 UNREACHABLE seq 0 epoch 0 bad none fault NONE\n'   # review V8
        self.assertEqual(xver.judge_x7(obs)['verdict'], 'INCONCLUSIVE')

    def test_an_open_gate_or_a_bound_core_fails_the_w12_rule(self):
        v = xver.judge_x7(x7_obs(gate_rows=[['SUSPENDED', 'GENESIS'], ['SUSPENDED', 'BRIDGE_HALT'], ['OPEN', 'ADMIN']]))
        self.assertEqual(v['verdict'], 'FAIL')
        v = xver.judge_x7(x7_obs(money=[{'meEpoch': 7, 'lastAppliedJournalSeq': 3, 'feedHalted': True,
                                         'haltReason': 'SOURCE_SCHEMA'}]))
        self.assertIn('the core bound: meEpoch 7, lastAppliedJournalSeq 3', v['reasons'])
        v = xver.judge_x7(x7_obs(driver={'exit': 0, 'out': 'GLOBAL OPEN (bound through the bridge)\n'}))
        self.assertEqual(v['verdict'], 'FAIL')

    def test_each_line_of_6_7(self):
        obs = x7_obs(); obs['samples'][5]['bridges']['bridge1']['health']['relistsSinceHalt'] = 1
        self.assertIn('bridge1 relistsSinceHalt 1 in a sample', xver.judge_x7(obs)['reasons'])
        obs = x7_obs(); obs['bridge_logs']['bridge0'] += 'halt left: cursor 0 last 0\n'
        self.assertIn('bridge0 logged "halt left"', xver.judge_x7(obs)['reasons'])
        obs = x7_obs(); obs['bridge_logs']['bridge1'] *= 2
        self.assertIn('bridge1 logged the foreign-head WARN 2 time(s), want once', xver.judge_x7(obs)['reasons'])
        self.assertIn('sampling 30 s < 60 s', xver.judge_x7(x7_obs(sample_s=30))['reasons'])
        obs = x7_obs(probe_order={'meaning': 'ANSWERED', 'reply': {'replies': [{'t': 'OrderAck'}]}, 'after_bridge_halt': True})
        self.assertIn('the probe order was not refused GATE_CLOSED', ' '.join(xver.judge_x7(obs)['reasons']))
        self.assertIn('the probe deposit was not ACKed (UNKNOWN)',
                      xver.judge_x7(x7_obs(probe_deposit={'meaning': 'UNKNOWN'}))['reasons'])

    def test_the_wiped_control_opens(self):
        ok = {'gate_rows': [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']], 'driver': {'exit': 0, 'out': 'GLOBAL OPEN\n'},
              'money': [{'meEpoch': 5, 'lastAppliedJournalSeq': 1}]}
        self.assertEqual(xver.judge_x7_wiped(ok)['verdict'], 'OPENED')
        self.assertEqual(xver.judge_x7_wiped(dict(ok, driver={'exit': 1, 'out': ''}))['verdict'], 'NOT-OPENED')


class ActJudgeTest(unittest.TestCase):
    def test_xa1(self):
        obs = {'record': {'status': 'OK', 'members_up': {'me': 2, 'ae': 3}}, 'killed': 'me0',
               'audit': {'stopped': [{'role': 'me0', 'registered_fault_target': True}]},
               'rerun_core': {'exit': 1, 'out': 'CoreConfig 1 result 4\n'}, 'rerun_me': {'exit': 0, 'out': 'EPOCH 15112027\n'},
               'me_engine_configs_after_rerun': {'me1': 1, 'me2': 1}, 'restart_ready': True, 'gate': 'OPEN', 'genesis_id': 15112027}
        self.assertEqual(xver.judge_a1(obs)['verdict'], 'PASS', xver.judge_a1(obs)['reasons'])
        bad = dict(obs, record={'status': 'OK', 'members_up': {'me': 3, 'ae': 3}})
        self.assertIn('members_up me 3, want 2/3 at the record time', xver.judge_a1(bad)['reasons'])
        bad = dict(obs, rerun_core={'exit': 0, 'out': 'CoreConfig 1 result 1\n'})
        self.assertIn('the core tool re-run was not refused STALE at CoreConfig 1', xver.judge_a1(bad)['reasons'])
        bad = dict(obs, me_engine_configs_after_rerun={'me1': 2, 'me2': 1})
        self.assertIn('the ME FRESH re-run wrote a second engine_config record on me1', xver.judge_a1(bad)['reasons'])

    def test_xa2(self):
        import test_s17_review as R          # review V15: the full 6.8 inputs (partial acks, order, the T1MeDriver output)
        self.assertEqual(xver.judge_a2(R.a2())['verdict'], 'PASS', xver.judge_a2(R.a2())['reasons'])
        self.assertIn('the record before the recovery reads OK, want INCOMPLETE or ABORTED',
                      xver.judge_a2(R.a2(before={'status': 'OK'}))['reasons'])
        self.assertIn('the new genesisId was not REJECTED at CoreConfig 1',
                      xver.judge_a2(R.a2(new_id_core={'exit': 1, 'out': 'CoreConfig 1 result 4'}))['reasons'])
        k2 = R.a2(stop_after=2, partial={'results': [[1, 'ACCEPTED'], [2, 'ACCEPTED']]},
                  same_id={'exit': 0, 'out': ''}, gate_final='GENESIS', bound_after_same_id=0, recovery={})
        self.assertIn('after CoreConfig 1 and 2 the same-id re-run was not refused STALE at CoreConfig 1', xver.judge_a2(k2)['reasons'])

    def test_xa3(self):
        obs = {'driver': {'exit': 1, 'out': 'ADMIN OPEN GLOBAL never accepted: last reason 41 ME_LANE_INACTIVE'},
               'gate_no_bridge': 'GENESIS', 'probe_open_no_bridge': {'meaning': 'REFUSED', 'reason': 41},
               'before': {'status': 'INCOMPLETE'}, 'bound_after_s': 12.9, 'gate_after_bind': 'GENESIS',
               'probe_open_after_bind': {'meaning': 'ANSWERED', 'result': 'ACCEPTED'}, 'gate_final': 'OPEN'}
        self.assertEqual(xver.judge_a3(obs)['verdict'], 'PASS', xver.judge_a3(obs)['reasons'])
        self.assertIn('the gate left GENESIS before the explicit open (OPEN)',
                      xver.judge_a3(dict(obs, gate_after_bind='OPEN'))['reasons'])

    def test_xa4_record_5_equal_except_member_local_fields(self):
        r5 = {'journal_seq': 1, 'me_epoch': 7, 'behavior_version': 2, 'source': 'me0', 'recording': 0, 'position': 96}
        obs = {'record5': {'me0': r5, 'me1': dict(r5, source='me1'), 'me2': dict(r5, source='me2', recording=3)},
               'ae_log_positions': {'ae0': 4096, 'ae1': 4096, 'ae2': 4096}, 'late_ready': {'me2': True, 'ae2': True}}
        self.assertEqual(xver.judge_a4(obs)['verdict'], 'PASS', xver.judge_a4(obs)['reasons'])
        obs['record5']['me2']['me_epoch'] = 9
        self.assertIn('me2 record 5 differs from me0 in me_epoch', xver.judge_a4(obs)['reasons'])
        obs['record5']['me2']['me_epoch'] = 7
        obs['ae_log_positions']['ae2'] = 1024
        self.assertIn('AE logPositions differ at quiescence: {\'ae0\': 4096, \'ae1\': 4096, \'ae2\': 1024}',
                      xver.judge_a4(obs)['reasons'])

    def test_xa5(self):
        obs = {'wait_rows': [{'fwd0': [True, 503], 'fwd1': [True, 503]}] * 30, 'wait_s': 30, 'epoch_waits': {'fwd0': 6, 'fwd1': 6},
               'bound_lines': {'fwd0': 1, 'fwd1': 1}, 'restarts': {'fwd0': 0, 'fwd1': 0}, 'ready_after_genesis': True,
               'resync_after_bound': {'fwd0': 1, 'fwd1': 1}}
        self.assertEqual(xver.judge_a5(obs)['verdict'], 'PASS', xver.judge_a5(obs)['reasons'])
        bad = dict(obs, wait_rows=obs['wait_rows'][:-1] + [{'fwd0': [True, 200], 'fwd1': [True, 503]}])
        self.assertIn('fwd0 answered /ready 200 while the epoch was 0', xver.judge_a5(bad)['reasons'])
        bad = dict(obs, wait_rows=[{'fwd0': [False, None], 'fwd1': [True, 503]}])
        self.assertIn('fwd0 exited before the genesis', ' '.join(xver.judge_a5(bad)['reasons']))
        self.assertIn('fwd1 restarted 1 time(s)', xver.judge_a5(dict(obs, restarts={'fwd0': 0, 'fwd1': 1}))['reasons'])


class RollbackJudgeTest(unittest.TestCase):
    D = {'r01_oms': {'rows': 54, 'sha256': 'a'}, 'r01_money': {'rows': 68, 'sha256': 'b'}, 'r01_market': {'rows': 12, 'sha256': 'c'},
         'ae': {'balances': 4, 'holds': 1, 'lastAppliedTradeId': 12, 'sha256': 'd'}, 'combined': 'x'}

    def test_rollback_and_omit(self):
        post = {'deposits': [True, True], 'orders': [True, True, True], 'changed': True}
        j = lambda *a, **k: xver.judge_rollback(*a, smoke='PASS', **k)
        self.assertEqual(j(self.D, dict(self.D), post)['verdict'], 'PASS')
        d1 = json.loads(json.dumps(self.D)); d1['r01_money']['sha256'] = 'z'; d1['combined'] = 'y'
        v = j(self.D, d1, post)
        self.assertEqual(v['verdict'], 'FAIL')
        self.assertIn('D1 != D0 in r01_money', v['reasons'])
        self.assertEqual(j(self.D, d1, post, omitted='pg-dump')['verdict'], 'PASS')      # xr-omit: must fail on its part
        self.assertEqual(j(self.D, dict(self.D), post, omitted='ae-money-journal')['verdict'], 'FAIL')
        self.assertEqual(j(self.D, None, None, omitted='ae-money-journal', error='tag engine log marker missing: ae0',
                           error_phase='restore-start')['verdict'], 'PASS')
        self.assertIn('the post-restore scenario did not pass',
                      ' '.join(j(self.D, dict(self.D), dict(post, orders=[False]))['reasons']))


class ProbeAnswerTest(unittest.TestCase):
    def test_answered_rules(self):
        self.assertTrue(xver.probe_answered('me', 0, '{"verb":"open-legs","legs":[]}', None))
        self.assertFalse(xver.probe_answered('me', 1, 'JournalProbe: timeout', None))
        self.assertTrue(xver.probe_answered('ae', 4, '', 'REFUSED'))
        self.assertTrue(xver.probe_answered('ae', 0, '', 'ANSWERED'))
        self.assertFalse(xver.probe_answered('ae', 3, '', 'UNKNOWN'))


class RunnerDispatchTest(unittest.TestCase):
    def test_runner_routes_the_s17_prefixes_to_xver(self):
        source = (Path(__file__).resolve().parent / 'runner.py').read_text()
        self.assertTrue("args.scenario.startswith(('core-xver-', 'core-act-', 'core-rollback-'))" in source,
                        'runner.py does not dispatch the S17 prefixes to xver')
        self.assertEqual(xver.PREFIXES, ('core-xver-', 'core-act-', 'core-rollback-'))

    def test_scenario_refuses_an_unknown_name_before_touching_the_box(self):
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / 'manifest.json'
            m.write_text(json.dumps({'manifest_kind': 's17-xver'}))
            with self.assertRaisesRegex(Inconclusive, 'unknown cross-version scenario'):
                xver.scenario(m, 'core-xver-nope', Path(d) / 'out')


if __name__ == '__main__':
    unittest.main()
