# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W1-W4 independent review (scratchpad s17/w1w4-review.txt): one RED per BLOCKER/FIX V1-V18. Each test feeds the wrong
input the review showed passing and asserts it is refused (or judged) now. No Docker."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import types
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import core_contracts
import r10_cut
import test_r10_cut as T
import test_xver as X
import xver

NS = X.NS
T0 = X.T0


def checker(world):
    return lambda m, cls=None, rules=r10_cut.RULES: r10_cut.check(m, cls=cls, rules=rules, old_pins=world.pins)


class CutBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.w = T.World(self.temp.name)
        self.check = checker(self.w)
        patch = mock.patch.object(r10_cut, 'git_blob', self.w.blob); patch.start(); self.addCleanup(patch.stop)

    def tearDown(self):
        self.temp.cleanup()


# ------------------------------------------------------------------ V2 / V18: the harness is tied to the cut

class V2HarnessTiedToTheCutTest(CutBase):
    def test_harness_commit_must_be_repos_tools(self):
        m = copy.deepcopy(self.w.m); m['harness_commit'] = 'f' * 40
        self.assertIn('K4', self.check(m).by_rule())
        self.assertTrue(any('harness_commit' in t and 'repos.tools' in t for _, t in self.check(m).items))

    def test_a_stale_probe_source_is_refused(self):
        m = copy.deepcopy(self.w.m)
        with mock.patch.object(r10_cut, 'git_blob', lambda repo, commit, rel: b'a newer CoreProbe.java'):
            items = self.check(m).items
        self.assertTrue(any(rule == 'K4' and 'harness.core_probe' in t and 'at harness_commit' in t for rule, t in items), items)

    def test_a_derived_manifest_on_another_or_dirty_harness_is_refused(self):
        fx = T.FixtureManifestTest.fixture(types.SimpleNamespace(w=self.w))
        fx.update(harness_commit=self.w.m['harness_commit'], harness_dirty=False)
        self.assertEqual(r10_cut.check(fx, self.w.m, 'rig', old_pins=self.w.pins).items, [])
        for edit, text in (({'harness_commit': 'f' * 40}, 'is not the cut\'s harness_commit'),
                           ({'harness_dirty': True}, 'dirty harness')):
            bad = dict(fx, **edit)
            found = r10_cut.check(bad, self.w.m, 'rig', old_pins=self.w.pins)
            self.assertTrue(any(text in t for _, t in found.items), found.items)
        waived = dict(fx, harness_commit='f' * 40, harness_dirty=True, harness_drift={'reason': 'smoke before the cut regeneration'})
        found = r10_cut.check(waived, self.w.m, 'rig', old_pins=self.w.pins)
        self.assertEqual(found.items, [])
        self.assertTrue(found.waived)
        self.assertTrue(r10_cut.check(waived, self.w.m, 'nightly', old_pins=self.w.pins).items)   # never on a night

    def test_xa2_refuses_a_staged_probe_without_the_genesis_argument(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'CoreProbe.java'; src.write_text('private int coreConfig() { configVersion(num("version")) }')
            with self.assertRaisesRegex(Inconclusive, 'stale CoreProbe'):
                xver.require_probe_genesis({'core_probe': {'source_path': str(src)}})
            src.write_text('.genesisId(Long.decode(arg("genesis")))')
            xver.require_probe_genesis({'core_probe': {'source_path': str(src)}})


class V18SiteCommitsFromTheCutTest(unittest.TestCase):
    def test_a_cut_on_other_commits_is_refused(self):
        cut = {'repos': dict(xver.COMMITS)}
        self.assertEqual(xver.check_sites(cut), [])
        cut['repos']['match'] = '0' * 40
        self.assertEqual(xver.check_sites(cut), [f'match: the refusal-site table was read at {xver.COMMITS["match"]}, the cut '
                                                 f'is at {"0" * 40}'])


# ------------------------------------------------------------------ V3 / V4: K4 rebuild-equal, K8 from the jars

class V3RebuildEqualNeedsTwoBuildsTest(CutBase):
    def test_one_file_listed_twice_is_not_two_builds(self):
        m = copy.deepcopy(self.w.m)
        name = 'assets-cluster.jar'
        path = m['artifacts'][name]['path']
        self.w.record[name] = [{'repo': 'assets', 'source_sha': T.SHAS['assets'], 'path': path,
                                'sha256': m['artifacts'][name]['sha256']}] * 2
        self.w.refresh_record(m)
        found = self.check(m)
        self.assertTrue(any(r == 'K4' and name in t and 'distinct' in t for r, t in found.items), found.items)


class V4AeronVersionFromTheJarsTest(CutBase):
    def test_a_1_53_0_jar_under_a_1_53_1_substrate_is_refused(self):
        m = copy.deepcopy(self.w.m)
        name = 'assets-cluster.jar'
        data = T.engine_jar(name, aeron='1.53.0')
        p = self.w.put('artifacts/' + name, data)
        self.w.record[name] = []
        self.w.build(name, 'assets', T.SHAS['assets'], data, 2, tag='-old')
        self.w.refresh_record(m)
        m['artifacts'][name]['sha256'] = T.h(data)
        found = self.check(m)
        self.assertTrue(any(r == 'K8' and 'io/aeron/AeronVersion' in t and '1.53.0' in t for r, t in found.items), found.items)


# ------------------------------------------------------------------ V5-V7: the 6.10 judge

def judge(case, members, probes, **kw):
    return xver.judge_state(case, members, probes, bound_s=150, quorum_wait_ms=120000, **kw)


def covering(members):
    """One probe attempt in flight during every member's life."""
    lo = min(m['started_ns'] for m in members)
    hi = max(m['finished_ns'] or m['started_ns'] for m in members)
    return [{'answered': False, 'started_ns': lo, 'ended_ns': hi + NS, 'code': 1}]


class V5ProbeMinimumTest(unittest.TestCase):
    def test_zero_attempts_is_not_a_refusal(self):
        v = judge('X-1c-emb', X.log_only(), [])
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertTrue(any('probe attempt' in r for r in v['reasons']), v['reasons'])
        self.assertEqual(judge('X-1c-emb', X.log_only(), covering(X.log_only()))['verdict'], 'REFUSED')

    def test_the_me_probe_is_judged_on_its_exit_code(self):
        legs = ',' .join('{"leg":%d,"order":%d}' % (i, i) for i in range(40))
        out = '{"verb":"open-legs","snapshot_max_order_id":0,"legs":[' + legs + ']}'
        self.assertTrue(xver.probe_answered('me', 0, out[-300:], None))
        self.assertFalse(xver.probe_answered('me', 1, out, None))


class V6CaptureWitnessTest(unittest.TestCase):
    def test_a_log_without_the_engine_start_banner_or_with_another_drop_text(self):
        ms = X.log_only('ae')
        for m in ms[:2]:
            m['log'] = 'aeron_driver_context_t {\n' + m['log'].split('\n', 1)[1]          # no "Assets Engine node N starting"
        v = judge('X-3b-ext', ms, covering(ms))
        self.assertNotEqual(v['verdict'], 'REFUSED')
        ms = X.log_only('ae')
        for m in ms:
            m['log'] = 'Assets Engine node 0 starting: portBase=19300\n' + m['log']
            m['restart_count'] = 0
        self.assertEqual(judge('X-3b-ext', ms, covering(ms))['verdict'], 'REFUSED')
        ms[0]['log'] = ms[0]['log'].replace('CRITICAL', 'INGRESS DROP (decode): templateId=32\nCRITICAL', 1)
        self.assertEqual(judge('X-3b-ext', ms, covering(ms))['verdict'], 'FAIL')
        ms = X.log_only('ae')
        for m in ms:
            m['log'] = 'Assets Engine node 0 starting\n' + m['log']
            m['restart_count'] = 0
        ms[1]['restart_count'] = 1
        self.assertNotEqual(judge('X-3b-ext', ms, covering(ms))['verdict'], 'REFUSED')


class V7QuorumMemberIsTheLastStartedTest(unittest.TestCase):
    def test_the_first_started_member_quorum_exited_is_not_the_prediction(self):
        ms = X.log_only()
        ms[0]['log'], ms[2]['log'] = ms[2]['log'], ms[0]['log']           # me0 (first) quorum-exited, me2 (last) halted
        v = judge('X-1c-emb', ms, covering(ms))
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertTrue(any('last-started' in r for r in v['reasons']), v['reasons'])


# ------------------------------------------------------------------ V8: X-7

def x7(**over):
    obs = X.x7_obs(**over)
    first = obs['samples'][0]['at_ns']
    obs.setdefault('last_feedhalt_ack_ns', {'bridge0': first - NS, 'bridge1': first - NS})
    obs.setdefault('tap_alive_after_sampling', True)
    return obs


class V8X7JudgeTest(unittest.TestCase):
    def test_a_regressed_b1_without_unreachability_evidence_fails(self):
        obs = x7()
        for s in obs['samples']:
            s['bridges']['bridge0']['health']['haltDetail'] = 'NONE'
        obs['bridge_logs']['bridge0'] = 'verdict source 0 e 1 BAD seq 0 epoch 0 bad schema fault NONE\n'
        self.assertEqual(xver.judge_x7(obs)['verdict'], 'FAIL')
        obs['bridge_logs']['bridge0'] += 'verdict source 1 e 1 UNREACHABLE seq 0 epoch 0 bad none fault NONE\n'
        self.assertEqual(xver.judge_x7(obs)['verdict'], 'INCONCLUSIVE')

    def test_a_missing_relists_key_is_not_zero(self):
        obs = x7()
        del obs['samples'][4]['bridges']['bridge1']['health']['relistsSinceHalt']
        self.assertIn('bridge1 relistsSinceHalt missing in a sample', xver.judge_x7(obs)['reasons'])

    def test_the_window_is_anchored_after_the_last_feedhalt_ack(self):
        obs = x7()
        obs['last_feedhalt_ack_ns'] = {'bridge0': obs['samples'][10]['at_ns'], 'bridge1': obs['samples'][0]['at_ns'] - NS}
        reasons = xver.judge_x7(obs)['reasons']
        self.assertTrue(any('after the last FeedHalt ack' in r for r in reasons), reasons)
        obs = x7(); obs['last_feedhalt_ack_ns'] = {'bridge0': None, 'bridge1': None}
        self.assertTrue(any('no FeedHalt AdminAck' in r for r in xver.judge_x7(obs)['reasons']))

    def test_the_tap_must_outlive_the_window(self):
        self.assertIn('the tap was not alive at the end of the sampling (an OPEN row after its death is unseen)',
                      xver.judge_x7(x7(tap_alive_after_sampling=False))['reasons'])


# ------------------------------------------------------------------ V9: X-R judge

class V9RollbackJudgeTest(unittest.TestCase):
    EMPTY = {'r01_oms': {'rows': 0, 'sha256': 'e'}, 'r01_money': {'rows': 0, 'sha256': 'e'}, 'r01_market': {'rows': 0, 'sha256': 'e'},
             'ae': {'balances': 0, 'holds': 0, 'lastAppliedTradeId': 0, 'sha256': 'e'}, 'combined': 'e'}
    POST = {'deposits': [True, True], 'orders': [True, True, True], 'changed': True}

    def full(self):
        d = json.loads(json.dumps(X.RollbackJudgeTest.D))
        d['ae']['lastAppliedTradeId'] = 12
        return d

    def test_an_empty_line_and_a_failed_legacy_smoke_are_not_a_rollback(self):
        v = xver.judge_rollback(self.EMPTY, dict(self.EMPTY), self.POST, smoke='PASS')
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertTrue(any('D0 is empty' in r for r in v['reasons']), v['reasons'])
        v = xver.judge_rollback(self.full(), self.full(), self.POST, smoke='FAIL')
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        self.assertEqual(xver.judge_rollback(self.full(), self.full(), self.POST, smoke='PASS')['verdict'], 'PASS')

    def test_omit_bites_only_on_its_own_part(self):
        v = xver.judge_rollback(self.full(), None, None, omitted='ae-money-journal', error='KeyError: harness bug', smoke='PASS')
        self.assertEqual(v['verdict'], 'INCONCLUSIVE')
        d1 = self.full(); d1['r01_oms']['sha256'] = 'z'
        self.assertEqual(xver.judge_rollback(self.full(), d1, self.POST, omitted='pg-dump', smoke='PASS')['verdict'],
                         'INCONCLUSIVE')
        d1 = self.full(); d1['r01_money']['sha256'] = 'z'
        self.assertEqual(xver.judge_rollback(self.full(), d1, self.POST, omitted='pg-dump', smoke='PASS')['verdict'], 'PASS')
        v = xver.judge_rollback(self.full(), None, None, omitted='ae-money-journal', smoke='PASS',
                                error='Inconclusive: tag engine log marker missing: ae1', error_phase='restore-start')
        self.assertEqual(v['verdict'], 'PASS')


# ------------------------------------------------------------------ V10-V12: the activation record

class RecordBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        rid = 'rc2-000000000001'
        self.gid = int(core_contracts.derive_genesis_id(rid), 16)
        self.d = T.RunDir(self.temp.name, gid=self.gid)
        self.d.owner['genesis']['derivation'] = {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': rid}
        self.d.write()

    def tearDown(self):
        self.temp.cleanup()

    def record(self):
        return r10_cut.activation_record(self.d.run, journal_schema=T.ME_JOURNAL)


class V10IndependentSourcesTest(RecordBase):
    def test_sources_are_the_files_read(self):
        rec = self.record()
        self.assertEqual(rec['status'], 'OK', rec['refusals'])
        files = rec['sources']['files']
        self.assertTrue(files['me_genesis_id'] and files['core_genesis_id'] and files['core_bound_epoch'])
        self.assertTrue(all(p.endswith('.rec') for p in files['core_genesis_id']))
        bad = copy.deepcopy(rec); bad['sources']['files']['core_genesis_id'] = list(files['me_genesis_id'])
        self.assertTrue(any('read from one file' in t for t in r10_cut.check_record(bad)))

    def test_the_records_cli_refuses_a_repeated_id_and_differing_invariants(self):
        r1 = self.record()
        a, b = Path(self.temp.name) / 'a.json', Path(self.temp.name) / 'b.json'
        a.write_text(json.dumps(r1)); b.write_text(json.dumps(r1))
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = r10_cut.main(['activation-records', str(a), str(b)])
        self.assertEqual(code, 1)
        self.assertIn('repeats across genesis runs', out.getvalue())
        r2 = copy.deepcopy(r1); r2['me']['genesisId'] = r1['me']['genesisId'] + 2; r2['me']['record5']['max_wire_version'] = 11
        self.assertIn('max_wire_version', ' '.join(r10_cut.check_record_set([r1, r2])))


class V11AppliedCoreConfigTest(RecordBase):
    def test_a_refused_coreconfig_1_with_another_id_does_not_win(self):
        for m in ('ae0', 'ae1', 'ae2'):
            T.write_ae_member(self.d.state, m, [T.core_config_payload(1, self.gid + 6)] +
                              [T.core_config_payload(v, self.gid) for v in (1, 2, 3)])
        self.d.requests.insert(0, {'verb': 'core-config', 'args': {'version': 1},
                                   'reply': {'replies': [{'t': 'AdminAck', 'ref': 70, 'result': 'REJECTED', 'reason': 2,
                                                          'configVersion': 1}]}, 'at_ns': 1})
        self.d.write()
        rec = self.record()
        self.assertEqual(rec['core']['genesisId'], self.gid, rec['refusals'])
        self.assertIn('accepted', rec['sources']['core_genesis_id'])


class V12DerivationRequiredTest(RecordBase):
    def test_an_s17_run_without_the_derivation_is_refused(self):
        del self.d.owner['genesis']['derivation']; self.d.write()
        rec = self.record()
        self.assertEqual(rec['status'], 'REFUSED')
        self.assertTrue(any('genesisId derivation missing' in t for t in rec['refusals']), rec['refusals'])


# ------------------------------------------------------------------ V13: nightly pin

class V13NightlyPinTest(unittest.TestCase):
    def setUp(self):
        import nightly
        self.nightly = nightly
        self.temp = tempfile.TemporaryDirectory(); self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_an_empty_commit_is_refused_in_plan_mode(self):
        with self.assertRaisesRegex(Violation, 'empty harness commit'):
            self.nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', str(self.dir / 'e'),
                                    '--harness-commit', ''], host=object())

    def test_the_cut_must_name_the_pinned_harness(self):
        cut = self.dir / 'cut.json'
        cut.write_text(json.dumps({'cut_id': 'rc2-cut-9', 'harness_commit': 'a' * 40}))
        ident = self.nightly.cut_identity(cut, 'a' * 40)
        self.assertEqual((ident['cut_id'], ident['sha256']), ('rc2-cut-9', hashlib.sha256(cut.read_bytes()).hexdigest()))
        with self.assertRaisesRegex(Violation, 'the cut names harness_commit'):
            self.nightly.cut_identity(cut, 'b' * 40)

    def test_the_plan_is_the_one_at_the_pinned_commit(self):
        harness = self.dir / 'harness-x' / 'runtime-e2e'; harness.mkdir(parents=True)
        (harness / 'nightly-cut.json').write_text('{"entries": []}')
        mine = self.dir / 'nightly-cut.json'; mine.write_text('{"entries": [1]}')
        with self.assertRaisesRegex(Violation, 'not the plan at the pinned commit'):
            self.nightly.pinned_plan(mine, harness)
        mine.write_text('{"entries": []}')
        self.assertEqual(self.nightly.pinned_plan(mine, harness), harness / 'nightly-cut.json')

    def test_the_launcher_re_execs_with_the_tools_repo(self):
        execs = []
        harness = self.dir / 'h' / 'runtime-e2e'; harness.mkdir(parents=True)
        with mock.patch.object(self.nightly, 'prepare_harness', lambda repo, commit, root: harness.parent), \
                mock.patch.object(self.nightly.os, 'execv', lambda exe, argv: execs.append(argv)), \
                mock.patch.object(self.nightly, 'cut_identity', lambda cut, commit: {}):
            try:
                self.nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', str(self.dir / 'e'),
                                        '--harness-commit', 'a' * 40, '--tools-repo', str(self.dir)])
            except Exception:
                pass
        self.assertTrue(execs)
        argv = execs[0]
        self.assertIn('--tools-repo', argv)
        self.assertEqual(argv[argv.index('--tools-repo') + 1], str(self.dir.resolve()))


# ------------------------------------------------------------------ V14-V17: controls, X-A2, X-A5, settings

class V14SeedControlsTest(unittest.TestCase):
    def test_every_seed_has_its_validity_control(self):
        names = set(xver.CONTROLS)
        for n in ('core-xver-ctl-me-old-same-a', 'core-xver-ctl-me-old-same-b', 'core-xver-ctl-me-old-same-c',
                  'core-xver-ctl-ae-old-same-a', 'core-xver-ctl-ae-old-same-c'):
            self.assertIn(n, names)
        self.assertEqual(xver.CONTROLS['core-xver-ctl-me-old-same-b']['seed'], 'B')


def a2(**over):
    base = {'stop_after': 1, 'before': {'status': 'INCOMPLETE'}, 'gate_after_partial': 'GENESIS',
            'partial': {'results': [[1, 'ACCEPTED']]}, 'order': ['same-id', 'new-id'],
            'new_id_core': {'exit': 1, 'out': 'CoreConfig 1 result 2\n'},
            'new_id_me': {'exit': 1, 'out': 'ME FRESH offered genesisId=9\nDRIVER FAIL no ClusterHeartbeat with meEpoch 9'},
            'same_id': {'exit': 0, 'out': 'CoreConfig 1 result 1\nGLOBAL OPEN (bound through the bridge)\n'}, 'gate_final': 'OPEN',
            'new_id': 9}
    base.update(over)
    return base


class V15XA2Test(unittest.TestCase):
    def test_the_partial_acks_the_order_and_the_me_driver_are_judged(self):
        self.assertEqual(xver.judge_a2(a2())['verdict'], 'PASS', xver.judge_a2(a2())['reasons'])
        self.assertEqual(xver.judge_a2(a2(partial={'results': [[1, 'REJECTED']]}))['verdict'], 'FAIL')
        self.assertEqual(xver.judge_a2(a2(order=['new-id', 'same-id']))['verdict'], 'FAIL')
        self.assertEqual(xver.judge_a2(a2(new_id_me={'exit': 0, 'out': 'EPOCH 9\n'}))['verdict'], 'FAIL')

    def test_k2_recovery_separates_finish_from_the_explicit_open(self):
        k2 = a2(stop_after=2, partial={'results': [[1, 'ACCEPTED'], [2, 'ACCEPTED']]},
                same_id={'exit': 1, 'out': 'CoreConfig 1 result 4\n'}, gate_final='GENESIS', bound_after_same_id=0,
                recovery={'finish': [[3, 'ACCEPTED']], 'bound': 7, 'gate_after_finish': 'GENESIS', 'gate_after_open': 'OPEN'})
        v = xver.judge_a2(k2)
        self.assertEqual(v['verdict'], 'PASS', v['reasons'])
        self.assertEqual(v['recovery'], 'finish bound the epoch (gate GENESIS); the explicit OPEN then opened [OPEN, ADMIN]')


class V16XA5ResyncTest(unittest.TestCase):
    def test_resync_0_after_the_bound_line_is_required(self):
        obs = {'wait_rows': [{'fwd0': [True, 503], 'fwd1': [True, 503]}] * 3, 'wait_s': 30,
               'epoch_waits': {'fwd0': 6, 'fwd1': 6}, 'bound_lines': {'fwd0': 1, 'fwd1': 1}, 'restarts': {'fwd0': 0, 'fwd1': 0},
               'ready_after_genesis': True, 'resync_after_bound': {'fwd0': 1, 'fwd1': 0}}
        self.assertIn('fwd1 logged no RESYNC(0) after "ME epoch bound"', xver.judge_a5(obs)['reasons'])
        self.assertEqual(xver.resync_after_bound('ME epoch bound: 7\nregistered (term 1, sourceEpoch 7): T1 head probe, then '
                                                 'RESYNC(0)\n'), 1)
        self.assertEqual(xver.resync_after_bound('registered: then RESYNC(0)\nME epoch bound: 7\n'), 0)


class V17SettingsTest(unittest.TestCase):
    def test_every_timing_size_is_a_setting(self):
        s = xver.settings({})
        for key in ('XVER_SERVE_HOLD_S', 'XVER_PROBE_ATTEMPT_S', 'XVER_PROBE_EXEC_S', 'XVER_PROBE_DRAIN_S',
                    'XVER_RECOVERY_READY_S', 'XVER_AE_QUIESCE_S', 'XVER_FINISH_BIND_S', 'XVER_BIND_WAIT_S',
                    'XVER_ENGINE_READY_S', 'XVER_DRIVER_S', 'XVER_ME_DRIVER_S', 'XVER_EPOCH_WAITS_MIN', 'XVER_RESTART_READY_S',
                    'XVER_FWD_READY_S', 'XVER_PROBE_MIN'):
            self.assertIn(key, s)
        with self.assertRaisesRegex(Violation, 'XVER_SAMPLE_S may only be raised'):
            xver.settings({'XVER_SAMPLE_S': '30'})
        import nightly
        self.assertEqual(nightly.Settings(lock='l', bound_s=1.0, after_interrupt='run', load_max=1.0,
                                          harness_commit='a' * 40).stop_grace_s, 180)


# ------------------------------------------------------------------ V1: X-R on the same roots

class V1SameRootsTest(unittest.TestCase):
    def test_the_cut_binds_its_members_to_the_restored_roots(self):
        import test_core_fixture as C
        with tempfile.TemporaryDirectory() as d:
            case = C.V4Base(); case.dir = d
            f = case.fx(roles=('probe',))
            l1 = Path(d) / 'l1' / 'state'
            for m in ('me0', 'ae0'):
                (l1 / m).mkdir(parents=True)
            f.bind_member_states(l1, members=('me0', 'ae0'))
            f.spawn('me0', ['java'], {})
            create = [c for c in case.docker.calls if c[:2] == ['docker', 'create']][-1]
            self.assertIn(f'type=bind,src={(l1 / "me0").resolve()},dst=/data', create)
            (l1 / 'ae0' / 'x').write_text('left')
            with self.assertRaisesRegex(Violation, 'not empty'):
                f.bind_member_states(l1, members=('ae0',))

    def test_the_forward_precheck_reads_the_projection_rows(self):
        f = types.SimpleNamespace()
        with mock.patch.object(r10_cut, 'projection_rows', lambda fx: {'money_journal_events': 3}):
            report = xver.forward_precheck(f, [Path('/nonexistent-root')])
        self.assertIn('projection database holds 3 row(s) in money_journal_events', report['refusals'])



# ------------------------------------------------------------------ W5 findings (coordinator 2026-11-04, rc2-cut-3)

class W5X1aEnvelopeTest(unittest.TestCase):
    def test_x1a_accepts_the_envelope_refusal_of_the_tag_snapshot(self):
        ms = [X.member(f'me{i}', 'CRITICAL: snapshot refused: snapshot envelope magic missing (length=120): refusing a bare or '
                                  'foreign snapshot image', start_s=5 * i, exit_s=5 * i + 0.2) for i in range(3)]
        v = judge('X-1a-emb', ms, covering(ms))
        self.assertEqual(v['verdict'], 'REFUSED', v['reasons'])


class W5PartialActivationTest(RecordBase):
    def test_an_audit_of_a_partial_step_accepts_slots_not_started_yet_and_still_refuses_foreign(self):
        m = T.audit_manifest(self.temp.name)
        listing = T.listing_for(m)
        listing['processes'] = [p for p in listing['processes'] if not p['role'].startswith('fwd')]
        self.assertEqual(r10_cut.audit_check(listing, m, aeron_version='1.53.1')['status'], 'REFUSED')
        report = r10_cut.audit_check(listing, m, aeron_version='1.53.1', not_started=('fwd0', 'fwd1'))
        self.assertEqual(report['status'], 'OK', report['findings'])
        self.assertEqual(sorted(report['not_started']), ['fwd0', 'fwd1'])
        listing['processes'].append({'role': 'assets-bridge', 'running': True, 'files': {}})
        self.assertEqual(r10_cut.audit_check(listing, m, aeron_version='1.53.1', not_started=('fwd0', 'fwd1'))['status'],
                         'REFUSED')

    def test_the_not_started_set_is_derived_from_the_steps_run(self):
        self.assertEqual(xver.not_started_by_steps(['snapshot_genesis', 'start_tap_witness', 'me_genesis', 'arm_money_journal',
                                                    'start_projector', 'start_bridges']), ('fwd0', 'fwd1'))
        self.assertEqual(xver.not_started_by_steps(['snapshot_genesis', 'start_tap_witness', 'me_genesis', 'arm_money_journal',
                                                    'start_projector']), ('bridge0', 'bridge1', 'fwd0', 'fwd1'))

    def test_a_partial_activation_reads_incomplete_not_refused(self):
        self.d.tap = self.d.tap[:1]
        Path(self.d.commands[0]['output']).write_text('CoreConfig 1 result 3\n')
        self.d.requests = [r for r in self.d.requests if not r['reply'].get('meEpoch')]
        self.d.audit = {'status': 'OK', 'findings': [], 'members_up': {'me': 3, 'ae': 3}, 'stopped': [],
                        'not_started': ['fwd0', 'fwd1']}
        del self.d.owner['boot']['phases']['core_bound_ns']
        self.d.write()
        rec = self.record()
        self.assertIn(rec['status'], ('INCOMPLETE', 'ABORTED'), rec['refusals'])


class W5T1MarketRowsTest(unittest.TestCase):
    T1 = ('m.next().marketId(d.marketId()).symbol(d.symbol()).baseAssetId(d.baseAsset().id())\n'
          '        .quoteAssetId(d.quoteAsset().id()).tickSize(1).minPrice(1).maxPrice(1_000_000_000_000_000L).lotSize(0);\n')

    def test_the_partial_genesis_sends_the_drivers_own_market_rows(self):
        import core_fixture
        rows = core_fixture.t1_market_rows(self.T1)
        self.assertEqual(rows, {'tick': 1, 'min': 1, 'max': 10 ** 15, 'lot': 0})     # W3 sent max 10**18: tables differ -> STALE
        with self.assertRaisesRegex(Violation, 'market rows'):
            core_fixture.t1_market_rows('no rows here')


class W5AeLogPositionsTest(unittest.TestCase):
    def test_list_members_output_is_noted_without_an_argument_clash(self):
        with tempfile.TemporaryDirectory() as d:
            text = 'memberId=0 leaderMemberId=0 activeMembers=[ClusterMember{id=0, logPosition=4096}, ClusterMember{id=1, ' \
                   'logPosition=4096}, ClusterMember{id=2, logPosition=4096}]'
            f = types.SimpleNamespace(engine_driver=lambda: 'embedded',
                                      execute=lambda role, argv, **kw: types.SimpleNamespace(
                                          stdout=text.replace('memberId=0', f'memberId={role[2]}'), stderr=''))
            self.assertEqual(xver._ae_log_positions(f, Path(d), bound_s=5), {'ae0': 4096, 'ae1': 4096, 'ae2': 4096})


class W5OmitControlTest(unittest.TestCase):
    def test_the_omit_control_drops_a_part_the_restore_needs(self):
        self.assertNotIn('core-rollback-ctl-omit-journal', xver.CONTROLS)
        self.assertEqual(xver.CONTROLS['core-rollback-ctl-omit-aestate']['omit'], 'ae-state')
        full = V9RollbackJudgeTest().full()
        d1 = json.loads(json.dumps(full)); d1['ae']['sha256'] = 'z'
        post = V9RollbackJudgeTest.POST
        self.assertEqual(xver.judge_rollback(full, d1, post, omitted='ae-state', smoke='PASS')['verdict'], 'PASS')
        self.assertEqual(xver.judge_rollback(full, full, post, omitted='ae-state', smoke='PASS')['verdict'], 'FAIL')


class W5RecordCliTest(RecordBase):
    def test_a_run_dir_whose_result_has_no_state_root_reads_it_from_the_manifest(self):
        (self.d.run / 'result.json').write_text(json.dumps({'status': 'PASS'}))
        (self.d.run / 'manifest.json').write_text(json.dumps(dict(self.d.manifest, state_root=str(self.d.state))))
        rec = self.record()
        self.assertEqual(rec['status'], 'OK', rec['refusals'])



class W5LateJoinerCatchUpTest(unittest.TestCase):
    """X-A4 live (W5 rerun): the followers' views are stale (-1 / 96) and the leader's advances under timers, so the late
    member's catch-up is judged in the leader's view against an earlier leader position."""
    LEADER = ('memberId=0 leaderMemberId=0 activeMembers=[ClusterMember{id=0, isBallotSent=false, isLeader=true, leadershipTermId=1, '
              'logPosition=%d, x=1}, ClusterMember{id=1, isBallotSent=false, isLeader=false, leadershipTermId=1, logPosition=%d, '
              'x=1}, ClusterMember{id=2, isBallotSent=false, isLeader=false, leadershipTermId=1, logPosition=%d, x=1}]')
    FOLLOWER = ('memberId=2 leaderMemberId=0 activeMembers=[ClusterMember{id=0, isBallotSent=false, isLeader=true, '
                'leadershipTermId=1, logPosition=-1, x=1}, ClusterMember{id=2, isBallotSent=false, isLeader=false, '
                'leadershipTermId=0, logPosition=96, x=1}]')

    def test_only_the_leaders_own_view_counts(self):
        self.assertIsNone(xver.leader_view(self.FOLLOWER))
        self.assertEqual(xver.leader_view(self.LEADER % (442208, 442208, 264096)), (0, {0: 442208, 1: 442208, 2: 264096}))

    def test_catch_up_against_an_earlier_leader_position(self):
        s1 = {'leader': 0, 'positions': {0: 442208, 1: 442208, 2: 264096}}
        s2 = {'leader': 0, 'positions': {0: 470000, 1: 470000, 2: 289632}}
        s3 = {'leader': 0, 'positions': {0: 495000, 1: 495000, 2: 471000}}
        self.assertFalse(xver.caught_up([s1, s2], 2)['caught_up'])
        self.assertTrue(xver.caught_up([s1, s2, s3], 2)['caught_up'])
        r5 = {'journal_seq': 1, 'me_epoch': 7}
        obs = {'record5': {'me0': r5, 'me1': dict(r5), 'me2': dict(r5)}, 'late_ready': {'me2': True, 'ae2': True},
               'ae_catch_up': {'caught_up': False}}
        self.assertIn('did not catch up', ' '.join(xver.judge_a4(obs)['reasons']))



# ------------------------------------------------------------------ W5 on rc2-cut-4: the final record after a recovery

class Cut4LateJoinerCoreIdTest(RecordBase):
    def test_a_member_that_has_not_applied_coreconfig_yet_does_not_make_the_id_unobservable(self):
        T.write_ae_member(self.d.state, 'ae2', [b'\0' * 40])           # the late joiner: no CoreConfig in its log yet
        rec = self.record()
        self.assertEqual(rec['core']['genesisId'], self.gid, rec['refusals'])
        self.assertEqual(rec['core']['read_from'], ['ae0', 'ae1'])
        self.assertEqual(rec['core']['not_applied'], ['ae2'])
        self.assertEqual(rec['status'], 'OK', rec['refusals'])

    def test_two_different_applied_ids_still_refuse_and_one_member_alone_is_not_enough(self):
        T.write_ae_member(self.d.state, 'ae1', [T.core_config_payload(v, self.gid + 2) for v in (1, 2, 3)])
        self.assertEqual(self.record()['status'], 'REFUSED')
        T.write_ae_member(self.d.state, 'ae1', [b'\0' * 40])
        T.write_ae_member(self.d.state, 'ae2', [b'\0' * 40])
        rec = self.record()
        self.assertEqual(rec['core']['genesisId'], 'not observable')     # a majority must hold the applied id


class Cut4RecordKindTest(RecordBase):
    def test_intermediate_records_stay_out_of_the_set(self):
        final = self.record()
        self.assertEqual(final['record_kind'], 'final')
        pre = r10_cut.activation_record(self.d.run, journal_schema=T.ME_JOURNAL, record_kind='intermediate')
        self.assertEqual(pre['record_kind'], 'intermediate')
        self.assertEqual(r10_cut.check_record_set([pre, final]), [])     # same run id by design, never a repeat
        r10_cut.write_activation_record(self.d.run, self.d.run / 'rc2-activation-record.before-recovery.json',
                                        journal_schema=T.ME_JOURNAL, record_kind='intermediate')
        r10_cut.write_activation_record(self.d.run, journal_schema=T.ME_JOURNAL)
        r10_cut.write_activation_record(self.d.run, self.d.run / 'rc2-activation-record.forward.json', journal_schema=T.ME_JOURNAL)
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = r10_cut.main(['activation-records', str(self.d.run)])
        listed = json.loads(out.getvalue())
        self.assertEqual(sorted(Path(p).name for p in listed['records']),
                         ['rc2-activation-record.forward.json', 'rc2-activation-record.json'])
        self.assertEqual(listed['skipped_intermediate'], [str(self.d.run / 'rc2-activation-record.before-recovery.json')])
        self.assertIn('repeats', ' '.join(listed['refusals']))           # two FINAL records of one run do repeat: refused


class Cut4CompleteAfterRecoveryTest(unittest.TestCase):
    def test_the_steps_after_a_recovery_complete_the_activation(self):
        self.assertEqual(xver.COMPLETE_STEPS, ['configure_risk', 'fund', 'verify_funded', 'start_forwarders'])
        f = types.SimpleNamespace(registry={'boot': {'phases': {}}}, save=lambda: None)
        calls = []
        moneys = iter([{'meEpoch': 0}, {'meEpoch': 7}])
        with mock.patch.object(xver, '_money', lambda fx: next(moneys)), \
                mock.patch.object(xver, '_steps', lambda fx, plan, steps: calls.append(list(steps))), \
                mock.patch.object(xver.time, 'sleep', lambda s: None):
            out = xver.complete_activation(f, {}, bound_s=10)
        self.assertTrue(out['bound'])
        self.assertIn('core_bound_ns', f.registry['boot']['phases'])
        self.assertEqual(calls, [xver.COMPLETE_STEPS])
        moneys = iter([{'meEpoch': 0}] * 50)
        with mock.patch.object(xver, '_money', lambda fx: next(moneys)), \
                mock.patch.object(xver, '_steps', lambda fx, plan, steps: calls.append(steps)), \
                mock.patch.object(xver.time, 'sleep', lambda s: None), mock.patch.object(xver.time, 'time', iter(range(0, 1000, 5)).__next__):
            self.assertFalse(xver.complete_activation(f, {}, bound_s=10)['bound'])


    def test_the_judges_require_the_final_record_ok_after_a_successful_recovery(self):
        done = {'steps': list(xver.COMPLETE_STEPS)}
        self.assertEqual(xver.judge_a2(a2(completion=done, record_after={'status': 'OK'}))['verdict'], 'PASS')
        v = xver.judge_a2(a2(completion=done, record_after={'status': 'INCOMPLETE', 'refusals': ['phase order']}))
        self.assertIn('the final record after the recovery reads INCOMPLETE', ' '.join(v['reasons']))
        r5 = {'journal_seq': 1}
        obs = {'record5': {'me0': r5, 'me1': dict(r5), 'me2': dict(r5)}, 'late_ready': {}, 'ae_catch_up': {'caught_up': True},
               'record': {'status': 'INCOMPLETE', 'refusals': ['core genesisId not observable']}}
        self.assertIn('the activation record reads INCOMPLETE', ' '.join(xver.judge_a4(obs)['reasons']))


if __name__ == '__main__':
    unittest.main()
