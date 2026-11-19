# SPDX-License-Identifier: Apache-2.0
"""The drills follow the cluster-kit of the cut: the rejoin watchdog that a newer kit gates during a genuine quorum loss
(the kit-default control's expected outcome and the peer-loss rejoin-wait override), and the member that a newer kit
lets exit loudly when it is stranded below the leader's log start (kill9-fullmode). No Docker."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

from contracts import Inconclusive, ProductDefect, Violation
import core_contracts
import core_drills
import replica_drills as rd
import test_replica_fixture

S = rd.settings({})
OLD_KIT = '0.1.23-runtime.20261118.rejoin.g8a6fb55'
NEW_KIT = '0.1.24-runtime.20261120.quorumgate.g1234abc'


def jar_with_pin(path, pin):
    with zipfile.ZipFile(path, 'w') as jar:
        jar.writestr('META-INF/maven/com.openexchange/cluster-kit/pom.properties',
                     f'artifactId=cluster-kit\ngroupId=com.openexchange\nversion={pin}\n')
    return str(path)


def fixture(temp, kind, pin):
    m = test_replica_fixture.replica_manifest(temp, kind)
    m['artifacts']['ae']['path'] = jar_with_pin(Path(temp) / f'ae-{abs(hash(pin))}.jar', pin) if pin else \
        str(Path(temp) / 'none.jar')
    m['artifacts']['shadow']['path'] = m['artifacts']['ae']['path']
    f = test_replica_fixture.bare_fixture(m)
    f.clock, f.sleep = (lambda: 0.0), (lambda s: None)
    return f


class KitVersionTest(unittest.TestCase):
    def test_only_a_kit_newer_than_the_rejoin_kit_gates_the_watchdog(self):
        self.assertFalse(core_contracts.kit_watchdog_gated(OLD_KIT))
        self.assertFalse(core_contracts.kit_watchdog_gated('0.1.22-runtime.20261116.buildid.gbd9f208'))
        self.assertFalse(core_contracts.kit_watchdog_gated('0.1.9-runtime.20261025.r03b'))
        self.assertTrue(core_contracts.kit_watchdog_gated(NEW_KIT))
        self.assertTrue(core_contracts.kit_watchdog_gated('0.2.0'))
        self.assertTrue(core_contracts.kit_watchdog_gated('0.1.100-runtime.20270101.x.g0000000'))
        for bad in (None, '', 'latest', '0.1', 'v0.1.24'):
            with self.assertRaises(Inconclusive, msg=bad):
                core_contracts.kit_watchdog_gated(bad)

    def test_a_rebuild_on_the_same_version_is_ordered_by_its_build_date(self):
        # the repo has shipped two pins on one X.Y.Z before: a later runtime build of 0.1.23 is newer than the pin
        self.assertTrue(core_contracts.kit_watchdog_gated('0.1.23-runtime.20261120.gate.gabc1234'))
        self.assertTrue(core_contracts.kit_watchdog_gated('0.1.23-runtime.20261121.other.gabcdef0'))
        self.assertFalse(core_contracts.kit_watchdog_gated('0.1.23-runtime.20261117.older.g0000000'))
        # same version and same build date but another build, or no build date at all: the order is unknown
        for ambiguous in ('0.1.23-runtime.20261118.other.g0000000', '0.1.23', '0.1.23-SNAPSHOT'):
            with self.assertRaisesRegex(Inconclusive, 'cannot order', msg=ambiguous):
                core_contracts.kit_watchdog_gated(ambiguous)


class RejoinWaitOverrideTest(unittest.TestCase):
    def test_the_override_applies_only_on_a_kit_that_does_not_gate(self):
        self.assertEqual(rd.rejoin_wait_env('peerloss_loud', {}, {}, watchdog_gated=False),
                         {'ENGINE_REJOIN_WAIT_MS': '330000'})
        self.assertEqual(rd.rejoin_wait_env('peerloss_loud', {}, {}, watchdog_gated=True), {})
        self.assertEqual(rd.rejoin_wait_env('peerloss', {}, {'REPLICA_MEMBER_REJOIN_WAIT_MS': '400000'},
                                            watchdog_gated=True), {})

    def test_the_drill_reads_the_kit_from_the_cut_jar_and_records_which_wait_applied(self):
        with tempfile.TemporaryDirectory() as temp:
            old = rd.ReplicaDrillRun(fixture(temp, 'shadow', OLD_KIT), 'peerloss-loud', Path(temp) / 'a')
            self.assertEqual(old.f.member_rejoin_wait_env, {'ENGINE_REJOIN_WAIT_MS': '330000'})
            self.assertEqual(old.rw['kit'], {'pin': OLD_KIT, 'watchdog_gated': False})
            self.assertIn('applied', old.rw['rejoin_wait_override'])
            new = rd.ReplicaDrillRun(fixture(temp, 'shadow', NEW_KIT), 'peerloss-loud', Path(temp) / 'b')
            self.assertEqual(new.f.member_rejoin_wait_env, {})
            self.assertEqual(new.rw['kit'], {'pin': NEW_KIT, 'watchdog_gated': True})
            self.assertIn('not applied', new.rw['rejoin_wait_override'])
            # a drill outside the peer-loss steps does not read the kit
            other = rd.ReplicaDrillRun(fixture(temp, 'shadow', None), 'replica-restart', Path(temp) / 'c')
            self.assertNotIn('kit', other.rw)
            # a peer-loss drill on a jar without a readable pin refuses to start
            with self.assertRaisesRegex(Inconclusive, 'cluster-kit pin'):
                rd.ReplicaDrillRun(fixture(temp, 'shadow', None), 'peerloss', Path(temp) / 'd')


class KitWaitControlTest(unittest.TestCase):
    WATCHDOG = ('2026-11-19T03:14:19Z [ERROR] RejoinWatchdog - CRITICAL rejoin watchdog: election 2 open for 60004 ms '
                'without a leader (state CANVASS), exiting 1')
    CYCLES = {'holds': True, 'detail': '3 fault rows opened (3 healed), the drill defines 3'}

    def lines(self, running):
        state = {'running': True} if running else {'running': False, 'exit_code': 1, 'watchdog': self.WATCHDOG}
        return {'survivor_outlasts_quorum_loss': rd.line_survivor_outlasts_quorum_loss(
            {'peerloss': {'survivor': 'ae1', 'rejoin_wait_ms': 60000, 'survivor_state': state}}),
            'fault_cycles': self.CYCLES}

    def test_the_expected_outcome_follows_the_kit(self):
        ok = {'status': 'PASS'}
        control = 'peerloss-loud-unblocked-kitwait'
        old = rd.control_expect(control, {'pin': OLD_KIT, 'watchdog_gated': False})
        new = rd.control_expect(control, {'pin': NEW_KIT, 'watchdog_gated': True})
        self.assertEqual(old, core_drills.REPLICA_CONTROL_EXPECT[control])
        self.assertEqual(new, {'fail': {}, 'hold': ['survivor_outlasts_quorum_loss']})
        # 0.1.23: the watchdog exit is the pinned outcome, an outlasting survivor is not
        self.assertEqual(rd.replica_control_verdict(ok, ok, self.lines(False), control, old)['status'], 'PASS')
        self.assertEqual(rd.replica_control_verdict(ok, ok, self.lines(True), control, old)['status'], 'FAIL')
        # a newer kit: the survivor outlasts the quorum loss on the kit default, a watchdog exit is the FAIL
        self.assertEqual(rd.replica_control_verdict(ok, ok, self.lines(True), control, new)['status'], 'PASS')
        self.assertEqual(rd.replica_control_verdict(ok, ok, self.lines(False), control, new)['status'], 'FAIL')
        # every other control keeps its table entry whatever the kit
        self.assertEqual(rd.control_expect('kill9-fullmode', {'watchdog_gated': True}),
                         core_drills.REPLICA_CONTROL_EXPECT['kill9-fullmode'])

    def test_the_control_names_its_lines_from_the_kit(self):
        with tempfile.TemporaryDirectory() as temp:
            variant = {'kind': 'shadow', 'kinds': ['shadow', 'shadow-ext'], 'unblocked': True, 'rejoin_wait': 'kit',
                       'control': 'peerloss-loud-unblocked-kitwait'}
            new = rd.ReplicaDrillRun(fixture(temp, 'shadow', NEW_KIT), 'peerloss-loud', Path(temp) / 'a', variant=variant)
            self.assertEqual(new.spec['lines'], ['survivor_outlasts_quorum_loss'])
            self.assertEqual(new.expect['hold'], ['survivor_outlasts_quorum_loss'])
            old = rd.ReplicaDrillRun(fixture(temp, 'shadow', OLD_KIT), 'peerloss-loud', Path(temp) / 'b', variant=variant)
            self.assertEqual(old.expect['fail'], {'survivor_outlasts_quorum_loss': 'rejoin watchdog'})
            self.assertEqual(old.f.member_rejoin_wait_env, {})

    def scripted(self, gated, kit_wait=True, wait_ms=None):
        events = []

        def restart_role(row, ready_timeout=None):
            events.append(('restart', row['target']))
            return {}, 1.0
        f = SimpleNamespace(engine_env=lambda engine, i: {'ENGINE_REJOIN_WAIT_MS': wait_ms} if wait_ms else {},
                            wipe_shadows=lambda role: {'files': 2}, archive_endpoint=lambda role: role, root=None)
        variant = {'unblocked': True, 'rejoin_wait': 'kit'} if kit_wait else {'unblocked': True}
        run = SimpleNamespace(
            variant=variant, s=S, f=f, rw={}, kit={'pin': NEW_KIT if gated else OLD_KIT, 'watchdog_gated': gated},
            peer_roles=lambda both_followers=False: ('ae0', 'ae2', 'ae1'),
            need=lambda *a: {'log_start_segment': 3}, try_read=lambda read: None, mm=lambda role: None,
            kill_role=lambda role: {'target': role}, restart_role=restart_role,
            survivor_state=lambda role: {'running': True, 'exit_code': None},
            watch_loud_start=lambda target, x: None,
            peerloss_kit_wait=lambda *a: events.append(('kit_wait',)))
        run.survivor_exit = lambda survivor, x, gated=False: rd.ReplicaDrillRun.survivor_exit(run, survivor, x, gated)
        return run, events

    def test_on_a_gating_kit_the_control_runs_the_quorum_loss_on_the_kit_wait(self):
        run, events = self.scripted(gated=True)
        rd.ReplicaDrillRun.replica_peerloss_loud(run)        # 60000 ms is below the bound: no refusal on this kit
        self.assertNotIn(('kit_wait',), events)
        self.assertIn(('restart', 'ae2'), events)
        x = run.rw['peerloss']
        self.assertEqual((x['rejoin_wait_ms'], x['watchdog_gated']), (60000, True))
        self.assertIn('outlasts', x['expected'])
        self.assertEqual(rd.line_survivor_outlasts_quorum_loss(run.rw)['holds'], True)
        # the drill (not the control) on a gating kit also runs without the override and without the refusal
        run, events = self.scripted(gated=True, kit_wait=False)
        rd.ReplicaDrillRun.replica_peerloss_loud(run)
        self.assertNotIn('expected', run.rw['peerloss'])

    def test_on_the_rejoin_kit_the_control_keeps_the_watchdog_exit(self):
        run, events = self.scripted(gated=False)
        rd.ReplicaDrillRun.replica_peerloss_loud(run)
        self.assertEqual(events, [('kit_wait',)])
        self.assertIn('exits 1 on the rejoin watchdog', run.rw['peerloss']['expected'])
        run, events = self.scripted(gated=False, kit_wait=False, wait_ms='60000')
        with self.assertRaisesRegex(Violation, 'lone survivor would exit 1'):
            rd.ReplicaDrillRun.replica_peerloss_loud(run)

    def test_on_a_gating_kit_a_survivor_watchdog_exit_is_a_product_defect(self):
        exited = {'running': False, 'exit_code': 1, 'watchdog': self.WATCHDOG}
        for kit_wait in (True, False):
            run, _ = self.scripted(gated=True, kit_wait=kit_wait)
            run.survivor_state = lambda role: dict(exited)
            with self.assertRaises(ProductDefect) as caught:
                rd.ReplicaDrillRun.replica_peerloss_loud(run)
            self.assertEqual(caught.exception.defect, rd.GATED_WATCHDOG_DEFECT)
            self.assertIn(NEW_KIT, str(caught.exception))
        # on the rejoin kit the same exit outside the control stays the survivor's INCONCLUSIVE
        run, _ = self.scripted(gated=False, kit_wait=False, wait_ms='400000')
        run.survivor_state = lambda role: dict(exited)
        with self.assertRaises(Inconclusive) as caught:
            rd.ReplicaDrillRun.replica_peerloss_loud(run)
        self.assertNotIsInstance(caught.exception, ProductDefect)
        # a gated survivor that exits on another FATAL is still named, not a watchdog defect
        run, _ = self.scripted(gated=True, kit_wait=False)
        run.survivor_state = lambda role: {'running': False, 'exit_code': 1, 'fatal': 'FATAL (exit 1): driver lost'}
        with self.assertRaisesRegex(Inconclusive, 'driver lost'):
            rd.ReplicaDrillRun.replica_peerloss_loud(run)


class LoudStrandTest(unittest.TestCase):
    """kill9-fullmode on a kit that holds retention for a down member: the member rejoins (PASS), or, when the kit wrote
    it off (its leader's STRANDED line, or a floor the members only report), it exits FATAL with the kit's catch-up
    watchdog lines (the expected loud failure). A loud exit the kit did not write off and a silent strand are product
    defects."""
    CRITICAL = ("2026-11-20T03:14:19Z Core node: CRITICAL catch-up watchdog: 3 catch-up attempt(s) in a row failed "
                "over 21004 ms: this member's log position 3092320 is below the log start position 3145728 of the "
                "leader (member 2). The leader no longer holds the log this member needs, so it can never catch up "
                "from the log and has to be reseeded (ENGINE_CATCHUP_REFUSALS 3, ENGINE_CATCHUP_REFUSAL_WAIT_MS "
                "30000 ms); exiting 1")
    FATAL = ("2026-11-20T03:14:19Z Core node FATAL (exit 1): member cannot catch up: its log position 3092320 is below "
             "the leader's log start position 3145728 (leader member 2) - node exiting, backstop in 5000 ms")
    WRITTEN_OFF = ('[RETENTION] CRITICAL: member 1 STRANDED: it has held the retention floor past the bound '
                   '(RETENTION_MEMBER_WAIT_MS 15000 ms, RETENTION_MEMBER_WAIT_BYTES 2147483648 bytes) and been written '
                   'off; the purge proceeds without it.')
    OTHER_WRITTEN_OFF = WRITTEN_OFF.replace('member 1 STRANDED', 'member 0 STRANDED')
    CATCHUP = 'TimeoutException: WARN - failed to join catchup log'
    REFUSAL = ('ArchiveException: ERROR - response for correlationId=917, error: requested replay start '
               'position=3092320 is less than recording start position=3145728 for recording 0')

    def test_the_kit_lines_are_recognised(self):
        for line in (self.CRITICAL, self.FATAL):
            found = core_contracts.loud_strand_of(line)
            self.assertEqual(found, {'position': 3092320, 'log_start': 3145728, 'leader_member': 2}, line)
        self.assertIsNone(core_contracts.loud_strand_of(self.CATCHUP))
        self.assertIsNone(core_contracts.loud_strand_of(
            "catch-up watchdog: 3 catch-up attempt(s) in a row failed over 1 ms; this member's log position 5 is not "
            "below the log start position 4 of the leader (member 2); not exiting, still trying to catch up"))
        self.assertTrue(core_contracts.written_off(self.WRITTEN_OFF, 1))
        self.assertFalse(core_contracts.written_off(self.OTHER_WRITTEN_OFF, 1))
        self.assertFalse(core_contracts.written_off(self.WRITTEN_OFF.replace('member 1 ', 'member 11 '), 1))

    def test_the_floor_arithmetic(self):
        bytes_, ms = core_contracts.RETENTION_MEMBER_WAIT_BYTES_DEFAULT, core_contracts.RETENTION_MEMBER_WAIT_MS_DEFAULT
        within = rd.retention_floor(3092320, 3327392, 20_000, bytes_, ms)
        self.assertFalse(within['exceeded'])
        self.assertEqual(within['lag_bytes'], 3327392 - 3092320)
        self.assertIn(f'lag {3327392 - 3092320} B <= {bytes_} B', within['arithmetic'])
        self.assertTrue(rd.retention_floor(0, 5 << 30, 20_000, bytes_, ms)['exceeded'])
        self.assertTrue(rd.retention_floor(3092320, 3327392, ms + 1, bytes_, ms)['exceeded'])
        self.assertTrue(rd.retention_floor(3092320, 3327392 + (1 << 20), 20_000, 1 << 20, ms)['exceeded'])
        unknown = rd.retention_floor(None, None, 20_000, bytes_, ms)
        self.assertFalse(unknown['exceeded'])
        self.assertIsNone(unknown['lag_bytes'])

    def test_the_floor_settings_are_the_kits_names_ranges_and_defaults(self):
        self.assertEqual(rd.retention_settings({}), {
            'floor': 'apply', 'member_wait_bytes': core_contracts.RETENTION_MEMBER_WAIT_BYTES_DEFAULT,
            'member_wait_ms': core_contracts.RETENTION_MEMBER_WAIT_MS_DEFAULT})
        self.assertEqual((core_contracts.RETENTION_MEMBER_WAIT_BYTES_DEFAULT,
                          core_contracts.RETENTION_MEMBER_WAIT_MS_DEFAULT), (2 << 30, 30 * 60 * 1000))
        self.assertEqual(rd.retention_settings({'RETENTION_MEMBER_WAIT_BYTES': '1048576',
                                                'RETENTION_MEMBER_WAIT_MS': '15000', 'RETENTION_FLOOR': 'report'}),
                         {'floor': 'report', 'member_wait_bytes': 1048576, 'member_wait_ms': 15000})
        for bad in ({'RETENTION_MEMBER_WAIT_BYTES': '1m'}, {'RETENTION_MEMBER_WAIT_BYTES': '1048575'},
                    {'RETENTION_MEMBER_WAIT_MS': '999'}, {'RETENTION_MEMBER_WAIT_MS': str(7 * 86400000 + 1)},
                    {'RETENTION_FLOOR': 'off'}):
            with self.assertRaises(Violation, msg=bad):
                rd.retention_settings(bad)

    def run_(self, member_running, logs, restart_fails=True, env=None, snapshot=3327392, down_s=20, exits_after=None):
        """``exits_after``: the member still runs at the readiness bound and exits loudly after that many polls."""
        calls = []
        polls = []

        def restart_role(row):
            calls.append(row['target'])
            if restart_fails:
                raise Inconclusive('fixture process ae1 exited 1 before readiness')
            return {'started_at': '2026-11-20T03:14:00Z', 'waited_after_kill_s': 1}, 5.0
        started_ns = core_drills._iso_ns('2026-11-20T03:14:00Z')

        def inspect(kind, cid):
            running = member_running
            if exits_after is not None and cid == 'c1':
                running = len(polls) < exits_after
            return {'State': {'Running': running, 'ExitCode': 0 if running else 1,
                              'StartedAt': '2026-11-20T03:14:00Z'}}

        def command(argv, check=False):
            cid = argv[-1]
            text = logs.get(cid, '')
            if exits_after is not None and cid == 'c1' and len(polls) >= exits_after:
                text += logs.get('c1-late', '')
            return SimpleNamespace(stdout=text, stderr='')
        f = SimpleNamespace(registry={'containers': {'ae0': 'c0', 'ae1': 'c1', 'ae2': 'c2', 'shadow0': 's0'}},
                            inspect=inspect, engine_env=lambda engine, i: dict(env or {}), command=command)

        def kill_role(role):
            row = {'target': role, 'opened_ns': started_ns - down_s * 10**9}
            return row

        def until(probe, bound_s, period_s=0.25):
            for _ in range(5):
                value = probe()
                if value:
                    return value, 1.0
                polls.append(1)
            return None, bound_s
        run = SimpleNamespace(need=lambda *a: 1, snapshot_position=lambda: 1, s=S, members=lambda: ['ae1'], f=f,
                              kill_role=kill_role, restart_role=restart_role, rw={}, leader=lambda: 'ae2',
                              try_read=lambda read: {'core_snapshot_last_log_position': snapshot},
                              mm=lambda role: None, until=until)
        for name in ('logs_of', 'stranded', 'loud_strand', 'strand_floor', 'strand_after_wait', 'judge_loud_strand'):
            setattr(run, name, (lambda n: lambda *a: getattr(rd.ReplicaDrillRun, n)(run, *a))(name))
        return run, calls

    def test_a_member_that_rejoins_passes_the_step(self):
        run, calls = self.run_(True, {}, restart_fails=False)
        with mock.patch.object(rd, 'gauge', lambda scrape, name, **k: 2):
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertEqual(run.rw['members_killed'], 3)
        self.assertNotIn('loud_strand', run.rw)

    def test_a_member_the_kit_wrote_off_is_the_expected_loud_failure(self):
        for line in (self.CRITICAL, self.FATAL):
            run, _ = self.run_(False, {'c1': line + '\n', 'c2': self.WRITTEN_OFF + '\n'})
            with self.assertRaises(Inconclusive) as caught:
                rd.ReplicaDrillRun.replica_member_kill9(run)
            self.assertNotIsInstance(caught.exception, ProductDefect)
            self.assertIn('expected loud failure', str(caught.exception))
            loud = run.rw['loud_strand']
            self.assertTrue(loud['floor']['exceeded'])
            self.assertEqual(loud['floor']['by'], 'written off')
            self.assertEqual(loud['floor']['written_off_by'], 'ae2')
            self.assertEqual((loud['position'], loud['log_start'], loud['leader_member']), (3092320, 3145728, 2))

    def test_a_floor_the_members_only_report_makes_the_loud_exit_expected(self):
        run, _ = self.run_(False, {'c1': self.FATAL + '\n'}, env={'RETENTION_FLOOR': 'report'})
        with self.assertRaisesRegex(Inconclusive, 'expected loud failure') as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertNotIsInstance(caught.exception, ProductDefect)
        self.assertEqual(run.rw['loud_strand']['floor']['by'], 'report')

    def test_a_loud_exit_the_kit_did_not_write_off_is_a_product_defect(self):
        # another member written off is not this member's
        run, _ = self.run_(False, {'c1': self.FATAL + '\n', 'c2': self.OTHER_WRITTEN_OFF + '\n'})
        with self.assertRaises(ProductDefect) as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertEqual(caught.exception.defect, rd.LOUD_STRAND_DEFECT)
        self.assertIn('did not write', str(caught.exception))
        self.assertFalse(run.rw['loud_strand']['floor']['exceeded'])
        self.assertIn('lag', run.rw['loud_strand']['floor']['arithmetic'])

    def test_a_bound_the_harness_sees_passed_without_the_kits_line_is_inconclusive(self):
        run, _ = self.run_(False, {'c1': self.FATAL + '\n'}, env={'RETENTION_MEMBER_WAIT_MS': '15000'}, down_s=20)
        with self.assertRaisesRegex(Inconclusive, 'no member logged a STRANDED line') as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertNotIsInstance(caught.exception, ProductDefect)

    def test_a_slow_loud_exit_is_not_read_as_a_silent_strand(self):
        logs = {'c1': self.CATCHUP + '\n', 'c1-late': self.FATAL + '\n', 'c2': self.REFUSAL + '\n' + self.WRITTEN_OFF}
        run, _ = self.run_(True, logs, exits_after=2)
        with self.assertRaisesRegex(Inconclusive, 'expected loud failure') as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertNotIsInstance(caught.exception, ProductDefect)
        self.assertNotIn('stranded', run.rw)

    def test_a_strand_that_exits_without_the_loud_line_stays_the_readiness_failure(self):
        logs = {'c1': self.CATCHUP + '\n', 'c1-late': 'Core node FATAL (exit 1): something else\n',
                'c2': self.REFUSAL + '\n'}
        run, _ = self.run_(True, logs, exits_after=2)
        with self.assertRaisesRegex(Inconclusive, 'exited 1 before readiness') as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertNotIsInstance(caught.exception, ProductDefect)
        self.assertIn('without the kit', run.rw['stranded']['loud_exit_wait'])

    def test_the_silent_strand_stays_a_product_defect(self):
        run, _ = self.run_(True, {'c1': self.CATCHUP + '\n', 'c2': self.REFUSAL + '\n'})
        with self.assertRaises(ProductDefect) as caught:
            rd.ReplicaDrillRun.replica_member_kill9(run)
        self.assertEqual(caught.exception.defect, rd.STRANDED_DEFECT)
        self.assertNotIn('loud_strand', run.rw)
        self.assertIn('still running', run.rw['stranded']['loud_exit_wait'])

    def test_an_exit_without_the_loud_line_stays_the_readiness_failure(self):
        run, _ = self.run_(False, {'c1': 'Core node FATAL (exit 1): something else\n'})
        with self.assertRaisesRegex(Inconclusive, 'exited 1 before readiness'):
            rd.ReplicaDrillRun.replica_member_kill9(run)


if __name__ == '__main__':
    unittest.main()
