# SPDX-License-Identifier: Apache-2.0
"""The replica role in the fixture, its kinds, the port kinds of the netfilter helper, the drill tables, the lag
sampler and the alternate-night plan sets. No Docker: the fixture's docker calls are replaced by recorders."""
import copy
import datetime
import json
from pathlib import Path
import tempfile
import unittest

from contracts import Violation
import core_contracts
import core_drills
from core_fixture import CoreFixture
from credentials import KeyRing
import test_core_fixture

HERE = Path(__file__).resolve().parent
REPLICA_KINDS = ('shadow', 'shadow-ext', 'shadow-anyverified', 'shadow-anyverified-ext', 'shadow-cooldown30',
                 'shadow-detectoronly', 'shadow-query', 'shadow-query-ext')
SEVEN_KINDS = REPLICA_KINDS + ('full',)


def replica_manifest(directory, kind='shadow'):
    """A manifest of a replica kind: the base test manifest with the core jar staged as the shadow artifact."""
    m = test_core_fixture.manifest(directory)
    m['manifest_kind'] = kind
    m['artifacts']['shadow'] = dict(m['artifacts']['ae'], driver='external' if kind.endswith('-ext') else 'embedded')
    m['slot_artifacts']['shadow0'] = 'shadow'
    if kind.endswith('-ext'):
        m['engine_driver'] = 'external'
    return m


def bare_fixture(m, keyring=None):
    """A CoreFixture without __init__ (no state dir, no docker)."""
    f = CoreFixture.__new__(CoreFixture)
    f.m = m
    f.keys = keyring or KeyRing(replica=True)
    f.registry = {'containers': {}, 'fault_targets': {}}
    return f


class NamedRedTest(unittest.TestCase):
    """The three REDs the contract names for this row, each on the old signatures so it fails on its named assertion."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self):
        f = CoreFixture.__new__(CoreFixture)
        f.m = replica_manifest(self.dir)
        f.keys = KeyRing.__new__(KeyRing)
        f.keys.keys = {('shadow0', 'ae'): (41, 'REPLICA', 'ab' * 32)}
        f.registry = {'containers': {}, 'fault_targets': {}}
        f.spawn = lambda name, command, env=None: None
        f.wait_http = lambda *a, **k: {'status': 200}
        f.slot_row = lambda slot, name, register_driver=True: {'state': 'STARTED', 'artifact': name}
        return f

    def test_start_slot_starts_the_replica(self):
        self.assertEqual(self.fixture().start_slot('shadow0')['state'], 'STARTED')

    def test_ready_target_answers_for_the_replica(self):
        self.assertEqual(self.fixture().ready_target('shadow0')[1], '/ready')

    def test_the_ae_key_classes_include_the_replica(self):
        from credentials import AE_CLASSES
        self.assertIn('REPLICA', AE_CLASSES)


class ReplicaContractsTest(unittest.TestCase):
    def test_the_core_knows_the_replica_session_class(self):
        from credentials import AE_CLASSES
        self.assertIn('REPLICA', AE_CLASSES)

    def test_the_seven_kinds_are_cut_kinds_named_by_content(self):
        for kind in SEVEN_KINDS:
            self.assertIn(kind, core_contracts.CUT_KINDS)
            self.assertTrue(core_contracts.cut_derived(kind))
            self.assertNotRegex(kind, r'(?i)\b(rc\d|rcs|s9|pl\d|s-a0)')
        self.assertTrue(core_contracts.cut_derived('s17-ext'))
        self.assertFalse(core_contracts.cut_derived('s16'))
        self.assertEqual(set(core_contracts.REPLICA_KINDS), set(REPLICA_KINDS))

    def test_the_port_profile_names_the_replica_metrics_port(self):
        self.assertEqual(core_contracts.PORT_PROFILE['shadow_metrics'], 19703)

    def test_the_shadow_artifact_is_the_core_jar_on_the_engines_driver(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'shadow--r1.json'
            m = replica_manifest(temp)
            core_contracts.validate_core_manifest(m, path, cpu_count=24)
            bad = copy.deepcopy(m); bad['artifacts']['shadow'] = test_core_fixture.write(temp, 'other.jar', b'other')
            bad['artifacts']['shadow']['driver'] = 'embedded'
            with self.assertRaises(Violation) as caught:
                core_contracts.validate_core_manifest(bad, path, cpu_count=24)
            self.assertIn('the core jar', str(caught.exception))
            bad = copy.deepcopy(m); bad['artifacts']['shadow']['driver'] = 'external'
            with self.assertRaises(Violation) as caught:
                core_contracts.validate_core_manifest(bad, path, cpu_count=24)
            self.assertIn('engines', str(caught.exception))
            bad = copy.deepcopy(m); bad['slot_artifacts']['shadow0'] = None; bad['artifacts']['shadow'] = None
            with self.assertRaises(Violation) as caught:
                core_contracts.validate_core_manifest(bad, path, cpu_count=24)
            self.assertIn('runs the replica', str(caught.exception))


class ReplicaCredentialTest(unittest.TestCase):
    def test_the_replica_key_is_minted_only_when_the_manifest_runs_one(self):
        ring = KeyRing(replica=True)
        self.assertTrue(ring.credential('shadow0', 'ae').startswith('41:REPLICA:'))
        self.assertIn('REPLICA', {e.split(':')[1] for e in ring.table('ae').split(';')})
        self.assertEqual(ring.evidence()['reserved'], {})
        plain = KeyRing()
        self.assertNotIn('REPLICA', {e.split(':')[1] for e in plain.table('ae').split(';')})
        self.assertIn('shadow0', plain.evidence()['reserved'])
        with self.assertRaises(KeyError):
            plain.credential('shadow0', 'ae')


class ReplicaFixtureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_ready_target_names_the_replica_port(self):
        f = bare_fixture(replica_manifest(self.dir))
        self.assertEqual(f.ready_target('shadow0'), (19703, '/ready'))

    def test_start_slot_launches_the_replica_through_the_engines_wrapper_embedded(self):
        f = bare_fixture(replica_manifest(self.dir))
        calls = []
        f.spawn = lambda name, command, env=None: calls.append((name, command, env))
        f.wait_http = lambda *a, **k: {'status': 200}
        f.slot_row = lambda slot, name, register_driver=True: {'state': 'STARTED', 'artifact': name}
        row = f.start_slot('shadow0')
        self.assertEqual(row['state'], 'STARTED')
        name, command, env = calls[0]
        self.assertEqual(name, 'shadow0')
        self.assertEqual(command[0], 'java')
        self.assertEqual(command[-2:], ['-jar', '/artifacts/shadow/bin'])
        self.assertEqual(env['CORE_ROLE'], 'replica')
        self.assertEqual(env['CLUSTER_REPLICA_SLOT'], '3')
        self.assertEqual(env['CLUSTER_REPLICA_ADDRESS'], f.m['nodes']['shadow0'])
        self.assertEqual(env['CORE_NODE_PORT'], '19703')
        self.assertEqual(env['REPLICA_BACKUP_SOURCE'], 'FOLLOWER')
        self.assertEqual(env['REPLICA_CATCHUP_RCV_WND'], '512k')
        self.assertEqual(env['TRANSPORT_LOG_TERM_LENGTH'], '1m')
        self.assertEqual(env['REPLICA_SHADOW_BUFFER_MB'], '64')
        self.assertEqual(env['SHADOW_RETAIN_N'], '3')
        self.assertTrue(env['CORE_AUTH_CREDENTIAL'].startswith('41:REPLICA:'))
        nodes = f.m['nodes']
        self.assertEqual(env['SHADOW_PULL_SOURCES'], ','.join(f'{nodes[f"ae{i}"]}:{19300 + i * 100 + 1}' for i in range(3)))
        self.assertEqual(env['CLUSTER_ADDRESSES'], ','.join(nodes[f'ae{i}'] for i in range(3)))
        self.assertNotIn('TRANSPORT_LOG_RCV_WINDOW', env)
        self.assertEqual(env['TRANSPORT_DRIVER_MODE'], 'embedded')
        self.assertNotIn('AERON_DIR', env)
        core_contracts.assert_production_timeouts(env, f.allowed_env())

    def test_the_external_replica_runs_on_the_staged_aeronmd(self):
        m = replica_manifest(self.dir, 'shadow-ext')
        f = bare_fixture(m)
        command, env = f.replica_command(), f.replica_env()
        self.assertEqual(command[:2], ['sh', '-c'])
        self.assertIn('/artifacts/engine_libs/aeronmd', command[2])
        self.assertIn('rm -rf /dev/shm/aeron-shadow0', command[2])
        self.assertIn('/artifacts/shadow/bin', command[2])
        self.assertEqual((env['TRANSPORT_DRIVER_MODE'], env['AERON_DIR']), ('external', '/dev/shm/aeron-shadow0'))

    def test_the_reserved_slot_stays_reserved_without_a_replica(self):
        f = bare_fixture(test_core_fixture.manifest(self.dir), KeyRing())
        self.assertEqual(f.start_slot('shadow0')['state'], 'RESERVED')

    def test_engine_env_shadow_block_for_ae_members_only_without_a_window(self):
        for kind in REPLICA_KINDS:
            with self.subTest(kind=kind):
                f = bare_fixture(replica_manifest(self.dir, kind))
                nodes = f.m['nodes']
                for i in range(3):
                    env = f.engine_env('ae', i)
                    self.assertEqual(env['SNAPSHOT_MODE'], 'shadow')
                    self.assertEqual(env['SNAPSHOT_INTERVAL_MINUTES'], '1')
                    self.assertEqual(env['SHADOW_PRODUCER_BUFFER_MB'], '64')
                    self.assertEqual(env['SHADOW_WITNESS_ALARM_MS'], '120000')
                    peers = [f'{nodes[f"ae{j}"]}:{19300 + j * 100 + 1}' for j in range(3) if j != i]
                    self.assertEqual(env['SHADOW_PULL_SOURCES'].split(','), [f'{nodes["shadow0"]}:19601'] + peers)
                    self.assertNotIn('TRANSPORT_LOG_RCV_WINDOW', env)
                    self.assertEqual(env.get('SHADOW_ANCHOR_RULE'),
                                     'any-verified' if kind in ('shadow-anyverified', 'shadow-anyverified-ext',
                                                                'shadow-detectoronly') else None)
                    self.assertEqual(env['ARCHIVE_SEGMENT_LENGTH'], '1m')
                    core_contracts.assert_production_timeouts(env, f.allowed_env())
                me = f.engine_env('me', 0)
                for key in ('SNAPSHOT_MODE', 'SHADOW_PULL_SOURCES', 'SHADOW_ANCHOR_RULE'):
                    self.assertNotIn(key, me)
        f = bare_fixture(dict(test_core_fixture.manifest(self.dir), manifest_kind='full'), KeyRing())
        env = f.engine_env('ae', 0)
        self.assertNotIn('SNAPSHOT_MODE', env)
        self.assertEqual(env['SNAPSHOT_INTERVAL_MINUTES'], '1')
        self.assertEqual(env['ARCHIVE_SEGMENT_LENGTH'], '1m')
        # the older kinds keep the core's default segment length (measured on it)
        old = bare_fixture(dict(test_core_fixture.manifest(self.dir), manifest_kind='s17'), KeyRing()).engine_env('ae', 0)
        self.assertNotIn('ARCHIVE_SEGMENT_LENGTH', old)

    def test_the_control_kinds_carry_their_one_replica_setting(self):
        want = {'shadow-cooldown30': ('REPLICA_BACKUP_COOLDOWN_MS', '30000'),
                'shadow-detectoronly': ('SHADOW_REBOOTSTRAP_REPLAY_FAILURES', '0'),
                'shadow-query': ('REPLICA_BACKUP_QUERY_INTERVAL_MS', '13000')}
        for kind, (key, value) in want.items():
            env = bare_fixture(replica_manifest(self.dir, kind)).replica_env()
            self.assertEqual(env[key], value)
            self.assertEqual(env['ARCHIVE_SEGMENT_LENGTH'], '1m')
            for other, (okey, _) in want.items():
                if other != kind:
                    self.assertNotIn(okey, env)

    def test_wipe_engine_has_a_replica_branch_without_a_projection_dump(self):
        f = bare_fixture(replica_manifest(self.dir))
        f.root = Path(self.dir) / 'root'
        state = f.root / 'state' / 'shadow0'
        (state / 'state' / 'archive').mkdir(parents=True)
        (state / 'state' / 'archive' / '0-0.rec').write_bytes(b'abc')
        f.registry['containers']['shadow0'] = 'cid'
        f.inspect = lambda kind, cid: {'State': {'Running': False}}
        f.save = lambda: None
        witness = f.wipe_engine('shadow0')
        self.assertEqual(witness['bytes_removed'], 3)
        self.assertIn('replica', witness['projection_dump'])
        self.assertEqual(list(state.iterdir()), [])
        f.inspect = lambda kind, cid: {'State': {'Running': True}}
        with self.assertRaises(Violation):
            f.wipe_engine('shadow0')

    def test_a_replica_restart_after_a_kill_waits_for_its_archive_mark_file(self):
        f = bare_fixture(replica_manifest(self.dir))
        f.registry['containers']['shadow0'] = 'cid'
        now = [1000.0]
        f.clock = lambda: now[0]
        slept = []
        f.sleep = lambda s: (slept.append(s), now.__setitem__(0, now[0] + s))
        f.registry['last_kill'] = {'shadow0': {'at': 995.0}}
        f.inspect = lambda kind, cid: {'State': {'Running': False, 'ExitCode': 137, 'StartedAt': 'x'}}
        f.command = lambda argv, **k: None
        f.wait_http = lambda *a, **k: {'status': 200}
        f.save = lambda: None
        witness = f.restart('shadow0')
        self.assertEqual(slept, [core_contracts.SHADOW_RESTART_MIN_AFTER_KILL_S - 5.0])
        self.assertEqual(witness['waited_after_kill_s'], core_contracts.SHADOW_RESTART_MIN_AFTER_KILL_S)

    def test_the_replica_is_a_polite_stop_target(self):
        import core_fixture
        self.assertEqual(core_fixture.role_kind('shadow0'), 'replica')
        self.assertIn('replica', core_fixture.STOP_BOUND_S)

    def test_the_barrier_scrape_reads_the_replica_on_its_own_port(self):
        import core_scenarios
        f = bare_fixture(replica_manifest(self.dir))
        f.slots = {'shadow0': {'state': 'STARTED'}}
        seen = []

        def metrics(role, port):
            seen.append((role, port))
            return {'shadow_replica_applied_position': 5.0, 'core_x': 1.0} if role == 'shadow0' else {}
        f.metrics = metrics
        scrape = core_scenarios.barrier_scrape(f)
        self.assertIn(('shadow0', 19703), seen)
        self.assertEqual(scrape['shadow0'], {'shadow_replica_applied_position': 5.0})

    def test_the_archive_listing_reads_the_log_start_from_the_segment_files(self):
        import struct
        import core_fixture
        root = Path(self.dir)
        base = root / 'state' / 'ae2' / 'state'
        (base / 'cluster').mkdir(parents=True); (base / 'archive').mkdir()
        entry = struct.pack('<qqqqqii', 7, 0, 0, 0, 0, -1, 0).ljust(64, b'\0')   # TERM, recording 7, one 64-byte entry
        (base / 'cluster' / 'recording.log').write_bytes(entry)
        for b in (2097152, 1048576, 3145728):
            (base / 'archive' / f'7-{b}.rec').write_bytes(b'x')
        (base / 'archive' / '9-0.rec').write_bytes(b'y')                     # a shadow recording, not the log
        # no catalog: the segment length is unknown, so contiguity is not claimed
        unknown = core_fixture.archive_listing(root, 'ae2')
        self.assertFalse(unknown['contiguous'])
        self.assertIsNone(unknown['segment_length'])
        self.assertIn('not in archive.catalog', unknown['error'])

        def descriptor(rid, segment, stream, state=1):
            body = struct.pack('<qqqqqqqiiiiii', 0, 0, rid, 0, 0, 0, -1, 0, segment, 1048576, 8192, 5, stream)
            body += b'\0' * 8                                               # the empty var-length strings
            return (struct.pack('<iiq', len(body), state, 0).ljust(32, b'\0') + body).ljust(128, b'\0')   # aligned to the header's 64
        header = struct.pack('<iiqi', 196864, 32, 10, 64).ljust(32, b'\0')
        (base / 'archive' / 'archive.catalog').write_bytes(
            header + descriptor(9, 4194304, 4101) + descriptor(7, 1048576, 100) + b'\0' * 256)
        self.assertEqual(core_fixture.catalog_descriptors(base / 'archive')[7],
                         {'state': 1, 'start': 0, 'stop': -1, 'segment_length': 1048576, 'term_length': 1048576,
                          'stream': 100})
        listing = core_fixture.archive_listing(root, 'ae2')
        self.assertEqual(listing['log_recording'], 7)
        self.assertEqual(listing['log_start_segment'], 1048576)
        self.assertEqual(listing['segment_length'], 1048576)                # from the descriptor, not a constant
        self.assertTrue(listing['contiguous'])
        (base / 'archive' / '7-2097152.rec').unlink()
        self.assertFalse(core_fixture.archive_listing(root, 'ae2')['contiguous'])
        # a 64 MiB descriptor makes the same 1 MiB bases non-contiguous (the old silent assumption)
        (base / 'archive' / '7-2097152.rec').write_bytes(b'x')
        (base / 'archive' / 'archive.catalog').write_bytes(header + descriptor(7, 67108864, 100) + b'\0' * 256)
        self.assertFalse(core_fixture.archive_listing(root, 'ae2')['contiguous'])


class PortKindTest(unittest.TestCase):
    def test_filter_arguments_names_a_port_kind(self):
        from log_channel_fault import filter_arguments
        m = {'ports': dict(core_contracts.PORT_PROFILE)}
        self.assertIn('19601', filter_arguments(m, 'shadow0', 'add', port_kind='archive'))
        args = filter_arguments(m, 'ae0', 'add', port_kind='archive')
        self.assertIn('19301', args)
        self.assertEqual(args[args.index('-i') - 1:args.index('-i') + 2], ['!', '-i', 'lo'])
        self.assertEqual(filter_arguments(m, 'ae1', 'add'), filter_arguments(m, 'ae1', 'add', port_kind='log'))
        with self.assertRaises(Violation):
            filter_arguments(m, 'shadow0', 'add', port_kind='log')
        with self.assertRaises(Violation):
            filter_arguments(m, 'ae0', 'add', port_kind='19301')


class DrillTableTest(unittest.TestCase):
    DRILLS = ('member-kill9', 'peerloss', 'peerloss-loud', 'shadow-catalog', 'supplierloss', 'leaderloss-promotion',
              'replica-restart', 'replica-wipe', 'replica-rebootstrap')
    CONTROLS = ('kill9-fullmode', 'peerloss-loud-unblocked', 'supplierloss-cooldown30', 'rebootstrap-detectoronly',
                'rebootstrap-nowitness')

    def test_the_drills_and_controls_parse(self):
        import core_drills
        import nightly
        for name in self.DRILLS:
            self.assertTrue(name in core_drills.DRILLS, name)
            self.assertTrue(nightly.scenario_known('core-drill-' + name))
        for name in self.CONTROLS:
            self.assertTrue(name in core_drills.CONTROLS, name)
            self.assertTrue(nightly.scenario_known('core-control-' + name))

    def test_the_replica_settings_are_settings_with_ranges(self):
        import replica_drills
        s = replica_drills.settings({})
        self.assertEqual((s['CATALOG_ALIGNED_BOUND_S'], s['SUPPLIER_LOSS_RECOVERY_BOUND_S'], s['MEMBER_RESTART_READY_BOUND_S'],
                          s['REPLICA_RESTART_READY_BOUND_S'], s['PEERLOSS_PULLS_BEFORE_KILL'], s['PROMOTION_ATTEMPTS']),
                         (5, 30, 30, 60, 2, 3))
        self.assertEqual(replica_drills.settings({'CATALOG_ALIGNED_BOUND_S': '7'})['CATALOG_ALIGNED_BOUND_S'], 7)
        with self.assertRaises(Violation) as caught:
            replica_drills.settings({'CATALOG_ALIGNED_BOUND_S': '0'})
        self.assertIn('CATALOG_ALIGNED_BOUND_S', str(caught.exception))


class PlanSetTest(unittest.TestCase):
    def test_both_plan_files_parse(self):
        import nightly
        embedded = nightly.parse_plan(json.loads((HERE / 'nightly-cut-embedded.json').read_text()))
        external = nightly.parse_plan(json.loads((HERE / 'nightly-cut-external.json').read_text()))
        base = nightly.parse_plan(json.loads((HERE / 'nightly-cut.json').read_text()))
        self.assertEqual(embedded[:len(base)], base)
        self.assertTrue(all(not e['kind'].endswith('-ext') for e in embedded[len(base):]))
        external_drills = {e['scenario'] for e in external if e['kind'].endswith('-ext')}
        embedded_drills = {e['scenario'] for e in embedded[len(base):]} | {
            e['scenario'] for e in external if e['scenario'].startswith('core-drill-') and not e['kind'].endswith('-ext')}
        # every drill runs in both driver modes every 48 h, once each
        every = {'core-drill-' + d for d in DrillTableTest.DRILLS}
        self.assertEqual(external_drills, every)
        self.assertEqual(embedded_drills, every)
        drill_rows = [e for e in embedded + external if e['scenario'].startswith('core-drill-') and e['kind'] in
                      core_contracts.REPLICA_KINDS]
        self.assertEqual(len(drill_rows), 2 * len(every))
        # the catalog and leader loss on the 13 s query kinds, re-bootstrap on the any-verified kinds, in both modes
        for scenario, kinds in (('core-drill-shadow-catalog', {'shadow-query', 'shadow-query-ext'}),
                                ('core-drill-leaderloss-promotion', {'shadow-query', 'shadow-query-ext'}),
                                ('core-drill-replica-rebootstrap', {'shadow-anyverified', 'shadow-anyverified-ext'})):
            self.assertEqual({e['kind'] for e in drill_rows if e['scenario'] == scenario}, kinds)
        self.assertEqual(sorted(e['scenario'] for e in external if e['scenario'].startswith('core-control-')),
                         sorted('core-control-' + c for c in DrillTableTest.CONTROLS))
        for e in embedded[len(base):] + external:
            spec = core_drills.DRILLS[e['scenario'][len('core-drill-'):]] if e['scenario'].startswith('core-drill-') \
                else None
            if spec:
                self.assertIn(e['kind'], spec['kinds'], e)

    def test_alternate_chooses_by_day_of_year_parity_and_can_be_forced(self):
        import nightly
        a, b = Path('/plans/e.json'), Path('/plans/x.json')
        day = datetime.date(2026, 1, 2)                    # day of year 2: even
        self.assertEqual(nightly.choose_plan_set((a, b), day, None), (a, 'embedded', 0))
        self.assertEqual(nightly.choose_plan_set((a, b), day + datetime.timedelta(days=1), None), (b, 'external', 1))
        self.assertEqual(nightly.choose_plan_set((a, b), day, 'external'), (b, 'external', 0))
        with self.assertRaises(Violation):
            nightly.choose_plan_set((a, b), day, 'both')


if __name__ == '__main__':
    unittest.main()
