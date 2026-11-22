# SPDX-License-Identifier: Apache-2.0
"""The gateway slots (gw0, gw1, st0, st1): contracts, credentials, fixture wiring, the cut checks, the gateway probe and
its oracle, the HTTP shim, the scenario registry and the dry-run decisions, the tap's replay after an election (no Docker)."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import assert_production_timeouts, validate_core_manifest
import core_fixture
from credentials import KeyRing
import gateway_drills
import gateway_probe
import gateway_shim
import release_cut
from test_core_fixture import fixture_for, slot_manifest, write


def gateway_manifest(directory, driver='external', slots=None, shim_mode='stored'):
    """A slot manifest with the four gateway roles and every gateway artifact pinned."""
    m = slot_manifest(directory, driver)
    for j, role in enumerate(sorted(core_contracts.GATEWAY_ROLES)):
        m['nodes'][role] = f'172.30.99.{40 + j}'
    m['ports'] = {**core_contracts.PORT_PROFILE, **core_contracts.GATEWAY_PORTS}
    libs = copy.deepcopy(m['artifacts']['forwarder']['libs']) if driver == 'external' else None
    for name, target in core_contracts.GATEWAY_TARGETS.items():
        entry = dict(write(directory, name + '.bin', b'elf-' + name.encode()), target=target,
                     driver='embedded' if name == 'gateway_stub' else driver)
        if libs and name != 'gateway_stub':
            entry['libs'] = copy.deepcopy(libs)
        if name == 'gateway_nc':
            entry['defines'] = ['GW_NC_FRESH_KEY']
        if name == 'gateway_stub':
            entry['mode'] = shim_mode
        m['artifacts'][name] = entry
    m['slot_artifacts'].update(slots or {'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'})
    return m


def gateway_fixture(directory, driver='external', slots=None, shim_mode='stored'):
    f = fixture_for(gateway_manifest(directory, driver, slots, shim_mode), directory)
    f.gateway_slots = True
    f.keys = KeyRing(gateway=True)
    f.secret_values = f.keys.secrets()
    return f


class GatewayContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'
        self.m = gateway_manifest(self.dir)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m):
        validate_core_manifest(m, self.path, cpu_count=24)

    def bad(self, edit, text):
        m = copy.deepcopy(self.m); edit(m)
        with self.assertRaises(Violation) as caught:
            self.check(m)
        self.assertIn(text, str(caught.exception))

    def test_a_gateway_manifest_passes_in_both_driver_modes(self):
        self.check(self.m)
        self.check(gateway_manifest(self.dir, 'embedded'))
        self.assertTrue(core_contracts.gateway_manifest(self.m))
        self.assertEqual(core_contracts.roles_of(self.m), core_contracts.ROLES | core_contracts.GATEWAY_ROLES)

    def test_the_gateway_roles_come_together_or_not_at_all(self):
        self.bad(lambda m: m['nodes'].pop('st1'), 'declared together')
        plain = slot_manifest(self.dir)
        self.assertFalse(core_contracts.gateway_manifest(plain))
        self.check(plain)                                   # negative control: an older manifest is unchanged

    def test_gateway_artifacts_are_refused_on_a_manifest_without_the_roles(self):
        m = slot_manifest(self.dir); m['artifacts']['gateway'] = self.m['artifacts']['gateway']
        with self.assertRaisesRegex(Violation, 'unknown artifacts: gateway'):
            self.check(m)

    def test_every_gateway_artifact_is_declared_and_the_ports_carry_the_gateway_block(self):
        self.bad(lambda m: m['artifacts'].pop('session_stub'), 'declares every gateway artifact explicitly')
        self.bad(lambda m: m.__setitem__('ports', dict(core_contracts.PORT_PROFILE)), 'port profile')

    def test_slots_run_only_their_artifacts(self):
        self.bad(lambda m: m['slot_artifacts'].update(st0='gateway'), 'slot st0 cannot run artifact gateway')
        self.bad(lambda m: m['slot_artifacts'].update(gw0='session_stub'), 'slot gw0 cannot run artifact session_stub')
        self.bad(lambda m: (m['artifacts'].__setitem__('stream', None)), 'slot st0 runs stream, but artifacts.stream is null')
        self.bad(lambda m: m['slot_artifacts'].pop('gw1'), 'slot_artifacts must name every slot role')

    def test_targets_defines_and_the_shim(self):
        self.bad(lambda m: m['artifacts']['gateway'].update(target='oe-stream'), 'target must be oe-gateway')
        self.bad(lambda m: m['artifacts']['gateway_nc'].update(defines=['GW_NC_BODY_USER']), 'control defines')
        self.bad(lambda m: m['artifacts']['gateway'].update(defines=['GW_NC_FRESH_KEY']), 'only gateway_nc carries')
        self.bad(lambda m: m['artifacts']['gateway_stub'].update(mode='other'), 'names its mode')
        self.bad(lambda m: m['artifacts']['gateway_stub'].update(driver='external'), 'driver embedded')
        self.bad(lambda m: m['artifacts']['stream'].pop('libs'), 'an external slot stages aeronmd')

    def test_core_jvm_properties_are_an_allowlist_of_positive_integers(self):
        m = copy.deepcopy(self.m); m['core_jvm_properties'] = {'core.egress.max.capacity.bytes': '262144'}
        self.check(m)
        self.bad(lambda m: m.__setitem__('core_jvm_properties', {'aeron.client.liveness.timeout': '1'}), 'allowlist')
        self.bad(lambda m: m.__setitem__('core_jvm_properties', {'core.egress.max.capacity.bytes': '0'}), 'positive integer')

    def test_gateway_kinds_are_cut_kinds_and_their_slots_are_legal(self):
        self.assertLessEqual(set(core_contracts.GATEWAY_KINDS), core_contracts.CUT_KINDS)
        for kind, spec in core_contracts.GATEWAY_KINDS.items():
            with self.subTest(kind=kind):
                self.assertEqual(set(spec['slots']), core_contracts.GATEWAY_ROLES)
                for slot, name in spec['slots'].items():
                    self.assertTrue(name is None or name in core_contracts.GATEWAY_SLOT_ARTIFACTS[slot])
                self.assertEqual('-ext' in kind, spec['driver'] == 'external')
                self.assertLessEqual(set(spec['core_jvm']), core_contracts.CORE_JVM_PROPERTIES)


class GatewayCredentialTest(unittest.TestCase):
    def test_each_gateway_holds_a_treasury_key_in_the_core_table(self):
        gw = KeyRing(gateway=True)
        for slot, key_id in (('gw0-treasury', 55), ('gw1-treasury', 56)):
            self.assertEqual(gw.keys[(slot, 'ae')][:2], (key_id, 'TREASURY'))
            self.assertIn(f'{key_id}:TREASURY:', gw.table('ae'))
        self.assertNotIn(('gw0-treasury', 'ae'), KeyRing().keys)

    def test_gateway_keys_only_for_a_gateway_manifest(self):
        plain, gw = KeyRing(), KeyRing(gateway=True)
        self.assertNotIn(('gw0', 'ae'), plain.keys)
        for slot, key_id in (('gw0', 51), ('gw1', 52), ('st0', 53), ('st1', 54)):
            self.assertEqual(gw.keys[(slot, 'ae')][:2], (key_id, 'GATEWAY'))
        self.assertIn('53:GATEWAY:', gw.table('ae'))
        self.assertTrue(all(entry.endswith('::users=*') for entry in gw.table('ae').split(';')))
        with self.assertRaisesRegex(ValueError, 'no user API key'):
            plain.api_keys([1])

    def test_api_keys_are_fixed_per_run_redacted_and_never_in_evidence(self):
        ring = KeyRing(gateway=True)
        keys = ring.api_keys([81002, 81001])
        self.assertEqual(ring.api_keys([81001]), {81001: keys[81001]})
        self.assertTrue(all(len(k) == 64 for k in keys.values()))
        self.assertEqual(ring.api_keys_file([81002, 81001]), f'{keys[81001]}:81001\n{keys[81002]}:81002\n')
        self.assertLessEqual(set(keys.values()), ring.secrets())
        evidence = json.dumps(ring.evidence())
        self.assertNotIn(keys[81001], evidence)
        self.assertEqual(ring.evidence()['api_key_users'], [81001, 81002])
        with self.assertRaises(ValueError):
            ring.api_keys([0])


class GatewayFixtureWiringTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_gateway_and_stream_env_in_both_modes_pass_the_guard(self):
        for driver in ('external', 'embedded'):
            f = gateway_fixture(self.dir, driver)
            gw, st = f.gateway_slot_env('gw0'), f.gateway_slot_env('st1')
            for env in (gw, st):
                assert_production_timeouts(env, f.allowed_env())
            self.assertEqual(gw['GATEWAY_DRIVER_MODE'], driver)
            self.assertEqual(gw['GATEWAY_HTTP_BIND'], '172.30.99.40:8080')
            self.assertEqual(gw['GATEWAY_ADMIN_BIND'], '172.30.99.40:8081')
            self.assertEqual(gw['GATEWAY_INSTANCE_ID'], '51')
            self.assertEqual(gw['CORE_AUTH_CREDENTIAL'], f.keys.credential('gw0', 'ae'))
            # the treasury lane: the gateway's switch, its TREASURY credential, the faucet caps (an unknown asset capped)
            self.assertEqual(gw['GATEWAY_ALLOW_TREASURY_LANE'], '1')
            self.assertEqual(gw['GATEWAY_TREASURY_CREDENTIAL'], f.keys.credential('gw0-treasury', 'ae'))
            self.assertTrue(gw['GATEWAY_TREASURY_CREDENTIAL'].startswith('55:TREASURY:'))
            self.assertIn(f'{f.GATEWAY_FUZZ_UNKNOWN_ASSET}:', gw['GATEWAY_FAUCET_MAX_AMOUNT'])
            self.assertNotIn('GATEWAY_ALLOW_TREASURY_LANE', st)
            self.assertIn('term-length=4m|mtu=8192', gw['GATEWAY_CORE_INGRESS_CHANNEL'])
            self.assertTrue(gw['GATEWAY_CORE_RESPONSE_CHANNEL'].startswith(
                    f'aeron:udp?endpoint=172.30.99.40:{core_fixture.CoreFixture.GATEWAY_RESPONSE_PORT}|'))
            self.assertEqual(gw['GATEWAY_PG_URL'], 'postgresql://runtime_fixture@172.30.99.1:55500/r01_gateway')
            self.assertEqual(st['STREAM_WS_BIND'], '172.30.99.43:8090')
            self.assertEqual(st['STREAM_INSTANCE_ID'], '54')
            self.assertNotIn('GATEWAY_PG_URL', st)        # api-key auth needs no users store on the stream
            self.assertEqual(st['STREAM_CORE_NODE_ENDPOINTS'].count('@'), 3)
            if driver == 'external':
                self.assertEqual((gw['AERON_DIR'], 'GATEWAY_DRIVER_DIR' in gw), ('/dev/shm/aeron-gw0', False))
            else:
                self.assertEqual((gw['GATEWAY_DRIVER_DIR'], 'AERON_DIR' in gw), ('/dev/shm', False))
            self.assertFalse(any(core_contracts.TIMEOUT_WORDS.search(k) for k in {**gw, **st}))

    def test_external_slot_attaches_to_its_sidecar_driver_embedded_execs_directly(self):
        f = gateway_fixture(self.dir, 'external')
        script = f.gateway_slot_command('gw0')[2]
        self.assertIn('/dev/shm/aeron-gw0/cnc.dat', script)
        self.assertNotIn('aeronmd', script)                    # the driver is not in the binary's container
        self.assertTrue(script.endswith('exec /artifacts/gateway/bin'))
        driver = f.gateway_driver_command('gw0')[2]
        self.assertIn('AERON_DIR=/dev/shm/aeron-gw0', driver)
        self.assertIn('AERON_DIR_DELETE_ON_START=1', driver)
        self.assertTrue(driver.endswith('exec /artifacts/gateway/aeronmd'))
        self.assertEqual([s for s in core_contracts.GATEWAY_SLOTS if f.driver_sidecar(s)], ['gw0', 'gw1', 'st0', 'st1'])
        self.assertEqual((f.sidecar_slot('st1-driver'), f.sidecar_slot('fwd0-driver'), f.sidecar_slot('gw0')), ('st1', None, None))
        f = gateway_fixture(self.dir, 'embedded')
        self.assertEqual(f.gateway_slot_command('st0'), ['sh', '-c', 'exec /artifacts/stream/bin'])
        self.assertFalse(f.driver_sidecar('st0'))
        # the session stub (a dry-run tool) keeps its staged driver in its own container
        f = gateway_fixture(self.dir, 'external', slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
        self.assertFalse(f.driver_sidecar('st0'))
        self.assertIn('/artifacts/session_stub/aeronmd', f.gateway_slot_command('st0')[2])

    def spawned(self, f):
        calls = []
        def command(argv, **kw):
            calls.append([str(a) for a in argv])
            return types.SimpleNamespace(stdout='cid-' + str(len(calls)) + '\n', stderr='', returncode=0)
        f.command = command
        f.inspect = lambda kind, rid: {'State': {'Running': True}}
        return calls

    def test_the_sidecar_holds_the_address_and_ipc_and_the_binary_joins_them(self):
        f = gateway_fixture(self.dir, 'external')
        calls = self.spawned(f)
        driver = f.spawn('gw0-driver', f.gateway_driver_command('gw0'))
        f.spawn('gw0', f.gateway_slot_command('gw0'), f.gateway_slot_env('gw0'), join=driver)
        create_driver, create_gw = [c for c in calls if c[:2] == ['docker', 'create']]
        def opt(argv, name):
            return argv[argv.index(name) + 1] if name in argv else None
        self.assertEqual((opt(create_driver, '--ip'), opt(create_driver, '--ipc'), opt(create_driver, '--network')),
                         ('172.30.99.40', 'shareable', 'net'))
        self.assertIsNotNone(opt(create_driver, '--shm-size'))
        self.assertEqual((opt(create_gw, '--network'), opt(create_gw, '--ipc')), ('container:' + driver, 'container:' + driver))
        self.assertEqual((opt(create_gw, '--ip'), opt(create_gw, '--shm-size')), (None, None))
        self.assertEqual(opt(create_driver, '--cpuset-cpus'), opt(create_gw, '--cpuset-cpus'))
        self.assertNotIn('/data', [m for m in create_gw if m.startswith('type=bind') and 'gw0-driver' in m])
        self.assertTrue(any('state/gw0-driver,dst=/data' in a for a in create_driver))      # its own /data
        self.assertTrue(any('state/gw0,dst=/data' in a for a in create_gw))
        with self.assertRaisesRegex(Violation, 'unknown or duplicate'):
            f.spawn('fwd0-driver', ['true'])

    def sidecar_fixture(self):
        f = gateway_fixture(self.dir, 'external')
        f.registry['containers'].update({'gw0': 'c-gw0', 'gw0-driver': 'c-drv'})
        state = {'c-gw0': {'Running': False, 'Paused': False, 'ExitCode': 137, 'StartedAt': 'G1', 'Pid': 0},
                 'c-drv': {'Running': True, 'Paused': False, 'ExitCode': 0, 'StartedAt': 'D1', 'Pid': 7}}
        f.inspect = lambda kind, rid: {'State': state[rid], 'RestartCount': 0}
        def command(argv, **kw):
            if argv[:2] == ['docker', 'start']:
                state[argv[2]].update(Running=True, StartedAt='G2')
            return types.SimpleNamespace(stdout='', stderr='', returncode=0)
        f.command = command
        f.execute = lambda name, argv, **kw: types.SimpleNamespace(
            stdout='S\n6 100.5\n' if name == 'gw0-driver' else 'main R\n', stderr='', returncode=0)
        f.wait_role_ready = lambda *a, **kw: {'status': 200}
        f.record_fault = lambda w: w
        f.clock = lambda: 0.0
        return f, state

    def test_a_restarted_slot_must_reuse_its_sidecar_driver(self):
        f, state = self.sidecar_fixture()
        f.registry['driver_identity'] = {'gw0': f.driver_identity('gw0')}
        self.assertEqual(f.driver_identity('gw0')['sidecar'], 'c-drv')
        witness = f.restart('gw0')
        self.assertEqual(witness['driver']['reused'], True)
        self.assertEqual(f.process_states('gw0'), {'main': 'R', 'driver': 'S', 'driver_sidecar': 'c-drv'})
        state['c-gw0']['Running'] = False
        state['c-drv']['StartedAt'] = 'D2'                    # the driver was restarted: another driver
        with self.assertRaisesRegex(Inconclusive, 'came back on another driver'):
            f.restart('gw0')
        state['c-drv']['Running'] = False
        self.assertEqual(f.slot_driver('gw0')['running'], False)

    def test_session_stub_reads_its_script_and_registers_the_stream_mask(self):
        for driver in ('external', 'embedded'):
            f = gateway_fixture(self.dir, driver, slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
            script = f.gateway_slot_command('st0')[2]
            self.assertIn('tail -n +1 -f /data/stub.cmd | /artifacts/session_stub/bin', script)
            args = f.stub_arguments('st0')
            self.assertEqual(args[args.index('--channels') + 1], 'acks,orders,balances,control')
            self.assertEqual(args[args.index('--instance-id') + 1], '53')
            self.assertIn('--aeron-dir' if driver == 'external' else '--driver-dir', args)
            self.assertFalse(any(core_contracts.JVM_TIMEOUT.search(a) for a in f.gateway_slot_command('st0')))
            self.assertEqual(f.gateway_slot_env('st0'), {'CORE_AUTH_CREDENTIAL': f.keys.credential('st0', 'ae')})
            self.assertEqual(f.ready_target('st0'), (None, 'log:registered'))

    def test_stub_commands_are_one_script_line(self):
        f = gateway_fixture(self.dir, 'embedded', slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
        f.record_fault = lambda w: w
        (f.root / 'state' / 'st0').mkdir(parents=True)
        f.stub_command('st0', 'throttle pause'); f.stub_command('st0', 'throttle 500 1')
        self.assertEqual((f.root / 'state/st0/stub.cmd').read_text(), 'throttle pause\nthrottle 500 1\n')
        for bad in ('quit\nthrottle off', 'offer DEADBEEF; rm', ''):
            with self.assertRaises(Violation):
                f.stub_command('st0', bad)
        with self.assertRaisesRegex(Violation, 'runs no session stub'):
            f.stub_command('st1', 'quit')

    def test_shim_slot(self):
        f = gateway_fixture(self.dir, 'embedded', slots={'gw0': 'gateway_stub', 'gw1': 'gateway_stub', 'st0': None,
                                                         'st1': None}, shim_mode='fresh-key')
        env = f.gateway_slot_env('gw1')
        assert_production_timeouts(env, f.allowed_env())
        self.assertEqual((env['SHIM_MODE'], env['SHIM_HTTP_BIND'], env['CORE_LOCAL_HOST']),
                         ('fresh-key', '172.30.99.41:8085', '172.30.99.41'))
        self.assertEqual(f.gateway_slot_command('gw0'), ['python3', '-I', '/artifacts/gateway_stub/bin'])
        self.assertEqual(f.ready_target('gw0'), (8085, '/ready'))

    def test_ready_targets_of_the_binaries_are_their_admin_binds(self):
        f = gateway_fixture(self.dir)
        self.assertEqual((f.ready_target('gw1'), f.ready_target('st0')), ((8081, '/ready'), (8091, '/ready')))

    def test_api_keys_file_is_written_into_the_slot_state_and_redacted(self):
        f = gateway_fixture(self.dir)
        f.gateway_user_ids = [81001, 81002]
        f.prepare_gateway_state('gw0')
        text = (f.root / 'state/gw0/api-keys').read_text()
        self.assertEqual(len(text.splitlines()), 2)
        self.assertEqual(oct((f.root / 'state/gw0/api-keys').stat().st_mode & 0o777), '0o600')
        key = text.split(':', 1)[0]
        self.assertIn(key, f.secret_values)
        self.assertEqual(f.registry['prepared_state']['gw0'], {'api_key_users': [81001, 81002]})

    def test_core_members_get_the_manifest_jvm_properties_and_the_me_does_not(self):
        f = gateway_fixture(self.dir, 'embedded')
        f.m['core_jvm_properties'] = {'core.egress.max.capacity.bytes': '262144'}
        self.assertIn('-Dcore.egress.max.capacity.bytes=262144', f.engine_command('ae', 1))
        self.assertNotIn('-Dcore.egress.max.capacity.bytes=262144', f.engine_command('me', 1))
        self.assertLess(f.engine_command('ae', 1).index('-Dcore.egress.max.capacity.bytes=262144'),
                        f.engine_command('ae', 1).index('-jar'))

    def test_the_gateway_database_is_a_fixture_database(self):
        f = gateway_fixture(self.dir)
        calls = []
        f.command = lambda argv, **kw: calls.append(argv) or types.SimpleNamespace(stdout='')
        f.pg = Path('/pg')
        f.create_gateway_database()
        sql = [c[-1] for c in calls]
        self.assertEqual(sql[0], 'CREATE DATABASE r01_gateway OWNER oe_gateway')
        # the console's grants on the database, its writers' default privileges for the retention role, and for oe-stream
        # SELECT on what oe-gateway creates
        self.assertIn('REVOKE CREATE ON SCHEMA public FROM PUBLIC', sql)
        self.assertIn('GRANT USAGE, CREATE ON SCHEMA public TO oe_gateway, oe_projector', sql)
        self.assertIn('ALTER DEFAULT PRIVILEGES FOR ROLE oe_projector GRANT DELETE, TRUNCATE ON TABLES TO history_retention', sql)
        self.assertIn('ALTER DEFAULT PRIVILEGES FOR ROLE oe_gateway GRANT SELECT ON TABLES TO oe_stream', sql)
        self.assertTrue(all(c[6] == 'runtime_fixture' for c in calls))
        with self.assertRaisesRegex(Violation, 'unknown fixture database'):
            f.psql('r01_oms', 'select 1')

    def test_parse_stub_line(self):
        row = core_fixture.parse_stub_line('2026-11-16T15:33:40.593883883Z event=state from=AWAIT_NEW_LEADER to=CLOSED '
                                           'close_reason=NEW_LEADER_TIMEOUT epoch=1 detail="no NewLeaderEvent within 2000 ms"')
        self.assertEqual((row['event'], row['to'], row['close_reason'], row['detail'], row['ts']),
                         ('state', 'CLOSED', 'NEW_LEADER_TIMEOUT', 'no NewLeaderEvent within 2000 ms',
                          '2026-11-16T15:33:40.593883883Z'))
        self.assertIsNone(core_fixture.parse_stub_line('ct_session_stub: embedded media driver at /dev/shm/x'))
        self.assertEqual(gateway_drills._ts_ns(row['ts']) % 1_000_000_000, 593883883)


class AllowedEnvCoversTheGatewaySlotsTest(unittest.TestCase):
    def test_every_gateway_env_name_the_fixture_sets_is_allowlisted_and_nothing_more(self):
        with tempfile.TemporaryDirectory() as d:
            names = set()
            for driver in ('external', 'embedded'):
                for slots in (None, {'gw0': 'gateway_stub', 'gw1': 'gateway_nc', 'st0': 'session_stub', 'st1': 'stream'}):
                    f = gateway_fixture(d, driver, slots)
                    for slot in core_contracts.GATEWAY_SLOTS:
                        names |= set(f.gateway_slot_env(slot))
                    # the freshness drill's two gateway history settings (gateway_env_overrides)
                    if f.slot_artifact('gw1') not in ('gateway_stub', 'session_stub'):
                        f.gateway_env_overrides = {'gw1': {'GATEWAY_HISTORY_STALE_MS': 3000, 'GATEWAY_HISTORY_PROBE_MS': 2000}}
                        names |= set(f.gateway_slot_env('gw1'))
            gateway_names = {n for n in core_contracts.PROCESS_ENV if n.startswith(('GATEWAY_', 'STREAM_', 'SHIM_'))}
            self.assertEqual({n for n in names if n.startswith(('GATEWAY_', 'STREAM_', 'SHIM_'))}, gateway_names)


class GatewayCutTest(unittest.TestCase):
    """rc2-cut/3 carries oe-gateway and oe-stream as product artifacts; the test-only gateway artifacts are checked
    against the cut's commits and refused in a product kind."""

    def setUp(self):
        import test_release_cut
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.w = test_release_cut.World(self.root / 'cut')
        patch = mock.patch.object(release_cut, 'git_blob', self.blob); patch.start(); self.addCleanup(patch.stop)
        self.shim = self.root / 'gateway_shim.py'; self.shim.write_bytes(b'shim bytes')

    def tearDown(self):
        self.temp.cleanup()

    def blob(self, repo, commit, rel):
        if repo == 'tools' and rel == release_cut.GATEWAY_SHIM and commit == self.w.m['harness_commit']:
            return self.shim.read_bytes()
        return self.w.blob(repo, commit, rel)

    def test_the_new_layout_carries_the_gateway(self):
        self.assertIn('gateway', release_cut.repos_of('rc2-cut/3'))
        self.assertNotIn('gateway', release_cut.repos_of('rc2-cut/2'))
        self.assertLessEqual({'oe-gateway', 'oe-stream'}, set(release_cut.product('rc2-cut/3')))
        self.assertNotIn('oe-gateway', release_cut.product('rc2-cut/2'))
        self.assertEqual(release_cut.check(self.w.m, old_pins=self.w.pins).items, [])

    def test_a_gateway_binary_of_another_commit_or_without_the_money_schema_is_refused(self):
        entry = self.w.m['artifacts']['oe-gateway']
        Path(entry['path']).chmod(0o644)
        Path(entry['path']).write_bytes(b'ELF oe-gateway ' + b'0' * 40 + b' ' + self.w.m['schemas']['money'].encode())
        m = copy.deepcopy(self.w.m); m['artifacts']['oe-gateway']['sha256'] = hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest()
        rules = {r for r, _ in release_cut.check(m, old_pins=self.w.pins).items}
        self.assertIn('K4', rules)
        m2 = copy.deepcopy(self.w.m); m2['repos'].pop('gateway')
        self.assertTrue(any('repos' in t and 'gateway' in t for _, t in release_cut.check(m2, old_pins=self.w.pins).items))

    def fixture(self, cls, **extra):
        m = {'artifacts': extra, 'harness_commit': self.w.m['harness_commit'], 'harness_dirty': False}
        return release_cut.check_fixture(m, self.w.m, cls, old_pins=self.w.pins)

    def nc_entry(self, flags='-DGW_NC_FRESH_KEY', defines=('GW_NC_FRESH_KEY',), body=None):
        build = self.root / ('gw-nc-' + hashlib.sha256(flags.encode()).hexdigest()[:8]); (build / 'bin').mkdir(parents=True, exist_ok=True)
        (build / 'CMakeCache.txt').write_text(f'CMAKE_BUILD_TYPE:STRING=Release\nCMAKE_CXX_FLAGS:STRING={flags}\n')
        nc = build / 'bin' / 'oe-gateway'; nc.write_bytes(body or b'nc ' + self.w.m['repos']['gateway'].encode())
        return {'path': str(nc), 'sha256': hashlib.sha256(nc.read_bytes()).hexdigest(), 'source_sha': self.w.m['repos']['gateway'],
                'defines': list(defines)}

    def test_test_artifacts_are_refused_in_a_product_kind(self):
        entry = self.nc_entry()
        self.assertIn(('K3', 'artifacts.gateway_nc: a test-only build (gateway_nc) in a product kind'),
                      self.fixture('product', gateway_nc=entry).items)
        self.assertEqual(self.fixture('rig', gateway_nc=entry).items, [])

    def test_gateway_nc_build_tree_must_carry_exactly_its_defines(self):
        for flags in ('', '-DGW_NC_NO_ASSET_CHECK', '-DGW_NC_FRESH_KEY -DGW_NC_NO_ASSET_CHECK'):
            items = self.fixture('rig', gateway_nc=self.nc_entry(flags=flags)).items
            self.assertTrue(any(r == 'K4' and 'CMAKE_CXX_FLAGS' in t for r, t in items), (flags, items))
        entry = self.nc_entry(flags='-DGW_NC_NO_CANCEL_REOFFER_RULE', defines=['GW_NC_NO_CANCEL_REOFFER_RULE'])
        self.assertEqual(self.fixture('rig', gateway_nc=entry).items, [])

    def test_gateway_nc_must_carry_the_cut_gateway_commit(self):
        entry = self.nc_entry(body=b'nc of another commit')
        self.assertTrue(any(r == 'K4' and 'gateway_nc is not a build' in t for r, t in self.fixture('rig', gateway_nc=entry).items))

    def test_session_stub_must_sit_in_a_stub_build_of_the_cut_cluster_tools(self):
        ct = self.w.m['repos']['cluster-tools']
        build = self.root / 'ct-nc'; (build / 'app/session-stub').mkdir(parents=True)
        stub = build / 'app/session-stub/ct_session_stub'; stub.write_bytes(b'stub')
        entry = {'path': str(stub), 'sha256': hashlib.sha256(b'stub').hexdigest(), 'source_sha': ct}
        (build / 'CMakeCache.txt').write_text(f'CT_BUILD_SOURCE_SHA:STRING={ct}\nCT_SESSION_STUB:BOOL=ON\n')
        self.assertEqual(self.fixture('rig', session_stub=entry).items, [])
        (build / 'CMakeCache.txt').write_text(f'CT_BUILD_SOURCE_SHA:STRING={ct}\nCT_SESSION_STUB:BOOL=OFF\n')
        self.assertTrue(any(r == 'K4' for r, _ in self.fixture('rig', session_stub=entry).items))
        (build / 'CMakeCache.txt').write_text('CT_BUILD_SOURCE_SHA:STRING=' + '9' * 40 + '\nCT_SESSION_STUB:BOOL=ON\n')
        self.assertTrue(any(r == 'K4' for r, _ in self.fixture('rig', session_stub=entry).items))

    def test_the_shim_is_the_harness_file_or_a_recorded_drift(self):
        entry = {'path': str(self.shim), 'sha256': hashlib.sha256(b'shim bytes').hexdigest(), 'source_sha': 'e' * 40}
        self.assertEqual(self.fixture('rig', gateway_stub=entry).items, [])
        self.shim.write_bytes(b'edited shim'); entry['sha256'] = hashlib.sha256(b'edited shim').hexdigest()
        committed = lambda repo, commit, rel: b'shim bytes' if rel == release_cut.GATEWAY_SHIM else self.w.blob(repo, commit, rel)
        with mock.patch.object(release_cut, 'git_blob', committed):
            found = self.fixture('rig', gateway_stub=entry)
            self.assertTrue(any(r == 'K4' and 'the shim is not' in t for r, t in found.items))
            m = {'artifacts': {'gateway_stub': entry}, 'harness_commit': self.w.m['harness_commit'], 'harness_dirty': False,
                 'harness_drift': {'reason': 'dry run'}}
            found = release_cut.check_fixture(m, self.w.m, 'rig', old_pins=self.w.pins)
            self.assertEqual(found.items, [])
            self.assertTrue(any('the shim is not' in t for t in found.waived))

    def test_build_tree_setting(self):
        build = self.root / 'b'; (build / 'x/y').mkdir(parents=True); (build / 'x/y/bin').write_bytes(b'')
        (build / 'CMakeCache.txt').write_text('A:BOOL=ON\nCT_BUILD_SOURCE_SHA:STRING=abc\n')
        self.assertEqual(release_cut.build_tree_setting(build / 'x/y/bin', 'CT_BUILD_SOURCE_SHA'), 'abc')
        self.assertIsNone(release_cut.build_tree_setting(build / 'x/y/bin', 'NOPE'))


class GatewayProbeTest(unittest.TestCase):
    def test_the_story_is_deterministic_keyed_and_quantity_unique_without_client_order_ids(self):
        rows = gateway_probe.story(12, [1, 2, 3], 7, 100_000, 50 * 10 ** 8, resend_every=4)
        self.assertEqual(rows, gateway_probe.story(12, [1, 2, 3], 7, 100_000, 50 * 10 ** 8, resend_every=4))
        self.assertEqual(len({r['key'] for r in rows}), 12)
        self.assertEqual(len({(r['user'], r['quantity']) for r in rows}), 12)
        self.assertTrue(all('clientOrderId' not in r['body'] for r in rows))
        self.assertEqual([r['i'] for r in rows if r['resend']], [3, 7, 11])
        self.assertEqual(rows[0]['body']['quantity'], '0.001')
        self.assertEqual(gateway_probe.money(50 * 10 ** 8), '50')

    def oracle(self, attempts, orders, rows=None):
        rows = rows or [{'i': 0, 'key': 'k0', 'user': 1, 'quantity': 10}, {'i': 1, 'key': 'k1', 'user': 2, 'quantity': 20}]
        return gateway_probe.key_oracle(rows, attempts, orders)

    def att(self, key, status, order=None, attempt=0, phase='send', code=None):
        body = {'orderId': order} if order else {'code': code}
        return {'key': key, 'status': status, 'body': body, 'attempt': attempt, 'phase': phase}

    def test_one_order_per_key_passes(self):
        out = self.oracle([self.att('k0', 0), self.att('k0', 201, '5', 1), self.att('k0', 201, '5', 2, 'resend'),
                           self.att('k1', 201, '6')],
                          [{'order': 5, 'user': 1, 'market': 1, 'quantity': 10}, {'order': 6, 'user': 2, 'market': 1, 'quantity': 20}])
        self.assertEqual((out['verdict'], out['failures'], out['retried_keys'], out['resends']), ('PASS', [], 1, 1))

    def test_a_second_order_for_a_key_fails_with_the_control_text(self):
        out = self.oracle([self.att('k0', 201, '5'), self.att('k0', 201, '7', 1, 'resend'), self.att('k1', 201, '6')],
                          [{'order': 5, 'user': 1, 'market': 1, 'quantity': 10}, {'order': 7, 'user': 1, 'market': 1, 'quantity': 10},
                           {'order': 6, 'user': 2, 'market': 1, 'quantity': 20}])
        self.assertEqual(out['failures'][0], 'second order for one Idempotency-Key')
        self.assertEqual(out['second_order_keys'], ['k0'])
        self.assertEqual(out['verdict'], 'FAIL')

    def test_missing_stray_and_unanswered(self):
        out = self.oracle([self.att('k0', 201, '5')], [{'order': 9, 'user': 1, 'market': 1, 'quantity': 10},
                                                       {'order': 8, 'user': 2, 'market': 1, 'quantity': 99}])
        self.assertIn('answered order is not the live order of its key', out['failures'])
        self.assertIn('a live order no key made', out['failures'])
        out = self.oracle([self.att('k0', 201, '5'), self.att('k1', 503)], [{'order': 5, 'user': 1, 'market': 1, 'quantity': 10}])
        self.assertEqual((out['verdict'], out['unanswered']), ('INCONCLUSIVE', ['k1']))
        out = self.oracle([self.att('k0', 422, code='GATE_CLOSED'), self.att('k0', 201, '5', 1)], [])
        self.assertIn('a retried key answered two decisions', out['failures'])

    def test_load_retries_with_the_same_key_and_resends_after_the_answer(self):
        with tempfile.TemporaryDirectory() as d:
            calls = []
            replies = iter([(0, None, 'reset'), (504, {'code': 'OUTCOME_UNKNOWN'}, None), (201, {'orderId': '1'}, None),
                            (201, {'orderId': '1', 'duplicate': True}, None)])

            def sender(target, path, headers, body, timeout):
                calls.append((target, headers['Idempotency-Key'], json.dumps(body)))
                return next(replies)
            rows = [{'i': 0, 'key': 'k', 'user': 7, 'quantity': 1, 'body': {'q': 1}, 'resend': True}]
            gateway_probe.Load(rows, ['a:1', 'b:1'], {'7': 'secret'}, Path(d) / 'out', sender=sender, sleep=lambda s: None,
                               concurrency=1).run()
            self.assertEqual([c[0] for c in calls], ['a:1', 'b:1', 'a:1', 'b:1'])
            self.assertEqual({c[1] for c in calls}, {'k'})
            self.assertEqual(len({c[2] for c in calls}), 1)
            phases = [json.loads(l)['phase'] for l in (Path(d) / 'out').read_text().splitlines()]
            self.assertEqual(phases, ['send', 'send', 'send', 'resend'])

    def test_load_gives_up_at_its_bound(self):
        with tempfile.TemporaryDirectory() as d:
            clock = iter(range(0, 1000, 50))
            rows = [{'i': 0, 'key': 'k', 'user': 7, 'quantity': 1, 'body': {}, 'resend': True}]
            gateway_probe.Load(rows, ['a:1'], {'7': 's'}, Path(d) / 'out', retry_bound_s=120,
                               sender=lambda *a: (503, None, None), sleep=lambda s: None, clock=lambda: next(clock)).run()
            lines = (Path(d) / 'out').read_text().splitlines()
            self.assertEqual(len(lines), 3)               # no resend of an unanswered key

    def test_websocket_frames(self):
        self.assertEqual(gateway_probe.ws_accept('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
        frame = gateway_probe.ws_frame(0x1, b'{"op":"ping"}', mask=b'\x01\x02\x03\x04')
        self.assertEqual(frame[0], 0x81); self.assertEqual(frame[1], 0x80 | 13)
        self.assertEqual(bytes(b ^ frame[2:6][i % 4] for i, b in enumerate(frame[6:])), b'{"op":"ping"}')
        server = bytes([0x81, 126]) + (300).to_bytes(2, 'big') + b'x' * 300 + bytes([0x88, 2, 0x0F, 0xA1])
        fin, op, payload, used = gateway_probe.ws_parse(server)
        self.assertEqual((fin, op, len(payload), used), (True, 1, 300, 304))
        self.assertEqual(gateway_probe.ws_parse(server[used:])[:2], (True, 0x8))
        self.assertIsNone(gateway_probe.ws_parse(server[:100]))
        with self.assertRaisesRegex(ValueError, 'never masked'):
            gateway_probe.ws_parse(bytes([0x81, 0x81, 0, 0, 0, 0, 0]))
        big = gateway_probe.ws_frame(0x2, b'y' * 70000, mask=b'\0\0\0\0')
        self.assertEqual((big[1] & 0x7F, int.from_bytes(big[2:10], 'big')), (127, 70000))


class GatewayShimTest(unittest.TestCase):
    def shim(self, mode='stored', replies=()):
        d = tempfile.mkdtemp(); self.addCleanup(lambda: __import__('shutil').rmtree(d))
        (Path(d) / 'keys').write_text('k' * 64 + ':81001\n')
        replies = list(replies)
        self.calls = []

        def runner(argv, **kw):
            self.calls.append(argv)
            code, out = replies.pop(0)
            return subprocess.CompletedProcess(argv, code, out, '')
        env = {'SHIM_API_KEYS_FILE': str(Path(d) / 'keys'), 'SHIM_MODE': mode, 'SHIM_CORE_PROBE': 'cp', 'CORE_ADDRESSES': 'a',
               'CORE_PORT_BASE': '1', 'CLUSTER_PORT_STRIDE': '1', 'CORE_LOCAL_HOST': 'h', 'CORE_AUTH_CREDENTIAL': 'c'}
        return gateway_shim.Shim(env, runner)

    BODY = json.dumps({'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC', 'price': '50',
                       'quantity': '0.001'}).encode()

    def test_request_ids_follow_the_gateway_derivation(self):
        key = '398201b0-a3da-44aa-a0cc-b42a535681b9'
        hi, lo = gateway_shim.request_id(key)
        self.assertEqual(((hi % (1 << 64)) << 64) | (lo % (1 << 64)), int(key.replace('-', ''), 16))
        digest = hashlib.sha256(b'order-17').digest()
        self.assertEqual(gateway_shim.request_id('order-17'),
                         tuple(gateway_shim.signed(int.from_bytes(digest[a:a + 8], 'big')) for a in (0, 8)))
        self.assertIsNone(gateway_shim.request_id('00000000-0000-0000-0000-000000000000'))
        self.assertIsNone(gateway_shim.request_id('x' * 65))
        self.assertIsNone(gateway_shim.request_id('bad key'))

    def test_order_bodies(self):
        order, _ = gateway_shim.parse_order(self.BODY)
        self.assertEqual((order['price'], order['qty'], order['ch']), (50 * 10 ** 8, 100_000, 0))
        for bad in ({'marketId': '1'}, {'x': 1}, {'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC',
                                                  'quantity': '0.123456789'},
                    dict(json.loads(self.BODY), marketId=1)):                  # an id is a decimal string, never a number
            self.assertIsNone(gateway_shim.parse_order(json.dumps(bad).encode())[0])
        self.assertEqual(gateway_shim.units('0.00000001'), 1)

    def test_answers(self):
        ack = '{"verb":"create","replies":[{"t":"OrderAck","order":5,"status":"PENDING_NEW","duplicate":true}]}'
        rej = '{"verb":"create","replies":[{"t":"OrderReject","reason":"GATE_CLOSED","order":0}]}'
        shim = self.shim(replies=[(0, ack), (4, rej), (3, '')])
        key = '398201b0-a3da-44aa-a0cc-b42a535681b9'
        self.assertEqual(shim.create(81001, key, self.BODY), (201, {'orderId': '5', 'status': 'PENDING_NEW', 'duplicate': True}))
        self.assertEqual(shim.create(81001, key, self.BODY)[0:2][0], 422)
        self.assertEqual(shim.create(81001, key, self.BODY)[1]['code'], 'OUTCOME_UNKNOWN')
        rh = {a.split('=')[0]: a.split('=')[1] for a in self.calls[0] if '=' in a and a.split('=')[0] in ('rh', 'rl', 'user')}
        self.assertEqual(rh['user'], '81001')
        self.assertEqual(len({tuple(a for a in c if a.startswith(('rh=', 'rl='))) for c in self.calls}), 1)
        self.assertTrue(shim.ready())

    def test_fresh_key_mode_mints_a_new_request_id_per_attempt(self):
        ack = '{"replies":[{"t":"OrderAck","order":5,"status":"NEW","duplicate":false}]}'
        shim = self.shim('fresh-key', [(0, ack), (0, ack)])
        key = '398201b0-a3da-44aa-a0cc-b42a535681b9'
        shim.create(81001, key, self.BODY); shim.create(81001, key, self.BODY)
        self.assertEqual(len({tuple(a for a in c if a.startswith(('rh=', 'rl='))) for c in self.calls}), 2)


class GatewayScenarioTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_the_five_ids_are_registered_and_dispatched_by_kind(self):
        self.assertEqual(set(gateway_drills.SCENARIOS), {'gateway-kill-restart', 'stream-slow-consumer', 'gateway-session-timeout',
                                                          'fill-visibility-core', 'tick-live-path'})
        self.assertEqual(set(gateway_drills.CONTROL_TEXT), set(gateway_drills.SCENARIOS))
        import gateway_scenarios
        self.assertEqual(set(gateway_scenarios.DRILLS), set(gateway_drills.SCENARIOS))
        m = gateway_manifest(self.dir, slots={'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'})
        for name in gateway_drills.SCENARIOS:
            self.assertIsNone(gateway_drills.check_scenario(m, name))       # the drill itself
        with self.assertRaisesRegex(Inconclusive, 'unknown gateway scenario'):
            gateway_drills.check_scenario(m, 'gateway-other')
        with self.assertRaisesRegex(Inconclusive, 'declares the gateway roles'):
            gateway_drills.check_scenario(slot_manifest(self.dir), 'stream-slow-consumer')
        stub = gateway_manifest(self.dir, slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
        with self.assertRaisesRegex(Inconclusive, 'runs on oe-gateway in gw0 and gw1'):
            gateway_drills.check_scenario(stub, 'gateway-session-timeout')
        # one control build in either gateway slot (the slot its drill's rule runs through), never two
        for slots in ({'gw0': 'gateway_nc', 'gw1': 'gateway'}, {'gw0': 'gateway', 'gw1': 'gateway_nc'}):
            m2 = gateway_manifest(self.dir, slots=dict(slots, st0='stream', st1='stream'))
            self.assertIsNone(gateway_drills.check_scenario(m2, 'gateway-kill-restart'))
        both = gateway_manifest(self.dir, slots={'gw0': 'gateway_nc', 'gw1': 'gateway_nc', 'st0': 'stream', 'st1': 'stream'})
        with self.assertRaisesRegex(Inconclusive, 'runs on oe-gateway in gw0 and gw1'):
            gateway_drills.check_scenario(both, 'gateway-kill-restart')

    def test_a_control_kind_runs_only_its_own_drill_with_its_text(self):
        import gateway_scenarios
        m = gateway_manifest(self.dir, slots={'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'})
        m['manifest_kind'] = 'gw-tick-nofwd'
        self.assertEqual(gateway_scenarios.control_of(m, 'tick-live-path'), 'market order not completed')
        with self.assertRaisesRegex(Inconclusive, 'is the control of tick-live-path'):
            gateway_drills.check_scenario(m, 'fill-visibility-core')
        m['manifest_kind'] = 'gw-b3'
        self.assertEqual(gateway_scenarios.control_of(m, 'gateway-kill-restart'), gateway_scenarios.STORED_TEXT)
        m['manifest_kind'] = 'gw'
        self.assertIsNone(gateway_scenarios.control_of(m, 'gateway-kill-restart'))
        m['manifest_kind'] = 'gw-noreoffer'
        self.assertEqual(gateway_scenarios.control_of(m, 'gateway-kill-restart'), gateway_scenarios.CANCEL_TEXT)
        m['manifest_kind'] = 'gw-noassetcheck'
        self.assertEqual(gateway_scenarios.control_of(m, 'fill-visibility-core'), gateway_scenarios.DECODE_TEXT)
        with self.assertRaisesRegex(Inconclusive, 'is the control of fill-visibility-core'):
            gateway_drills.check_scenario(m, 'gateway-kill-restart')
        for kind, spec in core_contracts.GATEWAY_KINDS.items():
            if spec.get('control'):
                self.assertIn(spec['control'], gateway_drills.SCENARIOS, kind)
                for key in spec.get('drill') or {}:
                    self.assertIn(key, gateway_drills.SETTINGS, kind)

    def test_dry_runs_and_controls_are_read_from_the_manifest(self):
        stub = gateway_manifest(self.dir, slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
        self.assertEqual(gateway_drills.check_scenario(stub, 'stream-slow-consumer'), 'stream')
        self.assertEqual(gateway_drills.control_of(stub, 'stream'), 'stream-slow-consumer')      # ceiling not lowered
        stub['core_jvm_properties'] = {'core.egress.max.capacity.bytes': '262144'}
        self.assertIsNone(gateway_drills.control_of(stub, 'stream'))
        with self.assertRaisesRegex(Inconclusive, 'runs on oe-gateway'):
            gateway_drills.check_scenario(stub, 'gateway-session-timeout')
        shim = gateway_manifest(self.dir, slots={'gw0': 'gateway_stub', 'gw1': 'gateway_stub', 'st0': None, 'st1': None})
        self.assertEqual(gateway_drills.check_scenario(shim, 'gateway-kill-restart'), 'gateway')
        self.assertIsNone(gateway_drills.control_of(shim, 'gateway'))
        shim['artifacts']['gateway_stub']['mode'] = 'fresh-key'
        self.assertEqual(gateway_drills.control_of(shim, 'gateway'), 'gateway-kill-restart')

    def test_verdict(self):
        hold = gateway_drills.line(True, {})
        fail = gateway_drills.line(False, {}, 'slow session not closed within bound')
        other = gateway_drills.line(False, {}, 'something else')
        self.assertEqual(gateway_drills.verdict({'a': hold}, None)[0], 'PASS')
        self.assertEqual(gateway_drills.verdict({'a': hold, 'b': fail}, None)[0], 'FAIL')
        self.assertEqual(gateway_drills.verdict({'a': hold, 'b': gateway_drills.line(True, {}, inconclusive=True)}, None)[0],
                         'INCONCLUSIVE')
        self.assertEqual(gateway_drills.verdict({'b': fail}, 'stream-slow-consumer')[0], 'PASS')
        self.assertEqual(gateway_drills.verdict({'b': other}, 'stream-slow-consumer')[0], 'FAIL')    # another text
        self.assertEqual(gateway_drills.verdict({'a': hold}, 'stream-slow-consumer')[0], 'FAIL')    # vacuous: nothing failed

    def test_settings_are_overridable_and_checked(self):
        self.assertEqual(gateway_drills.settings({})['SLOW_CLOSE_BOUND_S'], 150)
        self.assertEqual(gateway_drills.settings({'SLOW_CLOSE_BOUND_S': '30'})['SLOW_CLOSE_BOUND_S'], 30)
        with self.assertRaises(Violation):
            gateway_drills.settings({'FREEZE_S': '0'})

    def test_counters_moved_and_the_kill_window(self):
        before = {'ae0': {'core_resumable_sessions_closed_total': 0.0, 'core_log_position': 1.0, 'core_sessions_known': 3.0},
                  'ae1': {'error': 'x'}}
        after = {'ae0': {'core_resumable_sessions_closed_total': 1.0, 'core_log_position': 9.0, 'core_sessions_known': 3.0},
                 'ae1': {'core_resumable_sessions_closed_total': 1.0}}
        self.assertEqual(gateway_drills.counters_moved(before, after), {'ae0': {'core_resumable_sessions_closed_total': 1.0}})
        self.assertEqual(gateway_drills.total(after, 'core_resumable_sessions_closed_total'), 1.0)
        attempts = [{'key': 'a', 'target': 'g0', 'status': 0, 'sent_ns': 10, 'recv_ns': 30, 'attempt': 0},
                    {'key': 'a', 'target': 'g1', 'status': 201, 'sent_ns': 31, 'recv_ns': 40, 'attempt': 1},
                    {'key': 'b', 'target': 'g0', 'status': 201, 'sent_ns': 5, 'recv_ns': 15, 'attempt': 0}]
        report = gateway_drills.kill_window_report({'killed': True, 'target': 'g0', 'killed_ns': 20}, attempts)
        self.assertEqual((report['in_flight_at_kill'], report['in_flight_keys_answered'], report['in_flight_answers']),
                         (1, 1, [201]))


import test_mk_manifests


class GatewayKindBuilderTest(unittest.TestCase):
    """mk_manifests derives the gateway kinds from an rc2-cut/3 cut, keeps every other role's address, and stages only
    what the kind's slots run."""
    setUp = test_mk_manifests.CutManifestBuilderTest.setUp
    tearDown = test_mk_manifests.CutManifestBuilderTest.tearDown
    built = test_mk_manifests.CutManifestBuilderTest.built

    def test_gateway_kinds(self):
        _, plain = self.built('s17')
        for kind, spec in core_contracts.GATEWAY_KINDS.items():
            with self.subTest(kind=kind):
                _, m = self.built(kind)
                self.assertEqual({r: m['nodes'][r] for r in plain['nodes']}, plain['nodes'])
                self.assertEqual([m['nodes'][r] for r in ('gw0', 'gw1', 'st0', 'st1')],
                                 [f'172.30.216.{40 + j}' for j in range(4)])
                self.assertEqual({k: m['slot_artifacts'][k] for k in spec['slots']}, spec['slots'])
                staged = {n for n in core_contracts.GATEWAY_BINARIES if m['artifacts'][n] is not None}
                self.assertEqual(staged, set(spec['slots'].values()) - {None})
                self.assertEqual(m.get('core_jvm_properties', {}), spec['core_jvm'])
                self.assertEqual(m.get('engine_driver', 'embedded'), spec['driver'])
                if 'gateway' in staged:
                    self.assertEqual(m['artifacts']['gateway']['sha256'], self.world.m['artifacts']['oe-gateway']['sha256'])
                if 'gateway_stub' in staged:
                    self.assertEqual(m['artifacts']['gateway_stub']['mode'], spec['shim_mode'])
                if 'gateway_nc' in staged:
                    self.assertEqual(m['artifacts']['gateway_nc']['defines'], [core_contracts.nc_define(kind)])
                    self.assertIn(core_contracts.nc_define(kind).encode(), Path(m['artifacts']['gateway_nc']['path']).read_bytes())
                self.assertEqual(m['limits']['cpu_quota_by_role']['st0'], 1.0)

    def test_a_cut_without_the_gateway_is_refused(self):
        import test_release_cut
        old = test_release_cut.World(self.root / 'old-cut', 'rc2-cut/2')
        old.pins.update(self.world.pins)
        path = self.root / 'rc2-cut-2.json'; path.write_text(json.dumps(old.m))
        with self.assertRaisesRegex(Violation, 'the cut must be ' + release_cut.SCHEMA):
            test_mk_manifests.mk_manifests.build_from_cut('gw', 'r1', path, self.cfg, old_pins=old.pins)


class RunnerGatewayDispatchTest(unittest.TestCase):
    def test_a_drill_on_a_kind_without_the_product_binaries_exits_non_zero_before_any_container(self):
        import runner
        with tempfile.TemporaryDirectory() as d:
            m = gateway_manifest(d, slots={'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None})
            path = Path(d) / 'manifest.json'; path.write_text(json.dumps(m))
            for name in ['gateway-kill-restart', 'gateway-session-timeout', 'fill-visibility-core', 'tick-live-path']:
                out = Path(d) / ('out-' + name)
                with mock.patch('sys.argv', ['runner', '--manifest', str(path), '--scenario', name, '--output', str(out)]), \
                        mock.patch('builtins.print'), mock.patch('core_fixture.CoreFixture') as fixture:
                    self.assertEqual(runner.main(), 2)
                fixture.assert_not_called()
                result = json.loads((out / 'result.json').read_text())
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertIn('runs on oe-gateway in gw0 and gw1', result['error'])


class TapReplayAfterElectionTest(unittest.TestCase):
    """The tap's order-event gap after an election is filled from the core's ring (CoreProbe order-events); what the ring
    no longer held stays a declared untappable window with its count."""

    def events(self, seqs):
        return [{'seq': s, 'order': s, 'kind': 'NEW'} for s in seqs]

    def test_an_election_gap_is_filled_and_an_overrun_stays_declared(self):
        import core_drills
        import replica_drills
        tapped = self.events([1, 2, 3, 7, 8])
        transitions = [{'event': 'registered', 'at_ms': 0, 'last_event_seq': 0},
                       {'event': 'session_closed', 'at_ms': 1000, 'last_event_seq': 3, 'last_dispatch_seq': 0},
                       {'event': 'reconnected', 'at_ms': 5000, 'last_event_seq': 3, 'last_dispatch_seq': 0}]
        span = core_drills.event_replay_span(tapped, transitions)
        self.assertEqual((span['from'], span['gaps']), (3, [[4, 6]]))
        election = [{'from_ms': 900, 'to_ms': 4000, 'killed': 'ae0', 'new_leader': 'ae1'}]
        # the ring held everything: the gap closes, nothing is declared
        full = {'events': self.events(range(4, 9)), 'requests': 1, 'lost': [], 'last_seq': 8, 'complete': True}
        merged, report = core_drills.merge_event_replay(tapped, full, span)
        self.assertEqual(([e['seq'] for e in merged], report['remaining_gaps']), (list(range(1, 9)), []))
        summary = core_drills.replayed_summary({'events': {'gaps': [[4, 6]]}, 'dispatch': {'gaps': []}}, report)
        self.assertIsNone(replica_drills.untappable_windows(transitions, summary, elections=election))
        # the ring had wrapped past 4..5: they stay a gap, declared untappable with their count
        partial = {'events': self.events([6, 7, 8]), 'requests': 2, 'lost': [[4, 5]], 'last_seq': 8, 'complete': True}
        merged, report = core_drills.merge_event_replay(tapped, partial, span)
        self.assertEqual(report['remaining_gaps'], [[4, 5]])
        summary = core_drills.replayed_summary({'events': {'gaps': [[4, 6]]}, 'dispatch': {'gaps': []}}, report)
        declared = replica_drills.untappable_windows(transitions, summary, elections=election)
        self.assertEqual((declared['events'], declared['events_short']), ([[4, 5]], 2))


if __name__ == '__main__':
    unittest.main()
