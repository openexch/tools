# SPDX-License-Identifier: Apache-2.0
"""Fixture v2 contracts (H0 RED list, G10, G15/D20, G31, D18) without Docker."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import assert_production_timeouts, validate_core_manifest
from core_fixture import CoreFixture, parse_prometheus, partition_arguments
from credentials import KeyRing, redact


def write(directory, name, data=b'x'):
    path = Path(directory) / name
    path.write_bytes(data)
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'source_sha': 'a' * 40}


def manifest(directory):
    nodes = {role: f'172.30.99.{10 + i}' for i, role in enumerate(sorted(core_contracts.ROLES))}
    engines = {role: [2 * i, 2 * i + 1] for i, role in enumerate(core_contracts.ENGINES)}
    probe_src = write(directory, 'CoreProbe.java', b'src'); probe = write(directory, 'core-probe.jar', b'jar')
    journal_src = write(directory, 'JournalProbe.java', b'src2'); journal = write(directory, 'journal-probe.jar', b'jar2')
    return {
        'schema_version': 2, 'topology': 'core', 'run_id': 'rc2-0123456789ab', 'timeouts': 'production',
        'image': 'sha256:' + 'b' * 64, 'state_root': str(Path(directory) / 'fixtures' / 'rc2-0123456789ab'),
        'failure_domain': 'single_host_process_loss', 'network': {'subnet': '172.30.99.0/24', 'internal': True},
        'nodes': nodes, 'ports': dict(core_contracts.PORT_PROFILE), 'seed': 1,
        'cpu_set': list(range(12)) + [12, 13, 14, 15],
        'limits': {'shm_mb': 1024, 'memory_mb': 2048, 'disk_min_free_mb': 1,
                   'cpu_set_by_role': {**engines, 'probe': [20, 21]}, 'cpu_quota_by_role': {r: 2 for r in engines}},
        'artifacts': {'ae': write(directory, 'ae.jar'), 'me': write(directory, 'me.jar'),
                      'projector': write(directory, 'projector.jar'),
                      'forwarder': None, 'forwarder_b': None, 'bridge': None, 'bridge_b': None, 'shadow': None},
        'slot_artifacts': {'fwd0': None, 'fwd1': None, 'bridge0': None, 'bridge1': None, 'shadow0': None},
        'core_probe': {'path': probe['path'], 'sha256': probe['sha256'], 'source_path': probe_src['path'], 'source_sha256': probe_src['sha256']},
        'journal_probe': {'path': journal['path'], 'sha256': journal['sha256'], 'source_path': journal_src['path'],
                          'source_sha256': journal_src['sha256']},
        'credentials': {'ae': dict(core_contracts.AE_CREDENTIAL_ENV),
                        'me': {'mode': 'not_enforced_by_artifact', 'keys_env': 'ME_AUTH_KEYS', 'credential_env': 'ME_AUTH_CREDENTIAL'}},
        'me_journal_profile': 'me-journal-v1', 'postgres_bin': '/usr/lib/postgresql/16/bin', 'postgres_port': 55500,
    }


class CoreManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'
        self.m = manifest(self.dir)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m):
        validate_core_manifest(m, self.path, cpu_count=24)

    def bad(self, edit, error=Violation, text=None):
        m = copy.deepcopy(self.m); edit(m)
        with self.assertRaises(error) as caught:
            self.check(m)
        if text: self.assertIn(text, str(caught.exception))

    def test_valid_core_manifest_passes(self):
        self.check(self.m)

    def test_unknown_role_is_refused(self):
        self.bad(lambda m: m['nodes'].update(fwd2='172.30.99.200'), text='roles are exactly')

    def test_oms_or_market_in_core_topology_is_refused(self):
        self.bad(lambda m: m['nodes'].update(oms='172.30.99.201'), text='legacy roles')
        self.bad(lambda m: m['nodes'].update(market='172.30.99.202'), text='legacy roles')

    def test_missing_role_including_reserved_shadow0_is_refused(self):
        self.bad(lambda m: m['nodes'].pop('shadow0'))
        self.bad(lambda m: m['nodes'].pop('bridge1'))

    def test_missing_key_is_inconclusive(self):
        self.bad(lambda m: m.pop('credentials'), Inconclusive)
        self.bad(lambda m: m['artifacts'].pop('projector'), Inconclusive)
        self.bad(lambda m: m.pop('journal_probe'), Inconclusive)

    def test_credentials_must_be_explicit(self):
        self.bad(lambda m: m['credentials']['ae'].update(keys_env='ASSETS_KEYS'), text='ASSETS_AUTH_KEYS')
        self.bad(lambda m: m['credentials']['me'].update(mode='maybe'), text='ME credential mode')
        self.bad(lambda m: m['credentials']['me'].update(keys_env=''), text='environment names')

    def test_d20_timeouts_stay_production(self):
        self.bad(lambda m: m.update(timeouts='relaxed'), text='D20')
        self.bad(lambda m: m.update(engine_env={'AERON_CLUSTER_ELECTION_TIMEOUT': '5s'}), text='D20')

    def test_d20_engines_pinned_to_disjoint_cpusets(self):
        self.bad(lambda m: m['limits']['cpu_set_by_role'].pop('ae1'), text='pinned')
        self.bad(lambda m: m['limits']['cpu_set_by_role'].update(ae1=[0]), text='disjoint')
        self.bad(lambda m: m['limits']['cpu_set_by_role'].update(probe=[0]), text='probe CPUs')
        self.bad(lambda m: m['limits']['cpu_quota_by_role'].update(ae0=3), text='quota')

    def test_d18_network_internal_only(self):
        self.bad(lambda m: m['network'].update(internal=False), text='D18')

    def test_slots_skip_cleanly_or_name_a_compatible_artifact(self):
        self.bad(lambda m: m['artifacts'].pop('forwarder'), text='declared explicitly')
        self.bad(lambda m: m['slot_artifacts'].update(fwd0='bridge'), text='cannot run')
        self.bad(lambda m: m['slot_artifacts'].pop('shadow0'), text='every slot')
        def with_binary(m):
            m['artifacts']['forwarder'] = dict(write(self.dir, 'fwd.bin', b'elf'), driver='external')
            m['slot_artifacts']['fwd0'] = 'forwarder'
        m = copy.deepcopy(self.m); with_binary(m); self.check(m)
        def bad_driver(m):
            with_binary(m); m['artifacts']['forwarder']['driver'] = 'host'
        self.bad(bad_driver, text='driver')
        def changed(m):
            with_binary(m); m['artifacts']['forwarder']['sha256'] = '0' * 64
        self.bad(changed, text='digest')

    def test_unknown_journal_profile_is_refused(self):
        self.bad(lambda m: m.update(me_journal_profile='me-journal-9'), text='journal profile')

    def test_run_identity_and_state_root(self):
        self.bad(lambda m: m.update(run_id='r01-0123456789ab'))
        self.bad(lambda m: m.update(state_root='/tmp/elsewhere'), text='state path')

    def test_production_timeout_guard(self):
        core_contracts.assert_production_timeouts({'TRANSPORT_IDLE_MODE': 'backoff', 'FWD_INSTANCE_ID': '21'})
        for key in ['AERON_CLUSTER_ELECTION_TIMEOUT', 'LEADER_HEARTBEAT_MS', 'CLIENT_LIVENESS_NS', 'SESSION_TIMEOUT',
                    'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'SOME_NEW_KNOB']:
            with self.subTest(key=key), self.assertRaises(Violation): core_contracts.assert_production_timeouts({key: '1'})
        with self.assertRaises(Violation):
            core_contracts.assert_production_timeouts({'BASE_DIR': '-Daeron.cluster.election.timeout=1s'})

    def test_manifest_keys_are_an_allowlist(self):
        self.bad(lambda m: m.update(anything_new=1), text='allowlist')
        self.bad(lambda m: m.pop('timeouts'), Inconclusive)
        m = copy.deepcopy(self.m); m['profile_note'] = 'x'; self.check(m)

    def test_pinned_image_environment_is_checked(self):
        clean = {'Env': ['PATH=/usr/bin', 'JAVA_HOME=/opt/java', 'LANG=C.UTF-8'], 'Entrypoint': ['/entry.sh'], 'Cmd': None}
        self.assertEqual(core_contracts.check_image_config(clean), ['JAVA_HOME', 'LANG', 'PATH'])
        for config in [dict(clean, Env=clean['Env'] + ['JAVA_TOOL_OPTIONS=-Xmx1g']),
                       dict(clean, Env=['PATH=/x', 'JAVA_HOME=-Daeron.cluster.election.timeout=1s']),
                       dict(clean, Cmd=['java', '-Daeron.cluster.leader.heartbeat.timeout=1s'])]:
            with self.subTest(config=config), self.assertRaises(Violation):
                core_contracts.check_image_config(config)

    def test_me_credential_names_cannot_shadow_fixture_variables(self):
        self.bad(lambda m: m['credentials']['me'].update(keys_env='SETTLEMENT_JOURNAL_DIR'), text='collides')
        self.bad(lambda m: m['credentials']['me'].update(credential_env='CLUSTER_ADDRESSES'), text='collides')
        self.bad(lambda m: m['credentials']['me'].update(credential_env='ME_AUTH_KEYS'), text='distinct')

    def test_shadow0_slot_is_reserved_and_absent_slots_skip(self):
        fixture = CoreFixture.__new__(CoreFixture); fixture.m = self.m
        self.assertEqual(fixture.start_slot('shadow0')['state'], 'RESERVED')
        self.assertEqual(fixture.start_slot('fwd0')['state'], 'SKIPPED_ABSENT')
        self.assertEqual(fixture.start_slot('bridge1')['state'], 'SKIPPED_ABSENT')
        fixture.m = copy.deepcopy(self.m); fixture.m['slot_artifacts']['shadow0'] = 'shadow'
        with self.assertRaises(Inconclusive): fixture.start_slot('shadow0')


class CredentialsTest(unittest.TestCase):
    def test_tables_credentials_and_evidence_without_secrets(self):
        ring = KeyRing()
        ae = ring.table('ae').split(';')
        self.assertEqual({e.split(':')[1] for e in ae}, {'GATEWAY', 'ADMIN', 'TOOL', 'FORWARDER', 'BRIDGE'})
        self.assertEqual({e.split(':')[1] for e in ring.table('me').split(';')}, {'FORWARDER', 'ADMIN'})
        self.assertTrue(all(len(e.split(':')[2]) == 64 for e in ae))
        # RC2 S6 (A16): every key carries the explicit any-user scope; a missing users field fails the load
        self.assertTrue(all(e.endswith('::users=*') for e in ae + ring.table('me').split(';')))
        self.assertTrue(ring.credential('bridge0', 'ae').startswith('31:BRIDGE:'))
        self.assertTrue(ring.credential('fwd1', 'me').startswith('122:FORWARDER:'))
        evidence = json.dumps(ring.evidence())
        for secret in ring.secrets():
            self.assertNotIn(secret, evidence)
        self.assertIn('shadow0', ring.evidence()['reserved'])
        self.assertNotEqual(KeyRing().secrets(), ring.secrets())

    def test_redaction_in_retained_command_logs(self):
        ring = KeyRing()
        with tempfile.TemporaryDirectory() as temp:
            fixture = CoreFixture.__new__(CoreFixture)
            fixture.root = Path(temp); (fixture.root / 'logs').mkdir()
            fixture.registry = {'command_seq': 0}; fixture.secret_values = ring.secrets()
            fixture.save = lambda: None
            credential = ring.credential('probe-admin', 'ae')
            fixture.command([sys.executable, '-c', 'import sys; print(sys.argv[1]); raise SystemExit(4)', credential],
                            check=False, accepted=(0, 4))
            text = (fixture.root / 'commands.jsonl').read_text() + (fixture.root / 'logs' / 'command-00000.log').read_text()
            self.assertNotIn(credential.split(':')[2], text)
            self.assertIn('<redacted>', text)
            self.assertEqual(json.loads((fixture.root / 'commands.jsonl').read_text())['accepted_exit_codes'], [0, 4])
        self.assertEqual(redact('a-SECRET-b', {'SECRET'}), 'a-<redacted>-b')

    def test_probe_state_files_are_redacted_before_teardown(self):
        ring = KeyRing()
        with tempfile.TemporaryDirectory() as temp:
            fixture = CoreFixture.__new__(CoreFixture)
            fixture.root = Path(temp); fixture.secret_values = ring.secrets()
            probe = fixture.root / 'state' / 'probe'; probe.mkdir(parents=True)
            secret = ring.credential('probe-tool', 'ae')
            (probe / 'tap.err').write_text('boom ' + secret + '\n'); (probe / 'tap.out').write_text('{"rows": 1}\n')
            fixture.redact_probe_state()
            self.assertNotIn(secret.split(':')[2], (probe / 'tap.err').read_text())
            self.assertEqual((probe / 'tap.out').read_text(), '{"rows": 1}\n')


class FaultAndMetricsTest(unittest.TestCase):
    def setUp(self):
        self.m = {'ports': dict(core_contracts.PORT_PROFILE),
                  'nodes': {r: f'172.30.99.{10 + i}' for i, r in enumerate(sorted(core_contracts.ROLES))}}

    def test_g10_client_to_engine_partition_arguments(self):
        rules = partition_arguments(self.m, 'fwd0', 'me', 'ingress', 'add')
        self.assertEqual([r[r.index('--dport') + 1] for r in rules], ['9002', '9102', '9202'])
        self.assertTrue(all(r[2] == '-A' and r[3] == 'OUTPUT' for r in rules))
        one = partition_arguments(self.m, 'bridge1', 'me2', 'journal_archive', 'delete')
        self.assertEqual((one[0][2], one[0][one[0].index('--dport') + 1], one[0][one[0].index('-d') + 1]),
                         ('-D', '9210', self.m['nodes']['me2']))
        self.assertEqual(partition_arguments(self.m, 'bridge0', 'ae1', 'ingress', 'add')[0][-3], '19402')
        self.assertEqual(partition_arguments(self.m, 'projector', 'ae0', 'money_journal_archive', 'add')[0][-3], '19301')

    def test_partition_refuses_unowned_or_nonsense_paths(self):
        for args in [('probe', 'me', 'ingress', 'add'), ('fwd0', 'oms', 'ingress', 'add'), ('ae0', 'ae0', 'log', 'add'),
                     ('fwd0', 'ae', 'journal_archive', 'add'), ('fwd0', 'me', 'telnet', 'add'), ('fwd0', 'me', 'ingress', 'flush')]:
            with self.subTest(args=args), self.assertRaises(Violation):
                partition_arguments(self.m, *args)

    def test_prometheus_parsing_is_strict(self):
        values = parse_prometheus('# HELP x\nassets_ingress_unauthorised_total 3\nbridge_halted{reason="gap"} 1.0\n')
        self.assertEqual(values['assets_ingress_unauthorised_total'], 3.0)
        self.assertEqual(values['bridge_halted{reason="gap"}'], 1.0)
        with self.assertRaises(Inconclusive): parse_prometheus('this is not a metric line at all\n')

    def test_kill_allowlist(self):
        fixture = CoreFixture.__new__(CoreFixture); fixture.registry = {'containers': {'probe': 'x', 'ae0': 'y'}}
        for name in ['probe', 'oms', 'fwd0']:
            with self.subTest(name=name), self.assertRaises(Violation): fixture.kill(name)


# ======================================================================================================
# RC2 S15 W1 (contract 5): fixture v3. Everything below runs without Docker, on stubbed seams.
# ======================================================================================================

import core_fixture
import core_scenarios
import fixture as fixture_module


def slot_manifest(directory, driver='external'):
    m = manifest(directory)
    libs = lambda: {'aeronmd': dict({k: v for k, v in write(directory, 'aeronmd', b'md').items() if k != 'source_sha'}, exec=True),
                    'libaeron_driver.so': {k: v for k, v in write(directory, 'libaeron_driver.so', b'sod').items() if k != 'source_sha'},
                    'libaeron.so': {k: v for k, v in write(directory, 'libaeron.so', b'so').items() if k != 'source_sha'}}
    for name in ('forwarder', 'bridge'):
        m['artifacts'][name] = dict(write(directory, name + '.bin', b'elf-' + name.encode()), driver=driver, libs=libs())
    m['slot_artifacts'].update(fwd0='forwarder', fwd1='forwarder', bridge0='bridge', bridge1='bridge')
    m['credentials']['me']['mode'] = 'enforced'
    return m


_FIXTURES = iter(range(10**6))


def fixture_for(m, directory):
    f = CoreFixture.__new__(CoreFixture)
    f.m = m; f.keys = KeyRing(); f.secret_values = f.keys.secrets(); f.slots = {}
    f.root = Path(directory) / ('rt%d' % next(_FIXTURES)); (f.root / 'logs').mkdir(parents=True)
    f.run_id = m['run_id']; f.token = 'tok'
    f.registry = {'containers': {}, 'command_seq': 0, 'network_id': 'net'}
    f.save = lambda: None
    f.gateway = '172.30.99.1'; f.pg_port = 55500
    return f


class Docker:
    """A tiny container state machine behind `command`, `inspect` and `execute` stubs."""

    def __init__(self, fixture, roles):
        self.f, self.calls, self.exec_calls = fixture, [], []
        self.state = {}
        for i, role in enumerate(roles):
            fixture.registry['containers'][role] = 'c-' + role
            self.state['c-' + role] = {'Running': True, 'Paused': False, 'ExitCode': 0, 'Pid': 100 + i, 'StartedAt': 'S0',
                                       'FinishedAt': '0001-01-01T00:00:00Z'}
        self.stat = {}      # started_at -> cnc.dat mtime text
        self.exec_stdout = lambda argv: ''
        fixture.inspect = lambda kind, rid: {'State': self.state[rid], 'HostConfig': {'NetworkMode': 'net'}}
        fixture.command = self.command
        fixture.execute = self.execute

    def command(self, argv, **kw):
        argv = [str(a) for a in argv]; self.calls.append(argv)
        if argv[:2] == ['docker', 'create']:
            role = argv[argv.index('--name') + 1].rsplit('-', 1)[-1]
            self.state['c-' + role] = {'Running': False, 'Paused': False, 'ExitCode': 0, 'Pid': 1, 'StartedAt': 'S0',
                                       'FinishedAt': '0001-01-01T00:00:00Z'}
            return types.SimpleNamespace(stdout='c-' + role + '\n', stderr='', returncode=0)
        if argv[:2] == ['docker', 'pause']:
            self.state[argv[2]]['Paused'] = True
        elif argv[:2] == ['docker', 'unpause']:
            self.state[argv[2]]['Paused'] = False
        elif argv[:2] == ['docker', 'start']:
            st = self.state[argv[2]]
            st.update(Running=True, ExitCode=0, StartedAt='S%d' % (len(self.calls)))
        elif argv[:2] == ['docker', 'kill']:
            self.state[argv[3]].update(Running=False, ExitCode=137, FinishedAt='2026-11-02T10:00:00Z')
        return types.SimpleNamespace(stdout='', stderr='', returncode=0)

    def execute(self, name, argv, **kw):
        self.exec_calls.append((name, argv, kw))
        text = ' '.join(argv)
        if 'stat -c' in text:
            return types.SimpleNamespace(stdout=self.stat.get(self.state['c-' + name]['StartedAt'], '1.0') + '\n', returncode=0)
        return types.SimpleNamespace(stdout=self.exec_stdout(argv), stderr='', returncode=0)


class SlotEnvTest(unittest.TestCase):
    FWD = {'FWD_CORE_INGRESS', 'FWD_CORE_RESPONSE_CHANNEL', 'AE_AUTH_CREDENTIAL', 'FWD_ME_INGRESS', 'FWD_ME_RESPONSE_CHANNEL',
           'ME_AUTH_CREDENTIAL', 'FWD_INGRESS_CHANNEL', 'FWD_DRIVER_MODE', 'FWD_DRIVER_TIMEOUT_MS', 'FWD_INSTANCE_ID',
           'FWD_HTTP_BIND'}
    BRIDGE = {'BRIDGE_ME_JOURNAL_ARCHIVES', 'BRIDGE_JOURNAL_CONTROL_STREAM', 'BRIDGE_JOURNAL_STREAM', 'BRIDGE_JOURNAL_CHANNEL',
              'BRIDGE_REPLAY_STREAM', 'BRIDGE_JOURNAL_MTU', 'BRIDGE_LOCAL_HOST', 'BRIDGE_DRIVER_MODE', 'BRIDGE_DRIVER_TIMEOUT_MS',
              'BRIDGE_AE_CLUSTER_ADDRESSES', 'BRIDGE_AE_PORT_BASE', 'CLUSTER_PORT_STRIDE', 'BRIDGE_AE_EGRESS_ENDPOINT',
              'AE_AUTH_CREDENTIAL', 'BRIDGE_INSTANCE_ID', 'BRIDGE_HTTP_BIND'}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def fx(self, driver='external'):
        return fixture_for(slot_manifest(self.dir, driver), self.dir)

    def test_forwarder_env_is_the_strict_set(self):
        for driver, extra in (('external', 'AERON_DIR'), ('embedded', 'FWD_DRIVER_DIR')):
            f = self.fx(driver)
            for slot, instance in (('fwd0', '21'), ('fwd1', '22')):
                env = f.slot_env(slot)
                with self.subTest(driver=driver, slot=slot):
                    self.assertEqual(set(env), self.FWD | {extra})
                    # the same env goes through the production-timeout guard, exactly as spawn() does
                    assert_production_timeouts(env, f.allowed_env())
                    self.assertEqual((env['FWD_DRIVER_MODE'], env['FWD_DRIVER_TIMEOUT_MS'], env['FWD_INSTANCE_ID']),
                                     (driver, '5000', instance))
                    self.assertEqual(env['FWD_HTTP_BIND'], f.m['nodes'][slot] + ':9700')
                    self.assertEqual(env['FWD_INGRESS_CHANNEL'], 'aeron:udp?term-length=4m|mtu=8192')
                    self.assertEqual(env['FWD_CORE_RESPONSE_CHANNEL'], 'aeron:udp?endpoint=' + f.m['nodes'][slot] + ':0')
                    self.assertTrue(env['ME_AUTH_CREDENTIAL'].startswith('121:' if slot == 'fwd0' else '122:'))
                    self.assertTrue(env['AE_AUTH_CREDENTIAL'].startswith(instance + ':FORWARDER:'))
            self.assertEqual(f.slot_env('fwd0')[extra], '/dev/shm/aeron-fwd0' if extra == 'AERON_DIR' else '/dev/shm/fwd-embedded')

    def test_bridge_env_is_the_strict_set(self):
        for driver, extra in (('external', 'AERON_DIR'), ('embedded', 'BRIDGE_DRIVER_DIR')):
            f = self.fx(driver)
            for slot, instance in (('bridge0', '31'), ('bridge1', '32')):
                env = f.slot_env(slot)
                with self.subTest(driver=driver, slot=slot):
                    self.assertEqual(set(env), self.BRIDGE | {extra})
                    self.assertNotIn('BRIDGE_HALT_ON_GAP', env)
                    assert_production_timeouts(env, f.allowed_env())
                    self.assertEqual((env['BRIDGE_JOURNAL_MTU'], env['BRIDGE_DRIVER_TIMEOUT_MS'], env['BRIDGE_INSTANCE_ID']),
                                     ('1408', '5000', instance))
                    self.assertEqual(env['BRIDGE_HTTP_BIND'], f.m['nodes'][slot] + ':9600')
                    self.assertEqual(env['BRIDGE_DRIVER_MODE'], driver)

    def test_me_credential_env_name_must_be_the_one_the_forwarder_reads(self):
        f = self.fx(); f.m['credentials']['me']['credential_env'] = 'ME_CLIENT_CREDENTIAL'
        with self.assertRaisesRegex(Violation, 'ME_AUTH_CREDENTIAL'):
            f.slot_env('fwd0')

    def test_allowed_env_equals_what_the_fixture_sets(self):
        names = set()
        for driver in ('external', 'embedded'):
            f = self.fx(driver)
            for engine in ('ae', 'me'):
                for i in range(3):
                    names |= set(f.engine_env(engine, i))
            names |= set(f.projector_env())
            for slot in ('fwd0', 'fwd1', 'bridge0', 'bridge1'):
                names |= set(f.slot_process_env(slot))
            for principal in (None, 'probe-admin'):
                names |= set(f.probe_env(principal))
            names |= set(core_fixture.DRIVER_ENV)
        f = self.fx()
        self.assertEqual(names, f.allowed_env())
        # every set value passes the guard
        assert_production_timeouts(core_fixture.DRIVER_ENV, f.allowed_env())

    def test_me_engine_env_asks_for_the_replicated_config(self):
        f = self.fx()
        self.assertEqual(f.engine_env('me', 0)['MATCH_ENGINE_FROM_CONFIG'], 'true')
        self.assertNotIn('MATCH_ENGINE_FROM_CONFIG', f.engine_env('ae', 0))

    def test_probe_driver_names_are_allowed_for_the_probe_only(self):
        f = self.fx()
        for slot in ('fwd0', 'bridge0'):
            with self.subTest(slot=slot), self.assertRaisesRegex(Violation, 'D20: environment names are an allowlist; refusing T1_ADMIN_KEY'):
                f.spawn(slot, ['true'], {'T1_ADMIN_KEY': 'x'})
        docker = Docker(f, ['probe', 'fwd0'])
        f.execute = types.MethodType(CoreFixture.execute, f)       # the real guard, over the stubbed command
        f.command = docker.command
        f.execute('probe', ['true'], environment=f.t1_env())
        for env in ({'T1_BRIDGE_KEY': 'x'}, {'T1_TAP_KEY': 'x'}, {'T1_ME_FORWARDER_KEY': 'x'}):
            with self.subTest(env=env), self.assertRaisesRegex(Violation, 'allowlist'):
                f.execute('probe', ['true'], environment=env)
        with self.assertRaisesRegex(Violation, 'allowlist'):
            f.execute('fwd0', ['true'], environment={'T1_ADMIN_KEY': 'x'})

    def test_t1_env_maps_the_probe_principals(self):
        f = self.fx(); env = f.t1_env()
        self.assertEqual(set(env), {'T1_ADMIN_KEY', 'T1_TOOL_KEY', 'T1_GATEWAY_KEY', 'T1_ME_ADMIN_KEY', 'T1_ME_MARKETS', 'T1_LOCAL_HOST'})
        self.assertTrue(env['T1_ADMIN_KEY'].startswith('12:ADMIN:') and env['T1_TOOL_KEY'].startswith('13:TOOL:'))
        self.assertTrue(env['T1_GATEWAY_KEY'].startswith('11:GATEWAY:') and env['T1_ME_ADMIN_KEY'].startswith('112:ADMIN:'))
        self.assertEqual((env['T1_ME_MARKETS'], env['T1_LOCAL_HOST']), ('5', f.m['nodes']['probe']))

    def test_redaction_covers_t1_values(self):
        f = self.fx(); docker = Docker(f, ['probe'])
        f.execute = types.MethodType(CoreFixture.execute, f)
        env = f.t1_env()
        secrets = {v.split(':')[2] for k, v in env.items() if k.endswith('_KEY')}
        self.assertTrue(secrets and secrets <= f.secret_values)
        completed = types.SimpleNamespace(returncode=0, stdout='echo ' + env['T1_ADMIN_KEY'], stderr='')
        with mock.patch.object(core_fixture.subprocess, 'run', return_value=completed):
            f.command = types.MethodType(CoreFixture.command, f)
            f.execute('probe', ['true'], environment=env)
        retained = (f.root / 'commands.jsonl').read_text() + ''.join(p.read_text() for p in (f.root / 'logs').glob('*.log'))
        for secret in secrets:
            self.assertNotIn(secret, retained)
        self.assertIn('<redacted>', retained)
        probe = f.root / 'state' / 'probe'; probe.mkdir(parents=True)
        (probe / 'core-requests.jsonl').write_text('{"args": "' + env['T1_TOOL_KEY'] + '"}\n')
        f.redact_probe_state()
        for secret in secrets:
            self.assertNotIn(secret, (probe / 'core-requests.jsonl').read_text())


class DriverWrapperTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def started(self, driver, slot):
        f = fixture_for(slot_manifest(self.dir, driver), self.dir)
        spawned, waits = [], []
        f.spawn = lambda name, command, env=None: spawned.append((name, command, env))
        f.wait_http = lambda name, port, path, **kw: waits.append((name, port, path)) or {'status': 200, 'body': '{"aeConnected": true}'}
        f.http = lambda name, port, path, **kw: {'status': 200, 'body': '{"aeConnected": true, "halted": false}'}
        f.driver_identity = lambda role: {'cnc_mtime': '1.0', 'started_at': 'S0'}
        f.registry.setdefault('driver_identity', {})
        row = f.start_slot(slot)
        return f, spawned, waits, row

    def test_slot_wrapper_prepares_the_driver_dir_in_both_modes(self):
        for slot, binary, directory in (('fwd0', '/artifacts/forwarder/bin', '/dev/shm/fwd-embedded'),
                                        ('bridge1', '/artifacts/bridge/bin', '/dev/shm/bridge-embedded')):
            _, spawned, _, _ = self.started('embedded', slot)
            command = spawned[0][1]
            self.assertEqual(command[:2], ['sh', '-c'])
            self.assertIn('mkdir -p ' + directory, command[2]); self.assertIn('exec ' + binary, command[2])
            self.assertNotIn('aeronmd', command[2])
        for slot, name in (('fwd1', 'forwarder'), ('bridge0', 'bridge')):
            _, spawned, _, _ = self.started('external', slot)
            script = spawned[0][1][2]
            self.assertEqual(spawned[0][1][:2], ['sh', '-c'])
            directory = '/dev/shm/aeron-' + slot
            self.assertIn('rm -rf ' + directory, script)
            self.assertLess(script.index('rm -rf'), script.index('mkdir -p'))
            self.assertIn('LD_LIBRARY_PATH=/artifacts/%s /artifacts/%s/aeronmd &' % (name, name), script)
            self.assertIn('AERON_DIR=%s AERON_DIR_DELETE' % directory, script)   # the driver gets its dir from the wrapper, not by luck
            self.assertIn('AERON_DIR_DELETE_ON_START=1', script); self.assertIn('AERON_DIR_DELETE_ON_SHUTDOWN=1', script)
            self.assertIn('echo $! > /data/aeronmd.pid', script)
            self.assertIn(directory + '/cnc.dat', script); self.assertIn('kill -0', script)
            self.assertLess(script.index('cnc.dat'), script.index('exec /artifacts/%s/bin' % name))
            self.assertIn('exit 1', script)    # a driver that never comes up fails the container, it is not skipped

    def run_wrapper(self, driver, fake_driver, wait_ticks=300):
        """Execute the generated wrapper under sh with /artifacts, /data and /dev/shm redirected into a temp dir."""
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'artifacts' / 'forwarder').mkdir(parents=True); (root / 'data').mkdir(); (root / 'shm').mkdir()
            (root / 'artifacts' / 'forwarder' / 'aeronmd').write_text(fake_driver)
            (root / 'artifacts' / 'forwarder' / 'bin').write_text('#!/bin/sh\necho "BIN ran with AERON_DIR=$AERON_DIR dir_exists=$([ -d "$AERON_DIR" ] && echo yes)"\n')
            for f in (root / 'artifacts' / 'forwarder').iterdir(): f.chmod(0o755)
            f = fixture_for(slot_manifest(self.dir, driver), self.dir)
            script = f.slot_command('fwd0')[2]
            script = (script.replace('/artifacts/', str(root / 'artifacts') + '/').replace('/data/', str(root / 'data') + '/')
                      .replace('/dev/shm/', str(root / 'shm') + '/').replace('-lt 300', '-lt %d' % wait_ticks))
            env = dict(os.environ, AERON_DIR=str(root / 'shm' / 'aeron-fwd0'))
            run = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=20, env=env)
            return run, (root / 'data' / 'aeronmd.pid').exists()

    def test_external_wrapper_starts_the_driver_then_execs_the_binary(self):
        fake = '#!/bin/sh\ntouch "$(dirname "$0")/../../shm/aeron-fwd0/cnc.dat"; sleep 1\n'
        run, pid_written = self.run_wrapper('external', fake)
        self.assertEqual((run.returncode, pid_written), (0, True), run.stderr)
        self.assertIn('BIN ran', run.stdout); self.assertIn('dir_exists=yes', run.stdout)

    def test_external_wrapper_fails_the_container_when_the_driver_never_comes_up(self):
        run, _ = self.run_wrapper('external', '#!/bin/sh\nexit 3\n', wait_ticks=3)
        self.assertEqual(run.returncode, 1); self.assertIn('aeronmd did not come up', run.stderr); self.assertNotIn('BIN ran', run.stdout)

    def test_embedded_wrapper_creates_the_dir_then_execs(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'artifacts' / 'forwarder').mkdir(parents=True); (root / 'shm').mkdir()
            binary = root / 'artifacts' / 'forwarder' / 'bin'
            binary.write_text('#!/bin/sh\n[ -d %s/shm/fwd-embedded ] && echo EMBEDDED_DIR_OK\n' % root); binary.chmod(0o755)
            f = fixture_for(slot_manifest(self.dir, 'embedded'), self.dir)
            script = f.slot_command('fwd0')[2].replace('/artifacts/', str(root / 'artifacts') + '/').replace('/dev/shm/', str(root / 'shm') + '/')
            run = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=20)
            self.assertIn('EMBEDDED_DIR_OK', run.stdout, run.stderr)

    def test_slot_readiness_is_ready_not_health(self):
        for slot, port in (('fwd0', 9700), ('bridge1', 9600)):
            for driver in ('embedded', 'external'):
                _, _, waits, row = self.started(driver, slot)
                with self.subTest(slot=slot, driver=driver):
                    self.assertEqual(waits, [(slot, port, '/ready')])
                    self.assertEqual(row['readiness'], '/ready'); self.assertEqual(row['state'], 'STARTED')

    def test_external_slot_records_its_driver_identity(self):
        f, _, _, row = self.started('external', 'fwd0')
        self.assertEqual(f.registry['driver_identity']['fwd0'], {'cnc_mtime': '1.0', 'started_at': 'S0'})
        self.assertEqual(row['driver'], 'external')
        f, _, _, row = self.started('embedded', 'fwd0')
        self.assertNotIn('fwd0', f.registry['driver_identity'])

    def test_probe_runs_its_own_aeronmd_only_when_probe_libs_are_pinned(self):
        f = fixture_for(slot_manifest(self.dir), self.dir)
        self.assertEqual(f.probe_command(), ['sleep', 'infinity'])
        f.m['probe_libs'] = {'aeronmd': {'path': '/x', 'sha256': '0' * 64, 'exec': True}}
        command = f.probe_command()
        self.assertEqual(command[:2], ['sh', '-c'])
        for text in ('rm -rf /dev/shm/probe-aeron', 'mkdir -p /dev/shm/probe-aeron', 'AERON_DIR=/dev/shm/probe-aeron AERON_DIR_DELETE', 'LD_LIBRARY_PATH=/artifacts/probe /artifacts/probe/aeronmd',
                     'cnc.dat', 'exec sleep infinity'):
            self.assertIn(text, command[2])


class StagingTest(unittest.TestCase):
    def test_lib_exec_flag_is_validated_and_applied(self):
        with tempfile.TemporaryDirectory() as temp:
            m = slot_manifest(temp)
            m['probe_libs'] = {'aeronmd': dict({k: v for k, v in write(temp, 'p-aeronmd', b'pm').items() if k != 'source_sha'}, exec=True),
                               'libaeron.so': {k: v for k, v in write(temp, 'p-libaeron.so', b'ps').items() if k != 'source_sha'}}
            for key in ('t1_me_driver', 't1_core_driver'):
                jar, src = write(temp, key + '.jar', key.encode()), write(temp, key + '.java', b's')
                m[key] = {'path': jar['path'], 'sha256': jar['sha256'], 'source_path': src['path'], 'source_sha256': src['sha256']}
            f = fixture_for(m, temp)
            f.stage_artifacts()
            mode = lambda *p: os.stat(f.root.joinpath('artifacts', *p)).st_mode & 0o777
            self.assertEqual(mode('forwarder', 'bin'), 0o755); self.assertEqual(mode('bridge', 'bin'), 0o755)
            self.assertEqual(mode('forwarder', 'aeronmd'), 0o755)
            self.assertEqual(mode('forwarder', 'libaeron.so') & 0o111, 0)
            self.assertEqual(mode('forwarder', 'libaeron_driver.so') & 0o111, 0)
            self.assertEqual(mode('probe', 'aeronmd'), 0o755); self.assertEqual(mode('probe', 'libaeron.so') & 0o111, 0)
            self.assertTrue(f.root.joinpath('artifacts', 't1-me-driver.jar').is_file())
            self.assertTrue(f.root.joinpath('artifacts', 't1-core-driver.jar').is_file())

    def test_staged_lib_changed_while_staging_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            m = slot_manifest(temp); f = fixture_for(m, temp)
            real = core_fixture.shutil.copyfile
            def tamper(src, dst):
                real(src, dst)
                if str(dst).endswith('aeronmd'): Path(dst).write_bytes(b'other')
            with mock.patch.object(core_fixture.shutil, 'copyfile', tamper), self.assertRaisesRegex(Violation, 'slot artifact changed while staging'):
                f.stage_artifacts()

    def test_limits_by_role_reach_docker_create(self):
        with tempfile.TemporaryDirectory() as temp:
            m = slot_manifest(temp)
            m['limits'].update(shm_mb_by_role={'me0': 1536, 'ae0': 768}, memory_mb_by_role={'me0': 3072})
            f = fixture_for(m, temp); docker = Docker(f, [])
            for role in ('me0', 'ae0', 'me1'):
                f.spawn(role, ['true'])
            create = {a[a.index('--name') + 1].rsplit('-', 1)[-1]: a for a in docker.calls if a[1] == 'create'}
            arg = lambda role, flag: create[role][create[role].index(flag) + 1]
            self.assertEqual((arg('me0', '--shm-size'), arg('me0', '--memory'), arg('me0', '--memory-swap')), ('1536m', '3072m', '3072m'))
            self.assertEqual((arg('ae0', '--shm-size'), arg('ae0', '--memory')), ('768m', '2048m'))
            self.assertEqual((arg('me1', '--shm-size'), arg('me1', '--memory')), ('1024m', '2048m'))


class FaultHelperTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = fixture_for(slot_manifest(self.temp.name), self.temp.name)
        self.docker = Docker(self.f, ['fwd0', 'fwd1', 'ae0', 'ae1', 'me0'])
        self.now = 1_000_000.0
        self.f.clock = lambda: self.now
        self.sleeps = []
        self.f.sleep = lambda s: (self.sleeps.append(s), setattr(self, 'now', self.now + s))
        self.f.wait_http = lambda *a, **k: {'status': 200, 'body': '{}'}
        self.f.registry.update(driver_identity={'fwd0': {'cnc_mtime': '100.5', 'started_at': 'S0'}}, fault_targets={}, faults=[])

    def tearDown(self):
        self.temp.cleanup()

    def test_pause_and_unpause_verify_state_and_return_witnesses(self):
        opened = self.f.pause('fwd0')
        self.assertEqual((opened['kind'], opened['target'], opened['before_paused'], opened['after_paused']), ('pause', 'fwd0', False, True))
        self.assertIn('fwd0', self.f.registry['fault_targets'])
        closed = self.f.unpause('fwd0')
        self.assertEqual((closed['kind'], closed['before_paused'], closed['after_paused']), ('unpause', True, False))
        self.assertEqual([r['kind'] for r in self.f.registry['faults']], ['pause', 'unpause'])
        with self.assertRaisesRegex(Inconclusive, 'not paused'):
            self.f.unpause('fwd0')
        self.f.pause('fwd1')
        with self.assertRaisesRegex(Inconclusive, 'already paused'):
            self.f.pause('fwd1')

    def test_pause_is_refused_for_unowned_targets(self):
        for name in ('probe', 'oms', 'shadow0'):
            with self.subTest(name=name), self.assertRaises(Violation):
                self.f.pause(name)

    def test_kill_records_the_witness_and_the_time_for_the_ae_restart_rule(self):
        witness = self.f.kill('ae0')
        self.assertEqual((witness['exit_code'], witness['kind']), (137, 'kill'))
        self.assertIn('ae0', self.f.registry['fault_targets'])
        self.assertEqual(self.f.registry['last_kill']['ae0']['at'], self.now)

    def test_restart_witness_requires_a_new_driver_pid(self):
        # W0 answer 5 / amendment A4: inside a container the aeronmd pid is always 9 and the cnc.dat inode always 6, so
        # the witness is the cnc.dat mtime plus the container StartedAt.
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=70, StartedAt='S0')
        self.docker.stat = {'S0': '100.5', 'S2': '106.7'}
        self.docker.stat.update({s: '106.7' for s in ('S1', 'S2', 'S3', 'S4', 'S5')})
        witness = self.f.restart('fwd0')
        self.assertEqual(witness['kind'], 'restart')
        self.assertEqual(witness['driver']['old'], {'cnc_mtime': '100.5', 'started_at': 'S0'})
        self.assertEqual(witness['driver']['new']['cnc_mtime'], '106.7')
        self.assertNotEqual(witness['driver']['new']['started_at'], 'S0')
        self.assertTrue(witness['ready'])
        self.assertEqual(self.f.registry['driver_identity']['fwd0'], witness['driver']['new'])
        self.assertNotIn('fwd0', self.f.registry['fault_targets'])
        # the heal is observed (ready), not the command issued
        self.assertEqual(self.docker.calls[-1][:2], ['docker', 'start'])

    def test_restart_with_a_stale_driver_is_inconclusive(self):
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=70)
        self.docker.stat = {s: '100.5' for s in ('S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6')}    # the dead driver's cnc.dat survived
        with self.assertRaisesRegex(Inconclusive, 'driver identity did not change'):
            self.f.restart('fwd0')

    def test_restart_refuses_a_running_container(self):
        with self.assertRaisesRegex(Inconclusive, 'still running'):
            self.f.restart('fwd0')

    def test_ae_restart_waits_until_12_5_s_after_the_kill_and_requires_ready(self):
        self.f.kill('ae0'); self.now += 4.0
        waits = []
        self.f.wait_http = lambda name, port, path, **k: waits.append((name, port, path)) or {'status': 200, 'body': ''}
        witness = self.f.restart('ae0')
        self.assertAlmostEqual(sum(self.sleeps), 8.5, places=2)
        self.assertEqual(waits, [('ae0', 19700, '/ready')])
        self.assertTrue(witness['ready']); self.assertEqual(witness['waited_after_kill_s'] >= 12.5, True)
        self.assertNotIn('ae0', self.f.registry['fault_targets'])

    def test_me_restart_has_no_kill_wait(self):
        self.f.kill('me0'); self.f.restart('me0')
        self.assertEqual(sum(self.sleeps), 0)

    def test_exec_kill_reads_the_pid_and_opens_a_fault_row(self):
        self.docker.exec_stdout = lambda argv: '9\n'
        witness = self.f.exec_kill('fwd0', '/data/aeronmd.pid', 'KILL')
        self.assertEqual((witness['kind'], witness['target'], witness['pidfile'], witness['pid'], witness['signal']),
                         ('exec_kill', 'fwd0', '/data/aeronmd.pid', 9, 'KILL'))
        argv = self.docker.exec_calls[-1][1]
        self.assertIn('/data/aeronmd.pid', ' '.join(argv)); self.assertIn('kill -KILL', ' '.join(argv))
        self.assertIn('fwd0', self.f.registry['fault_targets'])
        with self.assertRaises(Violation):
            self.f.exec_kill('fwd0', '/data/aeronmd.pid', 'STOP')    # no SIGSTOP from the fixture
        with self.assertRaises(Violation):
            self.f.exec_kill('fwd0', '/etc/passwd', 'KILL')

    def test_wait_exit_observes_the_exit_code(self):
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=70, FinishedAt='2026-11-02T10:00:05Z')
        witness = self.f.wait_exit('fwd0', 70, 10)
        self.assertEqual((witness['kind'], witness['exit_code']), ('exit', 70))
        with self.assertRaisesRegex(Inconclusive, 'exited 70, expected 137'):
            self.f.wait_exit('fwd0', 137, 10)
        with self.assertRaisesRegex(Inconclusive, 'did not exit within 3 s'):
            self.f.wait_exit('fwd1', 70, 3)


class FaultTargetWaitTest(unittest.TestCase):
    """F-S15-17: wait_http used to abort on ANY non-Running registered container."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = fixture_for(slot_manifest(self.temp.name), self.temp.name)
        self.docker = Docker(self.f, ['fwd0', 'fwd1', 'probe'])
        self.f.execute = lambda *a, **k: types.SimpleNamespace(stdout='{"status": 200, "body": ""}')
        self.polls = 0
        def http(name, port, path, **kw):
            self.polls += 1
            return {'status': 200 if self.polls >= 2 else 503, 'body': ''}
        self.f.http = http
        self.sleep = mock.patch.object(fixture_module.time, 'sleep', lambda s: None); self.sleep.start()

    def tearDown(self):
        self.sleep.stop(); self.temp.cleanup()

    def test_killed_fault_target_does_not_abort_a_wait_on_another_role(self):
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=137)
        self.f.registry['fault_targets'] = {'fwd0': {'row_id': 1, 'until_ns': time_ns_in(60)}}
        self.assertEqual(self.f.wait_http('fwd1', 9700, '/ready')['status'], 200)

    def test_unexpected_exit_still_aborts_readiness(self):
        self.docker.state['c-fwd1'].update(Running=False, ExitCode=1)
        self.f.registry['fault_targets'] = {'fwd0': {'row_id': 1, 'until_ns': time_ns_in(60)}}
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=137)
        with self.assertRaisesRegex(Inconclusive, 'fixture process fwd1 exited 1 before readiness'):
            self.f.wait_http('fwd1', 9700, '/ready')

    def test_fault_target_past_its_bound_aborts(self):
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=137)
        self.f.registry['fault_targets'] = {'fwd0': {'row_id': 1, 'until_ns': time_ns_in(-1)}}
        with self.assertRaisesRegex(Inconclusive, 'fixture process fwd0 exited 137 before readiness'):
            self.f.wait_http('fwd1', 9700, '/ready')

    def test_no_fault_table_is_the_old_behaviour(self):
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=137)
        with self.assertRaisesRegex(Inconclusive, 'fixture process fwd0 exited 137 before readiness'):
            self.f.wait_http('fwd1', 9700, '/ready')


def time_ns_in(seconds):
    import time
    return time.time_ns() + int(seconds * 1e9)


class GenesisOrderTest(unittest.TestCase):
    STEPS = ['snapshot_genesis', 'start_tap_witness', 'me_genesis', 'arm_money_journal', 'start_projector', 'start_bridges',
             'core_genesis', 'configure_risk', 'fund', 'verify_funded', 'start_forwarders']

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = fixture_for(slot_manifest(self.temp.name), self.temp.name)
        self.order = []
        for step in self.STEPS:
            setattr(self.f, step, lambda plan, step=step: self.order.append(step))
        self.f.registry['boot'] = {'started_ns': 0, 'phases': {}}

    def tearDown(self):
        self.temp.cleanup()

    def test_genesis_order_snapshot_tap_then_money(self):
        self.f.genesis({'users': [1, 2], 'funding': []})
        self.assertEqual(self.order, self.STEPS)
        phases = self.f.registry['boot']['phases']
        for name in ('genesis_snapshot_ns', 'tap_started_ns', 'me_genesis_ns', 'bridges_ready_ns', 'core_bound_ns', 'first_deposit_ns',
                     'funded_ns', 'forwarders_ready_ns'):
            self.assertIn(name, phases)
        values = [phases[n] for n in ('genesis_snapshot_ns', 'tap_started_ns', 'me_genesis_ns', 'bridges_ready_ns', 'core_bound_ns',
                                      'first_deposit_ns', 'funded_ns', 'forwarders_ready_ns')]
        self.assertEqual(values, sorted(values))

    def test_a_boot_whose_first_deposit_precedes_the_snapshot_or_tap_is_refused(self):
        good = {'genesis_snapshot_ns': 1, 'tap_started_ns': 2, 'me_genesis_ns': 3, 'bridges_ready_ns': 4, 'core_bound_ns': 5,
                'first_deposit_ns': 6, 'funded_ns': 7, 'forwarders_ready_ns': 8}
        core_fixture.check_genesis_order(good)
        for edit in ({'first_deposit_ns': 1}, {'first_deposit_ns': 1, 'genesis_snapshot_ns': 2}, {'tap_started_ns': 9}):
            with self.subTest(edit=edit), self.assertRaisesRegex(Violation, 'genesis snapshot after money moved'):
                core_fixture.check_genesis_order(dict(good, **edit))
        with self.assertRaisesRegex(Violation, 'genesis phase missing: tap_started_ns'):
            core_fixture.check_genesis_order({k: v for k, v in good.items() if k != 'tap_started_ns'})

    def test_genesis_id_is_the_odd_seed_and_recorded(self):
        self.assertEqual(self.f.genesis_id(), hex(self.f.m['seed'] | 1))


class TapRegistrationAndFundingGateTest(unittest.TestCase):
    """Review F5 (the tap's registration is observed, not slept on) and F4 (each funding row's gate is the tap's last
    GLOBAL admission row at deposit time, not the constant 'OPEN')."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.f = fixture_for(slot_manifest(self.temp.name), self.temp.name)
        self.probe = self.f.root / 'state' / 'probe'; self.probe.mkdir(parents=True)
        self.tap = self.probe / 'tap.jsonl'
        self.sessions = self.probe / 'tap.jsonl.sessions.jsonl'

    def tearDown(self):
        self.temp.cleanup()

    def note(self, event, at_ms):
        with self.sessions.open('a') as out:
            out.write(json.dumps({'event': event, 'at_ms': at_ms, 'session': 7, 'leader': 1}) + '\n')

    def admission(self, market, state, reason):
        with self.tap.open('a') as out:
            out.write(json.dumps({'tap': 'admission', 'row': {'market': market, 'state': state, 'reason': reason}}) + '\n')

    def test_tap_registration_is_observed_before_the_gate_changes(self):
        started = time.time_ns()
        sleeps = []

        def sleep(s):
            sleeps.append(s)
            if len(sleeps) == 3:
                self.note('registered', started // 1_000_000 + 10)
        self.f.sleep = sleep
        self.f.start_tap = lambda duration: self.tap
        self.f.start_tap_witness({'tap_ms': 1000})
        self.assertEqual(len(sleeps), 3)                  # it waited for the note, no fixed 3 s
        self.assertNotIn(3, sleeps)
        self.assertEqual(self.f.registry['tap']['registered_leader'], 1)

    def test_tap_that_never_registers_is_inconclusive(self):
        self.f.sleep = lambda s: None
        self.note('registered', 1)                         # a stale note from before this tap started does not count
        with self.assertRaisesRegex(Inconclusive, 'the tap did not register within 0 s'):
            self.f.wait_tap_registered(self.tap, time.time_ns(), bound_s=0)

    def test_funding_rows_record_the_observed_gate(self):
        self.f.registry['tap'] = {'path': str(self.tap)}
        self.admission(0, 'SUSPENDED', 'GENESIS')
        self.admission(1, 'SUSPENDED', 'GENESIS')
        calls = []

        def core(verb, principal, **kw):
            calls.append(kw)
            if len(calls) == 1:
                self.admission(0, 'OPEN', 'ADMIN')         # the gate opens between the first and the second deposit
            return 'ANSWERED', {'outcome': 'ACK'}
        self.f.core = core
        self.f.fund({'funding': [{'user': 1, 'asset': 0, 'amount': 5}, {'user': 2, 'asset': 1, 'amount': 6}]})
        rows = self.f.registry['funding']
        self.assertEqual([r['gate'] for r in rows], ['SUSPENDED', 'OPEN'])
        self.assertEqual(rows[0]['gate_witness'], {'source': 'tap', 'row': {'market': 0, 'state': 'SUSPENDED', 'reason': 'GENESIS'}})

    def test_funding_with_no_admission_row_records_no_gate(self):
        self.f.registry['tap'] = {'path': str(self.tap)}
        self.f.core = lambda verb, principal, **kw: ('ANSWERED', {'outcome': 'ACK'})
        self.f.fund({'funding': [{'user': 1, 'asset': 0, 'amount': 5}]})
        self.assertIsNone(self.f.registry['funding'][0]['gate'])     # never the constant 'OPEN'


class BarrierCountersTest(unittest.TestCase):
    def metrics(self, role):
        base = {'assets_settle_faults_total': 0.0, 'assets_settle_rejects_total': 0.0, 'assets_cluster_role': 1.0,
                'assets_order_stale_outcomes_total': 0.0, 'assets_order_redundant_outcomes_total': 0.0,
                'assets_order_stale_terminals_total': 0.0, 'assets_order_conflicts_total': 0.0, 'assets_released_late_total': 0.0}
        if role == 'ae1':
            base.update(assets_cluster_role=2.0, assets_order_stale_outcomes_total=5.0, assets_order_redundant_outcomes_total=16.0,
                        assets_order_stale_terminals_total=16.0, assets_order_conflicts_total=0.0,
                        assets_released_late_total=2.0)   # W3: Table D U1 joins sample.counters (O11)
        return base

    def stub(self, leaderless=False):
        f = types.SimpleNamespace(m={'ports': dict(core_contracts.PORT_PROFILE)})
        f.core = lambda verb, principal, **kw: ('ANSWERED', {'count': 0, 'head': 0, 'entries': []})
        f.me_open_legs = lambda: []
        f.metrics = lambda role, port: dict(self.metrics(role), assets_cluster_role=1.0) if leaderless else self.metrics(role)
        return f

    def run_observe(self, fixture):
        patches = [mock.patch.object(core_scenarios, 'money_dump', lambda f: {'balances': [], 'holds': [], 'lastAppliedTradeId': 0}),
                   mock.patch.object(core_scenarios, 'order_dump', lambda f: []),
                   mock.patch.object(core_scenarios, 'me_journal', lambda f: ([], True)),
                   mock.patch.object(core_scenarios, 'money_journal', lambda f: ([], []))]
        for p in patches: p.start()
        try:
            return core_scenarios.observe(fixture)
        finally:
            for p in patches: p.stop()

    def test_barrier_fills_counters(self):
        observed = self.run_observe(self.stub())
        self.assertEqual(observed['counters'], {'stale_outcomes': 5, 'redundant_outcomes': 16, 'stale_terminals': 16, 'conflicts': 0,
                                                'released_late': 2})

    def test_no_ae_leader_at_the_barrier_is_inconclusive(self):
        with self.assertRaisesRegex(Inconclusive, 'no AE leader'):
            self.run_observe(self.stub(leaderless=True))


class MeRefusalControlTest(unittest.TestCase):
    def test_core_boot_me_refusal_control(self):
        result = lambda rc, out: types.SimpleNamespace(returncode=rc, stdout=out, stderr='')
        f = types.SimpleNamespace(m={'credentials': {'me': {'mode': 'enforced'}}})
        f.me_open_legs_unauthenticated = lambda: result(1, 'Exception in thread main io.aeron.cluster.client.AuthenticationException: session failed authentication')
        self.assertEqual(core_scenarios.me_refusal_control(f), {'result': 'REFUSED', 'error': 'AuthenticationException'})
        f.me_open_legs_unauthenticated = lambda: result(0, '{"legs": []}')
        with self.assertRaisesRegex(Violation, 'ME session without a credential was not refused'):
            core_scenarios.me_refusal_control(f)
        f.me_open_legs_unauthenticated = lambda: result(1, 'cluster connect timeout')
        with self.assertRaisesRegex(Inconclusive, 'not by an authentication refusal'):
            core_scenarios.me_refusal_control(f)
        f.m = {'credentials': {'me': {'mode': 'not_enforced_by_artifact'}}}
        self.assertTrue(str(core_scenarios.me_refusal_control(f)).startswith('NOT_ENFORCED_BY_ARTIFACT'))


class DrillConstructorTest(unittest.TestCase):
    def test_drill_constructor_refuses_a_non_enforced_me_before_touching_the_box(self):
        with tempfile.TemporaryDirectory() as temp:
            m = manifest(temp); path = Path(temp) / 'm.json'; path.write_text(json.dumps(m))
            with self.assertRaisesRegex(Violation, 'ME credential mode must be enforced for drills'):
                CoreFixture(path, drill=True)
            self.assertFalse(Path(m['state_root']).exists())


class BuildProbesCtDirTest(unittest.TestCase):
    def test_driver_sources_come_from_the_ct_tree(self):
        import build_core_probes
        with tempfile.TemporaryDirectory() as temp:
            ct = Path(temp); it = ct / 'app' / 'forwarder' / 'it'; it.mkdir(parents=True)
            with self.assertRaisesRegex(SystemExit, 'T1MeDriver.java'):
                build_core_probes.driver_sources(ct)
            (it / 'T1MeDriver.java').write_text('class T1MeDriver {}'); (it / 'T1CoreDriver.java').write_text('class T1CoreDriver {}')
            sources = build_core_probes.driver_sources(ct)
            self.assertEqual(sorted(sources), ['t1_core_driver', 't1_me_driver'])
            self.assertEqual(sources['t1_me_driver']['source'], it / 'T1MeDriver.java')
            self.assertEqual(sources['t1_me_driver']['main_class'], 'T1MeDriver')
            self.assertEqual(sources['t1_core_driver']['classpath_arg'], '--ae-jar')
            self.assertEqual(sources['t1_me_driver']['classpath_arg'], '--me-jar')


if __name__ == '__main__':
    unittest.main()
