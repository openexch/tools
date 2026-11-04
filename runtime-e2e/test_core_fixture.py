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
            for mode in ('embedded', 'external'):      # RC2 S17 W2: the projector_driver key
                names |= set(fixture_for(dict(f.m, projector_driver=mode), self.dir).projector_env())
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
        self.tap = self.probe / 'tap-life1.jsonl'                 # S16 5.1: per-life tap files
        self.sessions = self.probe / 'tap-life1.sessions.jsonl'

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
        self.f.start_tap = lambda duration, life=1: self.tap
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


# ======================================================================================================
# RC2 S16 W1 (contract 5.1, 5.2, 5.3 and the 20.1 amendments): fixture v4. Each test was RED on a693555 first.
# ======================================================================================================

import zipfile

# the pinned production keys of me/deploy/media-driver/driver.properties at c53dd20 (contract 5.3)
DP_TEXT = '''# external driver tuning (test copy of the pinned keys)
aeron.dir.delete.on.start=true
aeron.dir.delete.on.shutdown=true
aeron.term.buffer.sparse.file=false
aeron.term.buffer.length=16m
aeron.ipc.term.buffer.length=16m
aeron.mtu.length=8192
aeron.socket.so_sndbuf=4m
aeron.socket.so_rcvbuf=4m
aeron.rcv.initial.window.length=4m
aeron.timer.interval=500us
aeron.client.liveness.timeout=5s
aeron.publication.unblock.timeout=10s
aeron.untethered.window.limit.timeout=100ms
aeron.untethered.resting.timeout=100ms
'''
DEV_TEXT = '''aeron.threading.mode=SHARED
aeron.conductor.idle.strategy=backoff
aeron.sender.idle.strategy=backoff
aeron.receiver.idle.strategy=backoff
aeron.shared.idle.strategy=backoff
'''


def plain(entry):
    return {k: v for k, v in entry.items() if k != 'source_sha'}


def engine_libs(directory, props=DP_TEXT, overlay=DEV_TEXT):
    return {'aeronmd': dict(plain(write(directory, 'e-aeronmd', b'emd')), exec=True),
            'libaeron_driver.so': plain(write(directory, 'e-libaeron_driver.so', b'esod')),
            'libaeron.so': plain(write(directory, 'e-libaeron.so', b'eso')),
            'driver.properties': plain(write(directory, 'e-driver.properties', props.encode())),
            'driver-dev.properties': plain(write(directory, 'e-driver-dev.properties', overlay.encode()))}


def ext_manifest(directory, engines='external'):
    m = slot_manifest(directory)
    m['artifacts']['forwarder_b'] = dict(write(directory, 'fwd-b.bin', b'elf-forwarder-b'), driver='external',
                                         libs=m['artifacts']['forwarder']['libs'], target='ct-forwarder')
    m['artifacts']['forwarder']['target'] = 'ct-forwarder'
    m['artifacts']['bridge']['target'] = 'ct-bridge'
    m['engine_driver'] = engines
    if engines == 'external':
        m['engine_libs'] = engine_libs(directory)
    return m


class Clock:
    def __init__(self):
        self.now, self.sleeps = 1_000_000.0, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds); self.now += seconds


OK = types.SimpleNamespace(stdout='', stderr='', returncode=0)


class Docker4(Docker):
    """Docker plus SIGTERM stops (``docker kill --signal=TERM`` then ``docker stop -t N``), rm, logs, scripted exits on start
    and a cnc.dat mtime that changes with every container start (the driver identity)."""

    def __init__(self, fixture, roles, clock):
        super().__init__(fixture, roles)
        self.clock, self.polite, self.start_exits, self.removed, self.stale_driver = clock, {}, {}, [], False

    def command(self, argv, **kw):
        argv = [str(a) for a in argv]
        if argv[:3] == ['docker', 'kill', '--signal=TERM']:
            self.calls.append(argv); return OK
        if argv[:3] == ['docker', 'stop', '-t']:
            self.calls.append(argv)
            bound, state = int(argv[3]), self.state[argv[4]]
            code, seconds = self.polite.get(argv[4][2:], (137, None))
            if seconds is None or seconds > bound:
                code, seconds = 137, bound
            self.clock.now += seconds
            state.update(Running=False, ExitCode=code, FinishedAt='F%d' % len(self.calls))
            return OK
        if argv[:2] == ['docker', 'rm']:
            self.calls.append(argv); self.removed.append(argv[-1]); self.state.pop(argv[-1]); return OK
        if argv[:2] == ['docker', 'logs']:
            self.calls.append(argv); return types.SimpleNamespace(stdout='log of ' + argv[-1] + '\n', stderr='', returncode=0)
        result = super().command(argv, **kw)
        if argv[:2] == ['docker', 'start']:
            queue = self.start_exits.get(argv[2][2:])
            if queue:
                code = queue.pop(0)
                if code is not None:
                    self.state[argv[2]].update(Running=False, ExitCode=code)
        return result

    def execute(self, name, argv, **kw):
        if 'stat -c' in ' '.join(argv):
            self.exec_calls.append((name, argv, kw))
            mtime = '7.5' if self.stale_driver else self.state['c-' + name]['StartedAt'][1:] + '.5'
            return types.SimpleNamespace(stdout=mtime + '\n', stderr='', returncode=0)
        return super().execute(name, argv, **kw)


class V4Base(unittest.TestCase):
    ROLES = ('probe', 'fwd0', 'fwd1', 'bridge0', 'bridge1', 'projector', 'ae0', 'ae1', 'ae2', 'me0', 'me1', 'me2')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def fx(self, m=None, roles=ROLES):
        f = fixture_for(m or ext_manifest(self.dir), self.dir)
        self.clock = Clock(); f.clock = self.clock; f.sleep = self.clock.sleep
        self.docker = Docker4(f, roles, self.clock)
        f.registry.update(fault_targets={}, faults=[])
        self.health = {'aeConnected': True}
        f.http = lambda name, port, path, **kw: {'status': 200, 'body': json.dumps(self.health)}
        f.wait_http = lambda *a, **k: {'status': 200, 'body': '{}'}
        for role in roles:
            (f.root / 'state' / role).mkdir(parents=True, exist_ok=True)
        return f


class StopTest(V4Base):
    def test_stop_bounds_and_exit_codes_per_role(self):
        f = self.fx()
        self.docker.polite.update(fwd0=(0, 0.2), fwd1=(143, 0.1), bridge0=(0, 0.15), ae0=(0, 2.0))
        w = f.stop('fwd0')
        self.assertEqual((w['kind'], w['target'], w['exit_code'], w['bound_s'], w['elapsed_s'], w['within_contract']),
                         ('stop', 'fwd0', 0, 3, 0.2, True))
        self.assertEqual(self.docker.calls[-2][:3], ['docker', 'kill', '--signal=TERM'])
        self.assertEqual(self.docker.calls[-1][:4], ['docker', 'stop', '-t', '3'])
        self.assertIn('fwd0', f.registry['fault_targets'])
        with self.assertRaisesRegex(Inconclusive, 'polite stop exited 143'):
            f.stop('fwd1')
        self.assertEqual(f.registry['faults'][-1]['exit_code'], 143)        # the witness is recorded before the verdict
        self.assertEqual(f.stop('bridge0')['bound_s'], 10)
        with self.assertRaisesRegex(Inconclusive, 'polite stop exited 137'):
            f.stop('bridge1')                                                # never exits on SIGTERM: killed at 10 s
        self.assertEqual(f.registry['faults'][-1]['elapsed_s'], 10)
        w = f.stop('me0')                                                    # 20.1 line 4: 15 s bound, then kill, 137 kept
        self.assertEqual((w['exit_code'], w['bound_s'], w['escalated_to_kill']), (137, 15, True))
        self.assertIn('me0', f.registry['last_kill'])                        # the 12.5 s AE rule sees an escalated stop
        self.assertEqual(f.stop('ae0')['exit_code'], 0)
        self.assertNotIn('ae0', f.registry.get('last_kill', {}))
        with self.assertRaisesRegex(Inconclusive, 'not running'):
            f.stop('fwd0')
        for bad in (('probe',), ('fwd1', 'KILL'), ('fwd1', 'STOP')):
            with self.subTest(bad=bad), self.assertRaises(Violation):
                f.stop(*bad)


class ReplaceSlotTest(V4Base):
    def test_replace_slot_records_both_shas_refuses_same_binary_and_closes_the_fault_row(self):
        f = self.fx()
        f.slots['fwd0'] = {'state': 'STARTED', 'artifact': 'forwarder'}
        self.docker.polite.update(fwd0=(0, 0.1))
        with self.assertRaisesRegex(Violation, 'replace_slot needs the slot stopped'):
            f.replace_slot('fwd0', 'forwarder_b')
        (f.root / 'state' / 'fwd0' / 'old.txt').write_text('gen0')
        f.stop('fwd0')
        self.health = {'aeConnected': True, 'build': 'b' * 40}
        w = f.replace_slot('fwd0', 'forwarder_b')
        a, b = f.m['artifacts']['forwarder'], f.m['artifacts']['forwarder_b']
        self.assertEqual(w['old'], {'artifact': 'forwarder', 'sha256': a['sha256'], 'source_sha': a['source_sha']})
        self.assertEqual(w['new'], {'artifact': 'forwarder_b', 'sha256': b['sha256'], 'source_sha': b['source_sha']})
        self.assertEqual((w['kind'], w['build_health'], w['f7_rejected']), ('replace_slot', 'b' * 40, 0))
        self.assertIn('ready_after_s', w)
        self.assertEqual((f.root / 'state' / 'fwd0.gen1' / 'old.txt').read_text(), 'gen0')   # evidence kept
        self.assertTrue((f.root / 'state' / 'fwd0').is_dir())
        self.assertIn('c-fwd0', self.docker.removed)
        self.assertTrue((f.root / 'logs' / 'fwd0.gen1.log').read_text().startswith('log of c-fwd0'))
        self.assertEqual(f.registry['slot_override']['fwd0'], 'forwarder_b')
        self.assertEqual(f.slots['fwd0']['artifact'], 'forwarder_b')
        self.assertEqual(f.registry['slots']['fwd0']['artifact'], 'forwarder_b')
        create = [c for c in self.docker.calls if c[:2] == ['docker', 'create']][-1]
        self.assertIn('exec /artifacts/forwarder_b/bin', create[-1])
        self.assertNotIn('fwd0', f.registry['fault_targets'])                # closed on /ready 200
        f.stop('fwd0')
        with self.assertRaisesRegex(Violation, 'replace_slot with the same binary is not a swap'):
            f.replace_slot('fwd0', 'forwarder_b')
        w = f.replace_slot('fwd0', 'forwarder')                              # back to A: gen2
        self.assertTrue((f.root / 'state' / 'fwd0.gen2').is_dir())
        self.assertEqual(w['old']['artifact'], 'forwarder_b')
        self.docker.polite.update(fwd1=(0, 0.1)); f.stop('fwd1')
        for artifact, text in (('bridge_b', 'absent from the manifest'), ('bridge', 'cannot run'), ('nope', 'absent from the manifest')):
            with self.subTest(artifact=artifact), self.assertRaisesRegex(Violation, text):
                f.replace_slot('fwd1', artifact)

    def test_replace_slot_after_kill_restarts_once_after_the_session_window(self):
        f = self.fx()
        f.kill('fwd1'); killed_at = self.clock.now
        self.docker.start_exits['fwd1'] = [78, None]                        # F-S16-11: REJECTED registration, exit 78
        w = f.replace_slot('fwd1', 'forwarder_b', after_kill=True)
        self.assertEqual(w['f7_rejected'], 1)
        starts = [c for c in self.docker.calls if c[:2] == ['docker', 'start'] and c[2] == 'c-fwd1']
        self.assertEqual(len(starts), 2)
        self.assertGreaterEqual(self.clock.now - killed_at, core_fixture.SESSION_WINDOW_S)
        self.assertTrue(any(p.name.startswith('fwd1.gen1-f7') for p in (f.root / 'logs').iterdir()))
        self.assertNotIn('fwd1', f.registry['fault_targets'])
        self.assertEqual(w['ready_after_kill_bound_s'], core_fixture.READY_AFTER_KILL_S)
        # a polite stop leaves no kill witness: after_kill is refused (the kill witness belonged to the replaced container)
        self.docker.polite.update(fwd1=(0, 0.1)); f.stop('fwd1')
        with self.assertRaisesRegex(Violation, 'after_kill needs a kill witness'):
            f.replace_slot('fwd1', 'forwarder', after_kill=True)

    def test_replace_slot_refuses_a_replacement_that_exits(self):
        f = self.fx()
        self.docker.polite.update(fwd0=(0, 0.1)); f.stop('fwd0')
        self.docker.start_exits['fwd0'] = [1]
        with self.assertRaisesRegex(Inconclusive, 'replacement fwd0 exited 1'):
            f.replace_slot('fwd0', 'forwarder_b')


class WipeEngineTest(V4Base):
    def test_wipe_engine_refuses_a_running_member(self):
        f = self.fx()
        state = f.root / 'state' / 'me0'
        (state / 'state' / 'archive').mkdir(parents=True)
        (state / 'state' / 'archive' / 'rec.dat').write_bytes(b'x' * 100); (state / 'aeronmd.pid').write_text('9\n')
        with self.assertRaisesRegex(Violation, 'wipe_engine refuses a running member'):
            f.wipe_engine('me0')
        self.assertTrue((state / 'aeronmd.pid').exists())
        f.stop('me0')
        w = f.wipe_engine('me0')
        self.assertEqual((w['kind'], w['target'], w['bytes_removed'], w['files_removed']), ('wipe_engine', 'me0', 102, 2))
        self.assertIn('state/archive/rec.dat', w['listing_before'])
        self.assertTrue(state.is_dir()); self.assertEqual(list(state.iterdir()), [])
        self.assertIn('me0', f.registry['fault_targets'])
        with self.assertRaises(Violation):
            f.wipe_engine('fwd0')

    def test_wipe_engine_refuses_an_ae_member_without_its_life_projection_dump(self):
        """S16 fix round V6: the AE is the life's money source; its wipe needs that life's PG dump (precondition).
        RED f42a1c6: wipe_engine('ae0') wiped with no dump."""
        f = self.fx()
        state = f.root / 'state' / 'ae0'
        (state / 'snap.dat').write_bytes(b'y' * 10)
        self.docker.state['c-ae0'].update(Running=False, ExitCode=143)
        with self.assertRaisesRegex(Violation, r'wipe_engine refuses ae0: no projection dump of core life 1 \(reset_projection first\)'):
            f.wipe_engine('ae0')
        self.assertTrue((state / 'snap.dat').exists())
        dump = f.root / 'lives' / 'life-1' / 'money_journal.pg.jsonl'
        dump.parent.mkdir(parents=True); dump.write_text('{"table": "t", "row": {}}\n')
        f.registry['projection_dumps'] = {'1': {'dump': str(dump), 'sha256': hashlib.sha256(dump.read_bytes()).hexdigest()}}
        dump.write_text('changed\n')
        with self.assertRaisesRegex(Violation, 'projection dump is missing or changed'):
            f.wipe_engine('ae0')
        f.registry['projection_dumps']['1']['sha256'] = hashlib.sha256(dump.read_bytes()).hexdigest()
        self.assertEqual(f.wipe_engine('ae0')['bytes_removed'], 10)
        self.assertEqual(list(state.iterdir()), [])
        # a dump of another life does not count
        f.registry['lives'] = {'1': {'core': {}}, '2': {'core': {}}}
        (state / 'x').write_text('z')
        with self.assertRaisesRegex(Violation, 'no projection dump of core life 2'):
            f.wipe_engine('ae0')


class ResetProjectionTest(V4Base):
    def test_reset_projection_dumps_before_drop(self):
        m = ext_manifest(self.dir)
        jar = Path(self.dir) / 'projector-mig.jar'
        with zipfile.ZipFile(jar, 'w') as z:
            z.writestr('db/migration/V1__money.sql', 'CREATE TABLE money_journal (journal_seq bigint);')
        m['artifacts']['projector']['path'] = str(jar)
        f = self.fx(m)
        f.registry.update(lives={'1': {'core': {'genesis_id': '0x1'}}})
        self.docker.polite.update(projector=(0, 0.3))
        calls = []
        dump = f.root / 'lives' / 'life-1' / 'money_journal.pg.jsonl'

        def psql(db, sql):
            calls.append((db, sql))
            if sql.startswith('DROP DATABASE'):
                self.assertTrue(dump.exists() and dump.read_text().count('\n') == 3, 'dump written before the drop')
            if 'information_schema.tables' in sql:
                return '["money_journal", "money_journal_leg"]'
            if 'FROM "money_journal" t' in sql:
                return '[{"journal_seq": 1}, {"journal_seq": 2}]'
            if 'FROM "money_journal_leg" t' in sql:
                return '[{"journal_seq": 1, "leg_no": 0}]'
            return ''
        f.psql = psql
        w = f.reset_projection()
        sqls = [s for _, s in calls]
        drop = next(i for i, s in enumerate(sqls) if s.startswith('DROP DATABASE r01_money'))
        self.assertLess(max(i for i, s in enumerate(sqls) if ' t' in s and 'json_agg' in s), drop)
        self.assertEqual(sqls[drop + 1], 'CREATE DATABASE r01_money')
        self.assertIn('CREATE TABLE money_journal', sqls[-1])               # packaged migrations re-applied
        self.assertEqual((w['kind'], w['life'], w['tables']), ('reset_projection', 1, {'money_journal': 2, 'money_journal_leg': 1}))
        self.assertEqual(json.loads(dump.read_text().splitlines()[0]), {'table': 'money_journal', 'row': {'journal_seq': 1}})
        self.assertEqual(f.registry['projection_dumps']['1'],                    # V6: the wipe precondition's record
                         {'dump': str(dump), 'sha256': hashlib.sha256(dump.read_bytes()).hexdigest()})
        stop = [c for c in self.docker.calls if c[:3] == ['docker', 'stop', '-t']][-1]
        self.assertEqual(stop[-1], 'c-projector')


G1 = hex(1 | 1)


def life1(f):
    """The registry after a life-1 genesis (fixture.genesis on a plan)."""
    g1 = f.genesis_id(1)
    f.registry.update(lives={'1': {'me': {'genesis_id': g1}, 'core': {'genesis_id': g1}}},
                      boot={'started_ns': 0, 'phases': {}}, tap={'path': str(f.root / 'state/probe/tap-life1.jsonl')},
                      funding=[{'kind': 'deposit', 'user': 1}], genesis={'genesis_id': g1}, genesis_snapshot={'verified': True},
                      risk={'1': {}})
    return g1


class RegenesisTest(V4Base):
    CORE_STEPS = ['snapshot_genesis', 'start_tap_witness', 'arm_money_journal', 'start_projector', 'start_bridges',
                  'core_genesis', 'configure_risk', 'fund', 'verify_funded', 'start_forwarders']

    def recorded(self, f, names):
        calls = []
        for name in names:
            setattr(f, name, lambda *a, name=name, **k: calls.append((name,) + a) or {'kind': name})
        return calls

    def test_genesis_id_per_life_is_odd_and_distinct(self):
        f = self.fx()
        ids = [f.genesis_id(n) for n in (1, 2, 3, 4)]
        self.assertEqual(ids[0], hex(f.m['seed'] | 1)); self.assertEqual(f.genesis_id(), ids[0])
        self.assertEqual(ids[1], hex((f.m['seed'] | 1) + 2))
        self.assertTrue(all(int(i, 16) % 2 == 1 for i in ids)); self.assertEqual(len(set(ids)), 4)
        with self.assertRaises(Violation):
            f.genesis_id(0)

    def test_regenesis_me_uses_a_new_odd_genesis_id(self):
        f = self.fx(); g1 = life1(f)
        calls = self.recorded(f, ['stop', 'wipe_engine', 'start_members'])
        driven = []
        f._driver = lambda key, main, *args, **kw: driven.append((key, main) + args)
        w = f.regenesis({'ledger_capacity': 2000}, 'me')
        g2 = hex(int(g1, 16) + 2)
        self.assertEqual([c[:2] for c in calls], [('stop', 'me0'), ('stop', 'me1'), ('stop', 'me2'), ('wipe_engine', 'me0'),
                                                  ('wipe_engine', 'me1'), ('wipe_engine', 'me2'), ('start_members', 'me')])
        self.assertEqual(driven[0][2], 'genesis'); self.assertEqual(driven[0][5], g2); self.assertEqual(driven[0][6], 2000)
        self.assertEqual(f.registry['lives']['2']['me']['genesis_id'], g2)
        self.assertEqual(f.life('me'), 2); self.assertEqual(f.life('core'), 1)       # the core is still bound to g1
        self.assertEqual((w['kind'], w['scope'], w['life'], w['genesis_id']), ('regenesis', 'me', 2, g2))
        for fwd in ('fwd0', 'fwd1'):         # they exit 78 (F8_EPOCH) during the ME start: registered, not unexpected
            self.assertIn(fwd, f.registry['fault_targets'])
        self.assertIn('me_genesis_ns', f.registry['boot']['lives']['2']['me_phases'])
        with self.assertRaisesRegex(Violation, 'scope'):
            f.regenesis({}, 'both')

    def test_regenesis_core_runs_every_phase_on_a_new_life(self):
        f = self.fx(); g1 = life1(f)
        g2 = hex(int(g1, 16) + 2)
        f.registry['lives']['2'] = {'me': {'genesis_id': g2}}
        f.registry['boot']['lives'] = {'2': {'me_phases': {}}}
        self.docker.state['c-fwd0'].update(Running=False, ExitCode=78)
        self.docker.state['c-fwd1'].update(Running=False, ExitCode=78)
        calls = self.recorded(f, ['stop', 'wipe_engine', 'reset_projection', 'start_members'] + self.CORE_STEPS)
        w = f.regenesis({'users': [1]}, 'core')
        names = [c[:2] if c[0] in ('stop', 'wipe_engine', 'start_members') else c[:1] for c in calls]
        # V6: the projection is dumped before the AE is wiped (RED f42a1c6: the three wipes came first)
        self.assertEqual(names, [('stop', 'bridge0'), ('stop', 'bridge1'), ('stop', 'ae0'), ('stop', 'ae1'), ('stop', 'ae2'),
                                 ('reset_projection',), ('wipe_engine', 'ae0'), ('wipe_engine', 'ae1'), ('wipe_engine', 'ae2'),
                                 ('start_members', 'ae')] + [(s,) for s in self.CORE_STEPS])
        phases = f.registry['boot']['lives']['2']['phases']
        core_fixture.check_genesis_order(phases, expected=core_fixture.LIFE2_CORE_PHASES)
        self.assertNotIn('me_genesis_ns', phases)
        self.assertEqual(f.registry['lives']['2']['core']['genesis_id'], g2); self.assertEqual(f.life('core'), 2)
        self.assertEqual(f.registry['genesis']['genesis_id'], g2)
        self.assertEqual(f.registry['lives']['1']['records']['funding'], [{'kind': 'deposit', 'user': 1}])  # life 1 kept
        self.assertEqual(w['forwarders_exited'], {'fwd0': 78, 'fwd1': 78})
        # the forwarders already exited (A04): recorded, not stopped; a Running forwarder is stopped
        f2 = self.fx(); life1(f2); f2.registry['lives']['2'] = {'me': {'genesis_id': g2}}
        calls = self.recorded(f2, ['stop', 'wipe_engine', 'reset_projection', 'start_members'] + self.CORE_STEPS)
        f2.regenesis({}, 'core')
        self.assertEqual([c[1] for c in calls if c[0] == 'stop'][:2], ['fwd0', 'fwd1'])

    def test_regenesis_core_needs_an_me_regenesis_first(self):
        f = self.fx(); life1(f)
        with self.assertRaisesRegex(Violation, 'regenesis core needs the ME re-genesis of life 2 first'):
            f.regenesis({}, 'core')

    def test_regenesis_never_respawns_an_existing_container(self):
        f = self.fx(); life1(f)
        for role in ('projector', 'bridge0', 'bridge1', 'fwd0', 'fwd1'):
            self.docker.state['c-' + role].update(Running=False, ExitCode=0)
        f.spawn = lambda *a, **k: self.fail('spawn of an existing container: ' + a[0])
        restarted = []
        f.restart = lambda name, **kw: restarted.append(name) or {'kind': 'restart', 'target': name}
        f.registry['slots'] = {}
        for step in ('start_projector', 'start_bridges', 'start_forwarders'):
            getattr(f, step)({})
        self.assertEqual(restarted, ['projector', 'bridge0', 'bridge1', 'fwd0', 'fwd1'])
        self.assertEqual(f.slots['bridge0']['state'], 'STARTED'); self.assertEqual(f.slots['fwd1']['artifact'], 'forwarder')
        self.assertEqual(f.slots['shadow0']['state'], 'RESERVED')

    def test_check_genesis_order_accepts_life2_without_me_genesis(self):
        life2 = {'genesis_snapshot_ns': 1, 'tap_started_ns': 2, 'bridges_ready_ns': 4, 'core_bound_ns': 5,
                 'first_deposit_ns': 6, 'funded_ns': 7, 'forwarders_ready_ns': 8}
        core_fixture.check_genesis_order(life2, expected=core_fixture.LIFE2_CORE_PHASES)
        with self.assertRaisesRegex(Violation, 'genesis phase missing: me_genesis_ns'):
            core_fixture.check_genesis_order(life2)
        with self.assertRaisesRegex(Violation, 'genesis snapshot after money moved'):
            core_fixture.check_genesis_order(dict(life2, first_deposit_ns=0), expected=core_fixture.LIFE2_CORE_PHASES)


class PerLifeTapTest(V4Base):
    def test_tap_files_are_per_life(self):
        f = self.fx()
        path = f.start_tap(1000, life=2)
        script = self.docker.calls[-1][-1]
        for text in ('out=/data/tap-life2.jsonl', 'sessions=/data/tap-life2.sessions.jsonl', '> /data/tap-life2.out',
                     '2> /data/tap-life2.err', 'duration_ms=1000'):
            self.assertIn(text, script)
        self.assertEqual(path, f.root / 'state' / 'probe' / 'tap-life2.jsonl')
        probe = f.root / 'state' / 'probe'
        (probe / 'tap-life2.out').write_text('TAP first=1 last=3 rows=3 gaps=[]\n'
                                             '{"verb": "tap", "rows": 3, "sessions_file": "/data/tap-life2.sessions.jsonl"}\n')
        (probe / 'tap-life2.sessions.jsonl').write_text('{"event": "registered", "at_ms": 1}\n')
        summary = f.read_tap_summary(2)
        self.assertEqual((summary['line'][:11], summary['transitions'][0]['event']), ('TAP first=1', 'registered'))
        with self.assertRaisesRegex(Inconclusive, 'no TAP density line'):
            f.read_tap_summary(1)
        # start_tap_witness on life 2: the record lives under lives[2]; registry['tap'] is the current life's
        f.registry['lives'] = {'1': {'core': {}}, '2': {'core': {}}}
        f.wait_tap_registered = lambda path, started_ns, **kw: {'at_ms': 5, 'leader': 1, 'sessions': kw.get('sessions')}
        f.start_tap_witness({'tap_ms': 2000})
        self.assertEqual(f.registry['tap']['path'], str(probe / 'tap-life2.jsonl'))
        self.assertIs(f.registry['lives']['2']['tap'], f.registry['tap'])
        self.assertEqual(f.registry['tap']['life'], 2)

    def test_wait_tap_registered_reads_the_life_sessions_file(self):
        f = self.fx(); f.sleep = lambda s: None
        probe = f.root / 'state' / 'probe'
        started = time.time_ns()
        (probe / 'tap-life2.sessions.jsonl').write_text(json.dumps({'event': 'registered', 'at_ms': started // 1_000_000,
                                                                    'leader': 2}) + '\n')
        note = f.wait_tap_registered(probe / 'tap-life2.jsonl', started, bound_s=0, sessions=probe / 'tap-life2.sessions.jsonl')
        self.assertEqual(note['leader'], 2)


class FundRowsTest(V4Base):
    def test_fund_rows_records_gate_state_for_m9(self):
        f = self.fx()
        tap = f.root / 'state' / 'probe' / 'tap-life1.jsonl'
        tap.write_text(json.dumps({'tap': 'admission', 'row': {'market': 0, 'state': 'SUSPENDED', 'reason': 'BRIDGE_HALT'}}) + '\n')
        f.registry.update(tap={'path': str(tap)}, funding=[{'kind': 'deposit', 'request': [2, 1], 'user': 1, 'asset': 0,
                                                            'amount': 5, 'outcome': 'ACK', 'gate': 'OPEN'}])
        answers = iter([('ANSWERED', {'replies': [{'t': 'DepositAck'}]}), ('REFUSED', {'replies': [{'t': 'WithdrawReject'}]}),
                        ('UNKNOWN', None)])
        seen = []

        def core(verb, principal, **kw):
            seen.append((verb, principal, kw)); return next(answers)
        f.core = core
        rows = f.fund_rows([{'kind': 'deposit', 'user': 7, 'asset': 0, 'amount': 10},
                            {'kind': 'withdraw', 'user': 7, 'asset': 0, 'amount': 3},
                            {'kind': 'withdraw', 'user': 8, 'asset': 1, 'amount': 4}])
        self.assertEqual([r['outcome'] for r in rows], ['ACK', 'REJECT', 'UNKNOWN'])
        self.assertEqual([s[:2] for s in seen], [('deposit', 'probe-tool'), ('withdraw', 'probe-tool'), ('withdraw', 'probe-tool')])
        self.assertEqual(len(f.registry['funding']), 4)                  # appended to the genesis rows
        self.assertEqual({r['gate'] for r in rows}, {'SUSPENDED'})
        self.assertEqual(rows[0]['gate_witness'], {'source': 'tap', 'row': {'market': 0, 'state': 'SUSPENDED', 'reason': 'BRIDGE_HALT'}})
        requests = [tuple(r['request']) for r in f.registry['funding']]
        self.assertEqual(len(set(requests)), 4)                          # never reuses a request id
        self.assertTrue(all(r['phase'] == 'drill' for r in rows))
        with self.assertRaises(Violation):
            f.fund_rows([{'kind': 'transfer', 'user': 1, 'asset': 0, 'amount': 1}])


class EngineRestartRuleTest(V4Base):
    def test_ae_restart_waits_after_driver_death_exit(self):
        f = self.fx()
        self.docker.state['c-ae0'].update(Running=False, ExitCode=1)
        f.wait_exit('ae0', 1, 18)
        self.assertIn('ae0', f.registry['last_kill'])
        self.clock.now += 3.0
        w = f.restart('ae0')
        self.assertAlmostEqual(sum(self.clock.sleeps), 9.5, places=2)
        self.assertGreaterEqual(w['waited_after_kill_s'], core_fixture.AE_RESTART_MIN_AFTER_KILL_S)

    def test_wait_exit_accepts_nonzero(self):
        f = self.fx()
        self.docker.state['c-me0'].update(Running=False, ExitCode=139)
        self.assertEqual(f.wait_exit('me0', 'nonzero', 18)['exit_code'], 139)
        self.docker.state['c-ae1'].update(Running=False, ExitCode=0)
        with self.assertRaisesRegex(Inconclusive, 'ae1 exited 0, expected nonzero'):
            f.wait_exit('ae1', 'nonzero', 18)

    def boot(self, m):
        f = self.fx(m, roles=())
        f.registry['network_id'] = 'net'
        for name in ('check_image', 'stage_artifacts', 'start_network', 'start_database', 'arm_money_journal', 'start_projector'):
            setattr(f, name, lambda *a, **k: None)
        f.start_slot = lambda slot: {'state': 'SKIPPED_ABSENT'}
        self.docker.stale_driver = getattr(self, 'stale_boot', False)     # every cnc.dat mtime the same: a driver that never changes
        f.start()
        return f

    def test_engine_restart_requires_new_driver_identity(self):
        self.stale_boot = True
        f = self.boot(ext_manifest(self.dir))
        self.assertEqual(sorted(f.registry['driver_identity']), sorted(core_contracts.ENGINES))
        self.docker.state['c-ae1'].update(Running=False, ExitCode=1)
        with self.assertRaisesRegex(Inconclusive, 'ae1 driver identity did not change'):
            f.restart('ae1')
        self.docker.stale_driver = False
        self.docker.state['c-me2'].update(Running=False, ExitCode=1)
        self.assertIn('driver', f.restart('me2'))
        embedded = self.boot(ext_manifest(self.dir, engines='embedded'))
        self.assertFalse(set(embedded.registry.get('driver_identity', {})) & set(core_contracts.ENGINES))

    def test_engine_driver_pidfile(self):
        f = self.fx()
        self.assertEqual(f.engine_driver_pidfile('ae1'), '/data/aeronmd.pid')
        with self.assertRaises(Violation):
            self.fx(ext_manifest(self.dir, engines='embedded')).engine_driver_pidfile('ae1')


class EngineExternalProfileTest(V4Base):
    def test_engine_wrapper_in_external_mode_starts_aeronmd_with_the_pinned_properties_before_java(self):
        f = self.fx(roles=())
        f.registry['network_id'] = 'net'
        for name in ('check_image', 'stage_artifacts', 'start_network', 'start_database', 'arm_money_journal', 'start_projector'):
            setattr(f, name, lambda *a, **k: None)
        f.start_slot = lambda slot: {'state': 'SKIPPED_ABSENT'}
        f.start()
        create = {c[c.index('--name') + 1].rsplit('-', 1)[-1]: c for c in self.docker.calls if c[:2] == ['docker', 'create']}
        for role in core_contracts.ENGINES:
            argv = create[role]
            entry = argv[argv.index('--entrypoint') + 1]
            with self.subTest(role=role):
                self.assertEqual((entry, argv[-2]), ('sh', '-c'))      # a693555: --entrypoint java ... -jar
                script = argv[-1]
                d = '/dev/shm/aeron-' + role
                order = ['rm -rf ' + d, 'mkdir -p ' + d,
                         'LD_LIBRARY_PATH=/artifacts/engine_libs /artifacts/engine_libs/aeronmd '
                         '/artifacts/engine_libs/driver.properties /artifacts/engine_libs/driver-dev.properties',
                         'echo $! > /data/aeronmd.pid', d + '/cnc.dat', 'exec java']
                positions = [script.index(t) for t in order]
                self.assertEqual(positions, sorted(positions))
                self.assertIn('AERON_DIR=%s AERON_DIR_DELETE_ON_SHUTDOWN=1 AERON_DIR_DELETE_ON_START=1' % d, script)
                self.assertIn('-jar /artifacts/%s.jar' % role[:2], script)
                env = {a.split('=', 1)[0]: a.split('=', 1)[1] for a, p in zip(argv[1:], argv) if p == '--env'}
                self.assertEqual((env['TRANSPORT_DRIVER_MODE'], env['AERON_DIR']), ('external', d))
        # the dev profile keeps the plain embedded engines (D-S15-4)
        f2 = self.fx(ext_manifest(self.dir, engines='embedded'), roles=())
        self.assertEqual(f2.engine_command('me', 1), core_fixture.JAVA + ['-jar', '/artifacts/me.jar'])
        self.assertEqual(f2.engine_env('me', 1)['TRANSPORT_DRIVER_MODE'], 'embedded')
        self.assertNotIn('AERON_DIR', f2.engine_env('me', 1))
        assert_production_timeouts(f.engine_env('ae', 2), f.allowed_env())

    def run_engine_wrapper(self, fake_driver, ticks=300, skip=()):
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for d in ('artifacts/engine_libs', 'data', 'shm', 'bin'):
                (root / d).mkdir(parents=True)
            (root / 'artifacts/engine_libs/aeronmd').write_text(fake_driver)
            (root / 'bin/java').write_text('#!/bin/sh\necho "JAVA $* cnc=$([ -f "$AERON_DIR/cnc.dat" ] && echo yes)"\n')
            for p in ((root / 'artifacts/engine_libs/aeronmd'), (root / 'bin/java')):
                p.chmod(0o755)
            f = self.fx(roles=()); f.engine_driver_skip = tuple(skip)
            script = f.engine_command('ae', 0)[2]
            script = (script.replace('/artifacts/', str(root / 'artifacts') + '/').replace('/data/', str(root / 'data') + '/')
                      .replace('/dev/shm/', str(root / 'shm') + '/').replace('-lt 300', '-lt %d' % ticks))
            env = dict(os.environ, PATH=str(root / 'bin') + ':' + os.environ['PATH'], AERON_DIR=str(root / 'shm/aeron-ae0'))
            run = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=20, env=env)
            args = (root / 'data' / 'driver-args').read_text() if (root / 'data' / 'driver-args').exists() else ''
            return run, args

    def test_engine_wrapper_runs_the_driver_then_execs_java(self):
        fake = ('#!/bin/sh\necho "$*" > "$(dirname "$0")/../../data/driver-args"\n'
                'touch "$AERON_DIR/cnc.dat"; sleep 1\n')
        run, args = self.run_engine_wrapper(fake)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('JAVA', run.stdout); self.assertIn('-jar', run.stdout); self.assertIn('cnc=yes', run.stdout)
        self.assertTrue(args.strip().endswith('engine_libs/driver.properties ' + args.split()[-1]))
        self.assertTrue(args.split()[-1].endswith('engine_libs/driver-dev.properties'))
        run, _ = self.run_engine_wrapper('#!/bin/sh\nexit 3\n', ticks=3)
        self.assertEqual(run.returncode, 1); self.assertIn('aeronmd did not come up', run.stderr); self.assertNotIn('JAVA', run.stdout)

    def test_engine_driver_skip_starts_java_without_a_driver(self):
        run, args = self.run_engine_wrapper('#!/bin/sh\necho ran > "$(dirname "$0")/../../data/driver-args"\n', skip=('ae0',))
        self.assertEqual((run.returncode, args), (0, ''))
        self.assertIn('JAVA', run.stdout); self.assertIn('cnc=', run.stdout)
        f = self.fx(roles=()); f.engine_driver_skip = ('ae0', 'me0')
        self.assertNotIn('aeronmd', f.engine_command('ae', 0)[2]); self.assertIn('aeronmd', f.engine_command('ae', 1)[2])

    def test_engine_libs_are_staged_with_their_modes(self):
        m = ext_manifest(self.dir)
        f = fixture_for(m, self.dir)
        f.stage_artifacts()
        mode = lambda name: os.stat(f.root / 'artifacts' / 'engine_libs' / name).st_mode & 0o777
        self.assertEqual(mode('aeronmd'), 0o755)
        for name in ('libaeron.so', 'libaeron_driver.so', 'driver.properties', 'driver-dev.properties'):
            self.assertEqual(mode(name) & 0o111, 0, name)
        self.assertEqual((f.root / 'artifacts' / 'engine_libs' / 'driver.properties').read_text(), DP_TEXT)


class FaultTargetsV4Test(V4Base):
    def test_stopped_wiped_and_replaced_roles_do_not_abort_other_waits(self):
        f = self.fx()
        f.wait_http = types.MethodType(fixture_module.Fixture.wait_http, f)
        with mock.patch.object(fixture_module.time, 'sleep', lambda s: None):
            self.docker.polite.update(fwd0=(0, 0.1)); f.stop('fwd0')
            f.stop('me0'); f.wipe_engine('me0')
            self.assertEqual(f.wait_http('fwd1', 9700, '/ready')['status'], 200)
            # regenesis('me'): the forwarders exit 78 on their own while the fresh ME starts
            life1(f)
            for name in ('stop', 'wipe_engine'):
                setattr(f, name, lambda *a, **k: None)
            f._driver = lambda *a, **k: None
            def members(engine):
                for role in ('fwd1',):
                    self.docker.state['c-' + role].update(Running=False, ExitCode=78)
                return f.wait_http('me1', 19500, '/ready')
            f.start_members = members
            f.regenesis({}, 'me')
        self.assertEqual(f.registry['fault_targets']['fwd1']['reason'], 'regenesis me: F8 epoch fence expected')


if __name__ == '__main__':
    unittest.main()


def projector_manifest(directory, mode='external', engines='external'):
    """RC2 S17 W2 (W10, PO-11 (a)): the fixture key ``projector_driver`` beside ``engine_driver``; external mode stages the
    same pinned driver set as the engines (``projector_libs``)."""
    m = ext_manifest(directory, engines=engines)
    m['projector_driver'] = mode
    if mode == 'external':
        own = Path(directory) / 'projector-libs'; own.mkdir(exist_ok=True)
        m['projector_libs'] = engine_libs(own)
    return m


class ProjectorDriverFixtureTest(V4Base):
    def test_embedded_projector_never_sets_aeron_dir(self):
        for m in (ext_manifest(self.dir), projector_manifest(self.dir, 'embedded')):
            f = self.fx(m, roles=())
            env = f.projector_env()
            self.assertNotIn('AERON_DIR', env)
            self.assertEqual(f.projector_command(), core_fixture.JAVA + ['-jar', '/artifacts/projector.jar'])
            assert_production_timeouts(env, f.allowed_env())
        self.assertEqual(self.fx(projector_manifest(self.dir, 'embedded'), roles=()).projector_env()['PROJECTOR_DRIVER_MODE'],
                         'embedded')
        self.assertNotIn('PROJECTOR_DRIVER_MODE', self.fx(ext_manifest(self.dir), roles=()).projector_env())

    def test_external_projector_attaches_to_its_staged_aeronmd(self):
        f = self.fx(projector_manifest(self.dir), roles=())
        env = f.projector_env()
        self.assertEqual((env['PROJECTOR_DRIVER_MODE'], env['AERON_DIR']), ('external', '/dev/shm/aeron-projector'))
        assert_production_timeouts(env, f.allowed_env())
        entry, flag, script = f.projector_command()
        self.assertEqual((entry, flag), ('sh', '-c'))
        d = '/dev/shm/aeron-projector'
        order = ['rm -rf ' + d, 'mkdir -p ' + d,
                 'LD_LIBRARY_PATH=/artifacts/projector_libs /artifacts/projector_libs/aeronmd '
                 '/artifacts/projector_libs/driver.properties /artifacts/projector_libs/driver-dev.properties',
                 'echo $! > /data/aeronmd.pid', d + '/cnc.dat', 'exec java']
        positions = [script.index(t) for t in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('-jar /artifacts/projector.jar', script)
        self.assertEqual(f.engine_driver_pidfile('projector'), '/data/aeronmd.pid')
        with self.assertRaises(Violation):
            self.fx(projector_manifest(self.dir, 'embedded'), roles=()).engine_driver_pidfile('projector')

    def test_projector_libs_are_staged_with_their_modes(self):
        f = fixture_for(projector_manifest(self.dir), self.dir)
        f.stage_artifacts()
        mode = lambda name: os.stat(f.root / 'artifacts' / 'projector_libs' / name).st_mode & 0o777
        self.assertEqual(mode('aeronmd'), 0o755)
        for name in ('libaeron.so', 'libaeron_driver.so', 'driver.properties', 'driver-dev.properties'):
            self.assertEqual(mode(name) & 0o111, 0, name)

    def test_start_projector_spawns_the_wrapper(self):
        f = self.fx(projector_manifest(self.dir), roles=())
        spawned = []
        f.spawn = lambda name, command, env: spawned.append((name, command, env))
        f.start_projector(None)
        self.assertEqual(spawned[0][0], 'projector')
        self.assertEqual(spawned[0][1][:2], ['sh', '-c'])
        self.assertEqual(spawned[0][2]['PROJECTOR_DRIVER_MODE'], 'external')
