# SPDX-License-Identifier: Apache-2.0
"""Fixture v2 contracts (H0 RED list, G10, G15/D20, G31, D18) without Docker."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import validate_core_manifest
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
            m['artifacts']['forwarder'] = dict(write(self.dir, 'fwd.bin', b'elf'), driver='java_media_driver')
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
        core_contracts.assert_production_timeouts({'TRANSPORT_IDLE_MODE': 'backoff', 'FWD_KEEPALIVE_MS': '1000'})
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


if __name__ == '__main__':
    unittest.main()
