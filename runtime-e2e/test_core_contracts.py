# SPDX-License-Identifier: Apache-2.0
"""RC2 S15 W1, contract 5.1 / 5.2 / 3.2: manifest and environment contracts of fixture v3 (no Docker)."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import assert_production_timeouts, validate_core_manifest
from test_core_fixture import manifest, write


class DriverTimeoutExemptionTest(unittest.TestCase):
    """D-S15-11 / PO-8: exactly the two driver-liveness names at exactly the string 5000."""

    def allowed(self):
        return core_contracts.PROCESS_ENV | {'ME_SESSION_TIMEOUT_MS', 'ME_AUTH_KEYS', 'ME_AUTH_CREDENTIAL'}

    def test_driver_timeout_exemption_is_exact(self):
        # W0 answer 1 / amendment A3: on c781b4c the name is first refused by the allowlist
        # ("environment names are an allowlist; refusing FWD_DRIVER_TIMEOUT_MS"), and only once it is allowlisted
        # does it reach "refusing to pass a timeout setting". After W1 the exact pair passes.
        for key in ('FWD_DRIVER_TIMEOUT_MS', 'BRIDGE_DRIVER_TIMEOUT_MS'):
            assert_production_timeouts({key: '5000'}, self.allowed())
        refused = [{'FWD_DRIVER_TIMEOUT_MS': '3000'}, {'FWD_DRIVER_TIMEOUT_MS': '60001'}, {'FWD_DRIVER_TIMEOUT_MS': '5000 '},
                   {'FWD_DRIVER_TIMEOUT_MS': ' 5000'}, {'FWD_DRIVER_TIMEOUT_MS': '05000'}, {'FWD_DRIVER_TIMEOUT_MS': 5000},
                   {'BRIDGE_DRIVER_TIMEOUT_MS': '4999'}, {'BRIDGE_DRIVER_TIMEOUT_MS': ''}, {'ME_SESSION_TIMEOUT_MS': '10000'},
                   {'ME_SESSION_TIMEOUT_MS': '5000'}]
        for env in refused:
            with self.subTest(env=env), self.assertRaisesRegex(
                    Violation, 'D20: refusing to pass a timeout setting to a fixture process: ' + next(iter(env))):
                assert_production_timeouts(env, self.allowed())

    def test_exemption_is_by_name_not_by_pattern(self):
        self.assertEqual(core_contracts.DRIVER_TIMEOUT_EXEMPT,
                         {'FWD_DRIVER_TIMEOUT_MS': '5000', 'BRIDGE_DRIVER_TIMEOUT_MS': '5000'})
        for key in ('FWD_HEARTBEAT_MS', 'FWD_DRIVER_LIVENESS_MS', 'BRIDGE_ELECTION_MS', 'XFWD_DRIVER_TIMEOUT_MS'):
            with self.subTest(key=key), self.assertRaises(Violation):
                assert_production_timeouts({key: '5000'}, self.allowed() | {key})

    def test_exempt_names_still_need_the_allowlist(self):
        with self.assertRaisesRegex(Violation, 'environment names are an allowlist; refusing FWD_DRIVER_TIMEOUT_MS'):
            assert_production_timeouts({'FWD_DRIVER_TIMEOUT_MS': '5000'}, {'BASE_DIR'})

    def test_a_jvm_timeout_value_is_still_refused_next_to_the_exemption(self):
        with self.assertRaises(Violation):
            assert_production_timeouts({'FWD_DRIVER_TIMEOUT_MS': '5000', 'BASE_DIR': '-Daeron.cluster.election.timeout=1s'},
                                       self.allowed())


class ManifestV3Test(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'
        self.m = manifest(self.dir)

    def tearDown(self):
        self.temp.cleanup()

    def bad(self, edit, error=Violation, text=None, **kw):
        m = copy.deepcopy(self.m); edit(m)
        with self.assertRaises(error) as caught:
            validate_core_manifest(m, self.path, cpu_count=24, **kw)
        if text:
            self.assertIn(text, str(caught.exception))

    def binary(self, m, driver='external', libs=None):
        m['artifacts']['forwarder'] = dict(write(self.dir, 'fwd.bin', b'elf'), driver=driver, libs=libs or {})
        m['slot_artifacts']['fwd0'] = 'forwarder'

    def test_driver_values_are_embedded_or_external(self):
        for driver in ('embedded', 'external'):
            m = copy.deepcopy(self.m); self.binary(m, driver); validate_core_manifest(m, self.path, cpu_count=24)
        self.bad(lambda m: self.binary(m, 'java_media_driver'),
                 text='driver java_media_driver is retired: external means the staged aeronmd')
        self.bad(lambda m: self.binary(m, 'host'), text='driver')

    def test_lib_exec_flag_is_validated(self):
        def libs(**extra):
            return {'aeronmd': dict({k: v for k, v in write(self.dir, 'aeronmd', b'md').items() if k != 'source_sha'}, **extra),
                    'libaeron.so': {k: v for k, v in write(self.dir, 'libaeron.so', b'so').items() if k != 'source_sha'}}
        m = copy.deepcopy(self.m); self.binary(m, libs=libs(exec=True)); validate_core_manifest(m, self.path, cpu_count=24)
        self.bad(lambda m: self.binary(m, libs=libs(exec='yes')), text='exec')
        self.bad(lambda m: self.binary(m, libs=libs(mode=493)), text='library key')
        self.bad(lambda m: self.binary(m, libs=libs(sticky=True)), text='library key')

    def test_probe_libs_is_pinned(self):
        lib = {k: v for k, v in write(self.dir, 'probe-aeronmd', b'md').items() if k != 'source_sha'}
        self.m['probe_libs'] = {'aeronmd': dict(lib, exec=True)}
        validate_core_manifest(self.m, self.path, cpu_count=24)
        Path(lib['path']).write_bytes(b'tampered')
        with self.assertRaisesRegex(Violation, 'probe input changed: probe_libs aeronmd'):
            validate_core_manifest(self.m, self.path, cpu_count=24)
        self.bad(lambda m: m.update(probe_libs={'a/b': dict(lib, exec=True)}), text='flat file names')

    def test_t1_driver_keys_are_pinned_like_the_probes(self):
        lib = {k: v for k, v in write(self.dir, 'probe-aeronmd', b'md').items() if k != 'source_sha'}
        self.m['probe_libs'] = {'aeronmd': dict(lib, exec=True)}     # review F8: the drivers need the probe's aeronmd
        for key in ('t1_me_driver', 't1_core_driver'):
            jar, src = write(self.dir, key + '.jar', b'jar-' + key.encode()), write(self.dir, key + '.java', b'src-' + key.encode())
            self.m[key] = {'path': jar['path'], 'sha256': jar['sha256'], 'source_path': src['path'], 'source_sha256': src['sha256']}
        validate_core_manifest(self.m, self.path, cpu_count=24)
        Path(self.m['t1_core_driver']['source_path']).write_bytes(b'edited')
        with self.assertRaisesRegex(Violation, 'probe input changed: t1_core_driver source_path'):
            validate_core_manifest(self.m, self.path, cpu_count=24)

    def test_t1_drivers_without_the_probe_aeronmd_are_refused(self):
        """Review F8: pinned T1 drivers with no probe_libs.aeronmd are refused before any container starts (3.3); c781b4c's
        probe silently idled ('sleep infinity') and the drivers failed later at me_genesis with an opaque Aeron error."""
        for key in ('t1_me_driver', 't1_core_driver'):
            jar, src = write(self.dir, key + '.jar', b'jar-' + key.encode()), write(self.dir, key + '.java', b'src-' + key.encode())
            self.m[key] = {'path': jar['path'], 'sha256': jar['sha256'], 'source_path': src['path'], 'source_sha256': src['sha256']}
        self.bad(lambda m: None, text='t1_me_driver and t1_core_driver pinned without probe_libs.aeronmd')
        self.bad(lambda m: m.pop('t1_me_driver'), text='t1_core_driver pinned without probe_libs.aeronmd')
        lib = {k: v for k, v in write(self.dir, 'libaeron.so', b'so').items() if k != 'source_sha'}
        self.bad(lambda m: m.update(probe_libs={'libaeron.so': lib}), text='(contract 3.3)')
        m = copy.deepcopy(self.m)
        for key in ('t1_me_driver', 't1_core_driver'):
            m.pop(key)
        validate_core_manifest(m, self.path, cpu_count=24)    # core-boot without drivers keeps the idle probe

    def test_drills_refuse_a_non_enforced_me(self):
        validate_core_manifest(self.m, self.path, cpu_count=24)    # core-boot keeps both modes
        self.bad(lambda m: None, text='ME credential mode must be enforced for drills', require_me_enforced=True)
        m = copy.deepcopy(self.m); m['credentials']['me']['mode'] = 'enforced'
        validate_core_manifest(m, self.path, cpu_count=24, require_me_enforced=True)

    def test_per_role_memory_limits_are_validated(self):
        m = copy.deepcopy(self.m)
        m['limits'].update(shm_mb_by_role={'me0': 1536}, memory_mb_by_role={'me0': 3072})
        validate_core_manifest(m, self.path, cpu_count=24)
        self.bad(lambda m: m['limits'].update(shm_mb_by_role={'oms': 10}), text='unknown role')
        self.bad(lambda m: m['limits'].update(memory_mb_by_role={'me0': 0}), text='positive')
        self.bad(lambda m: m['limits'].update(shm_mb_by_role={'me0': 1.5}), Inconclusive)

    def test_probe_env_names(self):
        self.assertEqual(core_contracts.PROBE_ENV, {'T1_ADMIN_KEY', 'T1_TOOL_KEY', 'T1_GATEWAY_KEY', 'T1_ME_ADMIN_KEY',
                                                    'T1_ME_MARKETS', 'T1_LOCAL_HOST'})
        for never in ('T1_BRIDGE_KEY', 'T1_TAP_KEY', 'T1_ME_FORWARDER_KEY'):
            self.assertNotIn(never, core_contracts.PROBE_ENV)
        self.assertFalse(core_contracts.PROBE_ENV & core_contracts.PROCESS_ENV)


if __name__ == '__main__':
    unittest.main()
