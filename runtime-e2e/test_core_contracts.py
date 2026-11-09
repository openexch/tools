# SPDX-License-Identifier: Apache-2.0
"""Manifest and environment contracts of fixture v3 (no Docker)."""
import copy
import hashlib
from pathlib import Path
import tempfile
import time
import types
import unittest

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import assert_production_timeouts, validate_core_manifest
from test_core_fixture import manifest, write


class DriverTimeoutExemptionTest(unittest.TestCase):
    """Exactly the two driver-liveness names at exactly the string 5000."""

    def allowed(self):
        return core_contracts.PROCESS_ENV | {'ME_SESSION_TIMEOUT_MS', 'ME_AUTH_KEYS', 'ME_AUTH_CREDENTIAL'}

    def test_driver_timeout_exemption_is_exact(self):
        # On c781b4c the name is first refused by the allowlist
        # ("environment names are an allowlist; refusing FWD_DRIVER_TIMEOUT_MS"), and only once it is allowlisted
        # does it reach "refusing to pass a timeout setting". With the liveness names allowed, the exact pair passes.
        for key in ('FWD_DRIVER_TIMEOUT_MS', 'BRIDGE_DRIVER_TIMEOUT_MS'):
            assert_production_timeouts({key: '5000'}, self.allowed())
        refused = [{'FWD_DRIVER_TIMEOUT_MS': '3000'}, {'FWD_DRIVER_TIMEOUT_MS': '60001'}, {'FWD_DRIVER_TIMEOUT_MS': '5000 '},
                   {'FWD_DRIVER_TIMEOUT_MS': ' 5000'}, {'FWD_DRIVER_TIMEOUT_MS': '05000'}, {'FWD_DRIVER_TIMEOUT_MS': 5000},
                   {'BRIDGE_DRIVER_TIMEOUT_MS': '4999'}, {'BRIDGE_DRIVER_TIMEOUT_MS': ''}, {'ME_SESSION_TIMEOUT_MS': '10000'},
                   {'ME_SESSION_TIMEOUT_MS': '5000'}]
        for env in refused:
            with self.subTest(env=env), self.assertRaisesRegex(
                    Violation, 'refusing to pass a timeout setting to a fixture process: ' + next(iter(env))):
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
        """Pinned T1 drivers with no probe_libs.aeronmd are refused before any container starts; c781b4c's
        probe silently idled ('sleep infinity') and the drivers failed later at me_genesis with an opaque Aeron error."""
        for key in ('t1_me_driver', 't1_core_driver'):
            jar, src = write(self.dir, key + '.jar', b'jar-' + key.encode()), write(self.dir, key + '.java', b'src-' + key.encode())
            self.m[key] = {'path': jar['path'], 'sha256': jar['sha256'], 'source_path': src['path'], 'source_sha256': src['sha256']}
        self.bad(lambda m: None, text='t1_me_driver and t1_core_driver pinned without probe_libs.aeronmd')
        self.bad(lambda m: m.pop('t1_me_driver'), text='t1_core_driver pinned without probe_libs.aeronmd')
        lib = {k: v for k, v in write(self.dir, 'libaeron.so', b'so').items() if k != 'source_sha'}
        self.bad(lambda m: m.update(probe_libs={'libaeron.so': lib}), text='staged media driver')
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



# ======================================================================================================
# Engine driver profile, build B and the control guards.
# ======================================================================================================

import json
import os
from unittest import mock

import core_drills
from test_core_fixture import DEV_TEXT, DP_TEXT, engine_libs, ext_manifest, slot_manifest

# MK_DRIVER_PROPERTIES: the ME tree's deploy/media-driver/driver.properties (no default; the real-file case skips without it)
REAL_DP = Path(os.environ.get('MK_DRIVER_PROPERTIES') or '/nonexistent/driver.properties')


class EngineDriverManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m, path=None):
        validate_core_manifest(m, path or self.path, cpu_count=24)

    def bad(self, m, text, error=Violation, path=None):
        with self.assertRaises(error) as caught:
            self.check(m, path)
        self.assertIn(text, str(caught.exception))

    def test_engine_driver_values_and_complete_engine_libs(self):
        self.check(ext_manifest(self.dir))
        self.check(ext_manifest(self.dir, engines='embedded'))
        m = slot_manifest(self.dir); self.check(m)                       # absent = embedded (dev default)
        self.bad(dict(ext_manifest(self.dir), engine_driver='java'), 'engine_driver must be embedded or external')
        m = ext_manifest(self.dir); m.pop('engine_libs')
        self.bad(m, 'engine_driver external needs engine_libs')
        for name in ('aeronmd', 'driver.properties', 'driver-dev.properties', 'libaeron.so'):
            m = ext_manifest(self.dir); m['engine_libs'].pop(name)
            with self.subTest(missing=name):
                self.bad(m, 'engine_libs must be exactly')
        m = ext_manifest(self.dir); m['engine_libs']['aeronmd'].pop('exec')
        self.bad(m, 'engine_libs aeronmd must be exec')
        m = ext_manifest(self.dir, engines='embedded'); m['engine_libs'] = engine_libs(self.dir)
        self.bad(m, 'engine_libs without engine_driver external')
        m = ext_manifest(self.dir); Path(m['engine_libs']['libaeron.so']['path']).write_bytes(b'tampered')
        self.bad(m, 'engine_libs changed: libaeron.so')

    def test_engine_libs_properties_match_the_embedded_overrides(self):
        core_contracts.check_driver_properties(DP_TEXT, DEV_TEXT)
        drifts = [('aeron.mtu.length=8192', 'aeron.mtu.length=1408'), ('aeron.term.buffer.length=16m', 'aeron.term.buffer.length=64m'),
                  ('aeron.term.buffer.sparse.file=false', 'aeron.term.buffer.sparse.file=true'),
                  ('aeron.client.liveness.timeout=5s', 'aeron.client.liveness.timeout=10s'),
                  ('aeron.publication.unblock.timeout=10s', 'aeron.publication.unblock.timeout=15s'),
                  ('aeron.ipc.term.buffer.length=16m\n', '')]
        for old, new in drifts:
            with self.subTest(drift=new or 'missing ' + old), self.assertRaisesRegex(Violation, 'driver.properties drifts from the embedded'):
                core_contracts.check_driver_properties(DP_TEXT.replace(old, new), DEV_TEXT)
        # units are normalised: 16777216 is 16m, 5000ms is 5s
        core_contracts.check_driver_properties(DP_TEXT.replace('=16m', '=16777216').replace('liveness.timeout=5s', 'liveness.timeout=5000ms'), DEV_TEXT)
        with self.assertRaisesRegex(Violation, 'driver-dev.properties may set only'):
            core_contracts.check_driver_properties(DP_TEXT, DEV_TEXT + 'aeron.mtu.length=1408\n')
        with self.assertRaisesRegex(Violation, 'aeron.threading.mode=SHARED'):
            core_contracts.check_driver_properties(DP_TEXT, DEV_TEXT.replace('SHARED', 'DEDICATED'))
        m = ext_manifest(self.dir)
        Path(m['engine_libs']['driver.properties']['path']).write_text(DP_TEXT.replace('8192', '1408'))
        m['engine_libs']['driver.properties']['sha256'] = hashlib.sha256(DP_TEXT.replace('8192', '1408').encode()).hexdigest()
        self.bad(m, 'driver.properties drifts from the embedded overrides: aeron.mtu.length')

    @unittest.skipUnless(REAL_DP.is_file(), "set MK_DRIVER_PROPERTIES to the ME tree's driver.properties")
    def test_the_real_driver_properties_pass(self):
        core_contracts.check_driver_properties(REAL_DP.read_text(), DEV_TEXT)

    def b_manifest(self, kind, target):
        m = ext_manifest(self.dir)
        m['artifacts']['forwarder_b']['target'] = target
        m['manifest_kind'] = kind
        return m, Path(self.dir) / (kind + '--r1.json')

    def test_a05_manifest_refuses_a_negative_build_as_build_b(self):
        m, path = self.b_manifest('s16-a05', 'ct-forwarder'); self.check(m, path)
        m, path = self.b_manifest('s16-a05', 'ct_forwarder_nc_norelease')
        self.bad(m, 'an A05 manifest stages the negative build ct_forwarder_nc_norelease as forwarder_b', path=path)
        m, path = self.b_manifest('s16-a05', 'ct-forwarder'); m['artifacts']['forwarder_b'].pop('target')
        self.bad(m, 'forwarder_b needs a pinned CMake target', path=path)
        # scenario-level: core-drill-a05-* refuses it whatever the kind says
        fx = types.SimpleNamespace(m=self.b_manifest('s16-a05', 'ct_forwarder_nc_norelease')[0])
        fx.m['slot_artifacts'].update(fwd0='forwarder', fwd1='forwarder')
        with self.assertRaisesRegex(Violation, 'negative build ct_forwarder_nc_norelease as forwarder_b'):
            core_drills.scenario(fx, 'core-drill-a05-fwd-upgrade', self.dir)
        fx.m['artifacts']['forwarder_b']['target'] = 'ct-forwarder'
        fx.clock, fx.sleep = time.time, (lambda s: None)
        from unittest import mock                                              # the guard passed; the drill was added later
        with mock.patch.object(core_drills.DrillRun, 'run', lambda run: {'status': 'PASS', 'lines': {}, 'of_rows': {}}):
            self.assertEqual(core_drills.scenario(fx, 'core-drill-a05-fwd-upgrade', self.dir)['status'], 'PASS')

    def test_red_manifest_refuses_a_non_nc_build_b(self):
        m, path = self.b_manifest('s16-red-a03', 'ct_forwarder_nc_norelease'); self.check(m, path)
        m, path = self.b_manifest('s16-red-a03', 'ct-forwarder')
        self.bad(m, 'a RED manifest stages the real build ct-forwarder as forwarder_b', path=path)
        fx = types.SimpleNamespace(m=self.b_manifest('s16-red-a03', 'ct-forwarder')[0])
        with self.assertRaisesRegex(Violation, 'real build ct-forwarder as forwarder_b'):
            core_drills.scenario(fx, 'core-red-a03', self.dir)

    def test_a03_manifest_pins_the_norelease_phase_and_build_a(self):
        """A03 phase 1 runs ct_forwarder_nc_norelease, then replace_slot swaps to build A."""
        m, path = self.b_manifest('s16-a03', 'ct_forwarder_nc_norelease'); self.check(m, path)
        m, path = self.b_manifest('s16-a03', 'ct_forwarder_nc_noresync')
        self.bad(m, 'an A03 manifest stages ct_forwarder_nc_norelease as forwarder_b', path=path)
        m, path = self.b_manifest('s16-a03', 'ct_forwarder_nc_norelease'); m['artifacts']['forwarder']['target'] = 'ct_forwarder_nc_noresync'
        self.bad(m, 'build A forwarder must be a real build', path=path)

    def test_green_kinds_stage_no_build_b(self):
        m, path = self.b_manifest('s16', 'ct-forwarder')
        self.bad(m, 'manifest kind s16 stages no build B', path=path)

    def test_manifest_kind_matches_file_name(self):
        m, _ = self.b_manifest('s16-a05', 'ct-forwarder')
        self.bad(m, 'manifest kind s16-a05 does not match the file name x.json', path=Path(self.dir) / 'x.json')
        m['manifest_kind'] = 's16-nope'
        self.bad(m, 'unknown manifest kind s16-nope', path=Path(self.dir) / 's16-nope--r1.json')

    def test_b_artifact_needs_a_40_hex_source_sha(self):
        m, path = self.b_manifest('s16-a05', 'ct-forwarder')
        m['artifacts']['forwarder_b']['source_sha'] = 'abc'
        self.bad(m, 'missing artifact source commit: forwarder_b', Inconclusive, path=path)

    def test_engine_driver_skip_is_refused_outside_its_control(self):
        m = ext_manifest(self.dir); m['manifest_kind'] = 's16-ctl-edk-cnctimeout'
        ok = Path(self.dir) / 's16-ctl-edk-cnctimeout--r1.json'
        self.assertEqual(core_contracts.check_engine_driver_skip(m, ok, '1'), ('ae0', 'me0'))
        self.assertEqual(core_contracts.check_engine_driver_skip(m, ok, None), ())
        for kind in ('s16-ext', 's16'):
            other = dict(m, manifest_kind=kind)
            with self.subTest(kind=kind), self.assertRaisesRegex(Violation, 'ENGINE_DRIVER_SKIP is refused outside s16-ctl-edk-cnctimeout'):
                core_contracts.check_engine_driver_skip(other, Path(self.dir) / (kind + '--r1.json'), '1')
        with self.assertRaisesRegex(Violation, 'ENGINE_DRIVER_SKIP is refused outside'):
            core_contracts.check_engine_driver_skip(ext_manifest(self.dir), self.path, '1')
        with self.assertRaisesRegex(Violation, 'ENGINE_DRIVER_SKIP=1 only'):
            core_contracts.check_engine_driver_skip(m, ok, 'ae1')
        embedded = dict(m, engine_driver='embedded')
        with self.assertRaisesRegex(Violation, 'needs engine_driver external'):
            core_contracts.check_engine_driver_skip(embedded, ok, '1')
        # the constructor reads it from the harness environment before touching the box
        m2 = ext_manifest(self.dir); path = Path(self.dir) / 'm.json'; path.write_text(json.dumps(m2))
        with mock.patch.dict(os.environ, {'ENGINE_DRIVER_SKIP': '1'}), self.assertRaisesRegex(Violation, 'ENGINE_DRIVER_SKIP'):
            import core_fixture
            core_fixture.CoreFixture(path)
        self.assertFalse(Path(m2['state_root']).exists())


if __name__ == '__main__':
    unittest.main()


class ProjectorDriverManifestTest(unittest.TestCase):
    """``projector_driver`` mirrors ``engine_driver``."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'

    def tearDown(self):
        self.temp.cleanup()

    def bad(self, m, text):
        with self.assertRaises(Violation) as caught:
            validate_core_manifest(m, self.path, cpu_count=24)
        self.assertIn(text, str(caught.exception))

    def test_projector_driver_values_and_complete_libs(self):
        from test_core_fixture import projector_manifest
        validate_core_manifest(projector_manifest(self.dir), self.path, cpu_count=24)
        validate_core_manifest(projector_manifest(self.dir, 'embedded'), self.path, cpu_count=24)
        self.bad(dict(projector_manifest(self.dir, 'embedded'), projector_driver='host'),
                 'projector_driver must be embedded or external')
        m = projector_manifest(self.dir); m.pop('projector_libs')
        self.bad(m, 'projector_driver external needs projector_libs')
        m = projector_manifest(self.dir); m['projector_libs'].pop('driver-dev.properties')
        self.bad(m, 'projector_libs must be exactly')
        m = projector_manifest(self.dir); m['projector_libs']['aeronmd'].pop('exec')
        self.bad(m, 'projector_libs aeronmd must be exec')
        m = projector_manifest(self.dir, 'embedded'); m['projector_libs'] = engine_libs(self.dir)
        self.bad(m, 'projector_libs without projector_driver external')
        m = projector_manifest(self.dir); Path(m['projector_libs']['libaeron.so']['path']).write_bytes(b'tampered')
        self.bad(m, 'projector_libs changed: libaeron.so')
        m = projector_manifest(self.dir)
        Path(m['projector_libs']['driver.properties']['path']).write_text(DP_TEXT.replace('8192', '1408'))
        m['projector_libs']['driver.properties']['sha256'] = hashlib.sha256(DP_TEXT.replace('8192', '1408').encode()).hexdigest()
        self.bad(m, 'driver.properties drifts from the embedded overrides')

    def test_projector_driver_mode_is_an_allowed_process_name(self):
        self.assertIn('PROJECTOR_DRIVER_MODE', core_contracts.PROCESS_ENV)
