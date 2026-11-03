# SPDX-License-Identifier: Apache-2.0
"""RC2 S16 W1: the manifest builder promoted from S15 evidence (contract 3.1, 3.2, 5.2, 5.3, 15 W1; 20.1 lines 2, 11).
No Docker: every pinned input is a small file in a temp tree."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from contracts import Violation
import core_contracts
import mk_manifests
from test_core_fixture import DP_TEXT

B_SHA = 'b' * 40


class ManifestBuilderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); root = self.root = Path(self.temp.name)

        def put(rel, data=None):
            p = root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data or rel.encode()); return p
        for name in ('ct-forwarder', 'ct-bridge', 'aeronmd', 'libaeron.so', 'libaeron_driver.so'):
            put('bin-s15/' + name)
        put('build-s16/app/forwarder/ct-forwarder', b'B-forwarder'); put('build-s16/app/bridge/ct-bridge', b'B-bridge')
        put('build-s16/app/forwarder/ct_forwarder_nc_norelease'); put('build-s16/app/bridge/ct_bridge_nc_noepoch')
        dp = put('me/deploy/media-driver/driver.properties', DP_TEXT.encode())
        jars = {k: put(f'jars/{k}.jar') for k in ('ae', 'me', 'projector')}
        probes = {}
        for key in ('core_probe', 'journal_probe', 't1_me_driver', 't1_core_driver'):
            jar, src = put(f'probes/{key}.jar'), put(f'probes/{key}.java')
            probes[key] = {'path': str(jar), 'sha256': hashlib.sha256(jar.read_bytes()).hexdigest(), 'source_path': str(src),
                           'source_sha256': hashlib.sha256(src.read_bytes()).hexdigest()}
        (root / 'probes/probe-manifest.json').write_text(json.dumps(probes))
        put('helper/iptables-legacy'); put('helper/extensions/libxt_udp.so')
        self.cfg = mk_manifests.Config(
            runs=root / 'runs', bin_a=root / 'bin-s15', build_b=root / 'build-s16', nc_dir=root / 'build-s16',
            b_source_sha=B_SHA, driver_properties=dp, driver_properties_sha256=hashlib.sha256(DP_TEXT.encode()).hexdigest(),
            jars={k: (v, 'c' * 40) for k, v in jars.items()}, probe_manifest=root / 'probes/probe-manifest.json',
            netfilter_helper=root / 'helper', harness_commit='d' * 40, harness_dirty=True,
            image='sha256:' + 'e' * 64)

    def tearDown(self):
        self.temp.cleanup()

    def built(self, kind, **over):
        cfg = mk_manifests.Config(**{**self.cfg.__dict__, **over})
        path, m = mk_manifests.build(kind, 'r1', cfg)
        core_contracts.validate_core_manifest(json.loads(path.read_text()), path, cpu_count=24, require_me_enforced=True)
        return path, m

    def test_every_s16_kind_builds_and_validates(self):
        self.assertEqual(len(mk_manifests.KINDS), 11)
        self.assertEqual(set(mk_manifests.KINDS), core_contracts.S16_KINDS)
        for kind in sorted(mk_manifests.KINDS):
            with self.subTest(kind=kind):
                path, m = self.built(kind)
                self.assertEqual(path.name, kind + '--r1.json')
                self.assertEqual(m['manifest_kind'], kind)
                self.assertEqual(m['state_root'], str(path.parent / 'fixtures' / m['run_id']))
                self.assertEqual(m['harness_commit'], 'd' * 40)

    def test_resource_sizes_are_the_s15_settings_and_overridable(self):
        _, m = self.built('s16')
        shm, mem = m['limits']['shm_mb_by_role'], m['limits']['memory_mb_by_role']
        for role in core_contracts.ENGINES:
            self.assertEqual((shm[role], mem[role]), (2048, 5120), role)
        for role in ('bridge0', 'bridge1', 'probe'):
            self.assertEqual(shm[role], 1024, role)
        for role in ('fwd0', 'fwd1', 'projector'):
            self.assertEqual(shm[role], 256, role)
        _, m = self.built('s16', shm_mb={'me0': 3072})
        self.assertEqual(m['limits']['shm_mb_by_role']['me0'], 3072)        # a setting, not an acceptance limit
        self.assertIn('settings', m['profile_note'])

    def test_profiles_per_kind(self):
        drivers = lambda m: {m['artifacts'][n]['driver'] for n in ('forwarder', 'bridge', 'forwarder_b', 'bridge_b') if m['artifacts'][n]}
        for kind in ('s16', 's16-n1', 's16-a03', 's16-a05', 's16-red-a03'):
            _, m = self.built(kind)
            self.assertEqual(m.get('engine_driver', 'embedded'), 'embedded', kind); self.assertEqual(drivers(m), {'external'}, kind)
        for kind in ('s16-ext', 's16-red-a04', 's16-ctl-edk-cnctimeout'):
            _, m = self.built(kind)
            self.assertEqual(m['engine_driver'], 'external', kind)
            self.assertEqual(set(m['engine_libs']), core_contracts.ENGINE_LIBS)
            self.assertEqual(Path(m['engine_libs']['driver.properties']['path']).read_text(), DP_TEXT)
            self.assertEqual(Path(m['engine_libs']['driver-dev.properties']['path']).read_text(), mk_manifests.DEV_OVERLAY)
        for kind in ('s16-embedded', 's16-a03-embedded', 's16-a05-embedded'):
            _, m = self.built(kind)
            self.assertEqual(drivers(m), {'embedded'}, kind)
        _, m = self.built('s16-n1'); self.assertIsNone(m['slot_artifacts']['fwd1'])
        _, m = self.built('s16-a03')
        self.assertEqual(m['slot_artifacts']['fwd0'], 'forwarder_b')
        self.assertEqual((m['artifacts']['forwarder_b']['target'], m['artifacts']['forwarder']['target']),
                         ('ct_forwarder_nc_norelease', 'ct-forwarder'))
        _, m = self.built('s16-a05')
        self.assertEqual((m['artifacts']['forwarder_b']['source_sha'], m['artifacts']['bridge_b']['source_sha']), (B_SHA, B_SHA))
        self.assertEqual(m['slot_artifacts'], {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge',
                                               'shadow0': None})
        _, m = self.built('s16-red-a04')
        self.assertEqual(m['slot_artifacts']['bridge0'], 'bridge_b'); self.assertEqual(m['artifacts']['bridge_b']['target'], 'ct_bridge_nc_noepoch')

    def test_build_b_needs_its_source_sha(self):
        with self.assertRaisesRegex(Violation, '40-hex source_sha'):
            self.built('s16-a05', b_source_sha=None)

    def test_driver_properties_must_be_the_pinned_copy(self):
        with self.assertRaisesRegex(Violation, 'driver.properties is not the pinned c53dd20 copy'):
            self.built('s16-ext', driver_properties_sha256='0' * 64)

    def test_a_missing_negative_build_is_named(self):
        (self.root / 'build-s16/app/bridge/ct_bridge_nc_noepoch').unlink()
        with self.assertRaisesRegex(Violation, 'ct_bridge_nc_noepoch .* not built'):
            self.built('s16-red-a04')

    def test_two_runs_of_a_kind_differ_only_in_identity(self):
        _, a = self.built('s16-ext'); _, b = mk_manifests.build('s16-ext', 'r2', self.cfg)
        diff = {k for k in a if a[k] != b[k]}
        self.assertEqual(diff, {'run_id', 'state_root'})


if __name__ == '__main__':
    unittest.main()
