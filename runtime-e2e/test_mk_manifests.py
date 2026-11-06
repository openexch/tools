# SPDX-License-Identifier: Apache-2.0
"""RC2 S16 W1: the manifest builder promoted from S15 evidence (contract 3.1, 3.2, 5.2, 5.3, 15 W1; 20.1 lines 2, 11).
No Docker: every pinned input is a small file in a temp tree."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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


class CutManifestBuilderTest(unittest.TestCase):
    """RC2 S17 W2 (contract 5.3): ``mk_manifests.py --cut`` derives the s17 kinds from the cut manifest and refuses to emit a
    manifest the checker refuses."""

    def setUp(self):
        import test_r10_cut
        self.temp = tempfile.TemporaryDirectory(); root = self.root = Path(self.temp.name)
        self.world = test_r10_cut.World(root / 'cut')
        self.cut_path = root / 'rc2-cut-manifest.json'
        self.cut_path.write_text(json.dumps(self.world.m))
        patch = mock.patch.object(mk_manifests.r10_cut, 'git_blob', self.world.blob); patch.start(); self.addCleanup(patch.stop)
        def put(rel, data):
            path = root / rel; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); return path
        self.bin_a = root / 'bin-s15'
        for name in ('ct-forwarder', 'ct-bridge', 'aeronmd', 'libaeron.so', 'libaeron_driver.so'):
            p = put('bin-s15/' + name, b'build A ' + name.encode())
            self.world.pin(p, mk_manifests.CT_A_SOURCE_SHA, name)
        dp = put('me/driver.properties', DP_TEXT.encode())
        put('helper/iptables-legacy', b'ipt')
        ct = self.world.m['repos']['cluster-tools']        # the negative targets: a test-config build of the cut's ct commit
        for sub, target in (('forwarder', 'ct_forwarder_nc_norelease'), ('bridge', 'ct_bridge_nc_noepoch'),
                            ('forwarder', 'ct_forwarder_nc_noresync'), ('bridge', 'ct_bridge_nc_legacy')):
            put(f'ct-test/app/{sub}/{target}', b'ELF nc ' + target.encode() + b' ' + ct.encode())
        self.cfg = mk_manifests.Config(
            runs=root / 'runs', bin_a=self.bin_a, driver_properties=dp,
            driver_properties_sha256=hashlib.sha256(DP_TEXT.encode()).hexdigest(), netfilter_helper=root / 'helper',
            harness_commit='e' * 40, harness_dirty=False, image='sha256:' + 'e' * 64, cut_nc_dir=root / 'ct-test')

    def tearDown(self):
        self.temp.cleanup()

    def built(self, kind, cut=None):
        path, m = mk_manifests.build_from_cut(kind, 'r1', cut or self.cut_path, self.cfg, old_pins=self.world.pins)
        core_contracts.validate_core_manifest(json.loads(path.read_text()), path, cpu_count=24, require_me_enforced=True)
        return path, m

    def test_every_s17_kind_builds_validates_and_passes_the_checker(self):
        import r10_cut
        self.assertEqual(set(mk_manifests.KINDS17), core_contracts.S17_KINDS)
        cut = self.world.m['artifacts']
        for kind in sorted(mk_manifests.KINDS17):
            with self.subTest(kind=kind):
                path, m = self.built(kind)
                self.assertEqual(path.name, kind + '--r1.json')
                self.assertEqual(m['manifest_kind'], kind)
                for role, name in (('me', 'match-cluster.jar'), ('ae', 'assets-cluster.jar'), ('projector', 'assets-projector.jar')):
                    self.assertEqual(m['artifacts'][role]['sha256'], cut[name]['sha256'], (kind, role))
                cls = mk_manifests.cut_class(kind)
                self.assertEqual(r10_cut.check(m, self.world.m, cls, old_pins=self.world.pins).items, [], kind)
                self.assertEqual(m['core_probe']['sha256'], self.world.m['harness']['core_probe']['sha256'])
                self.assertEqual(m['probe_libs']['aeronmd']['sha256'], self.world.m['harness']['probe_aeronmd']['sha256'])

    def test_slots_profiles_and_build_a(self):
        cut = self.world.m['artifacts']
        _, m = self.built('s17')
        self.assertEqual((m['artifacts']['forwarder']['sha256'], m['artifacts']['bridge']['sha256']),
                         (cut['ct-forwarder']['sha256'], cut['ct-bridge']['sha256']))
        self.assertEqual(m['artifacts']['forwarder']['libs']['aeronmd']['sha256'], cut['aeronmd']['sha256'])
        self.assertEqual((m.get('engine_driver', 'embedded'), m['projector_driver']), ('embedded', 'embedded'))
        _, m = self.built('s17-ext')
        self.assertEqual((m['engine_driver'], m['projector_driver']), ('external', 'external'))
        self.assertEqual(m['projector_libs']['aeronmd']['sha256'], cut['aeronmd']['sha256'])
        self.assertEqual(m['engine_libs']['aeronmd']['sha256'], cut['aeronmd']['sha256'])
        _, m = self.built('s17-a05')
        self.assertEqual(m['artifacts']['forwarder']['source_sha'], mk_manifests.CT_A_SOURCE_SHA)    # build A = upgrade_from
        self.assertEqual(m['artifacts']['forwarder_b']['sha256'], cut['ct-forwarder']['sha256'])     # build B = the cut
        _, m = self.built('s17-a05-reverse')
        self.assertEqual(m['artifacts']['forwarder']['sha256'], cut['ct-forwarder']['sha256'])
        self.assertEqual(m['artifacts']['bridge_b']['source_sha'], mk_manifests.CT_A_SOURCE_SHA)

    def test_negative_kinds_stage_the_cut_s_test_builds(self):
        cut = self.world.m['artifacts']
        _, m = self.built('s17-a03')
        self.assertEqual((m['artifacts']['forwarder_b']['target'], m['slot_artifacts']['fwd0']), ('ct_forwarder_nc_norelease', 'forwarder_b'))
        self.assertEqual(m['artifacts']['forwarder']['sha256'], cut['ct-forwarder']['sha256'])
        _, m = self.built('s17-red-a03')
        self.assertIsNone(m['artifacts']['forwarder'])
        _, m = self.built('s17-red-a04')
        self.assertEqual((m['artifacts']['bridge_b']['target'], m['engine_driver']), ('ct_bridge_nc_noepoch', 'external'))
        self.assertEqual(m['artifacts']['bridge_b']['source_sha'], self.world.m['repos']['cluster-tools'])
        (self.root / 'ct-test/app/bridge/ct_bridge_nc_noepoch').write_bytes(b'ELF nc built from another commit')
        with self.assertRaisesRegex(Violation, 'K4 .*not a build of the cut'):
            self.built('s17-red-a04')

    def test_xver_kinds_take_the_legacy_member_addresses(self):
        """RC2 S17 W3 (W0 mk_dr --legacy-ips): a seeded state meets the member addresses it was written with (the legacy
        fixture's me .10-.12, ae .13-.15); every other kind keeps the sorted layout."""
        for kind in ('s17-xver', 's17-xver-ext', 's17-rollback'):
            with self.subTest(kind=kind):
                _, m = self.built(kind)
                o = m['network']['subnet'].split('.')[2]
                self.assertEqual([m['nodes'][f'me{i}'] for i in range(3)], [f'172.30.{o}.{10 + i}' for i in range(3)])
                self.assertEqual([m['nodes'][f'ae{i}'] for i in range(3)], [f'172.30.{o}.{13 + i}' for i in range(3)])
                self.assertEqual(len(set(m['nodes'].values())), len(m['nodes']))
                self.assertEqual(m['node_layout'], 'legacy')
        _, m = self.built('s17-act')
        self.assertNotIn('node_layout', m)
        self.assertEqual(m['nodes']['ae0'].rsplit('.', 1)[1], '10')

    def test_red1_and_red2_on_the_cut(self):
        """RC2 S17 W3 (coordinator): the S15 RED-1 / RED-2 on the cut: the nc target of the cut's ct commit in both slots."""
        _, m = self.built('s17-red1')
        self.assertEqual((m['artifacts']['forwarder_b']['target'], m['slot_artifacts']['fwd0'], m['slot_artifacts']['fwd1']),
                         ('ct_forwarder_nc_noresync', 'forwarder_b', 'forwarder_b'))
        self.assertIsNone(m['artifacts']['forwarder'])
        _, m = self.built('s17-red2')
        self.assertEqual((m['artifacts']['bridge_b']['target'], m['slot_artifacts']['bridge0'], m['slot_artifacts']['bridge1']),
                         ('ct_bridge_nc_legacy', 'bridge_b', 'bridge_b'))
        self.assertIsNone(m['artifacts']['bridge'])
        self.assertEqual(m['artifacts']['bridge_b']['source_sha'], self.world.m['repos']['cluster-tools'])

    def test_build_a_must_be_pinned(self):
        self.world.pins.clear()
        with self.assertRaisesRegex(Violation, 'K4 .*not pinned in R10/old-artifacts.sha256'):
            self.built('s17-a05')
        self.built('s17-ext')           # a kind without build A needs no pin

    def test_a_cut_the_checker_refuses_is_refused(self):
        bad = json.loads(self.cut_path.read_text()); bad['substrate']['aeron']['ae'] = '1.53.0'
        path = self.root / 'bad-cut.json'; path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(Violation, 'K8 cut: substrate Aeron versions differ'):
            self.built('s17-ext', cut=path)
        self.assertFalse((self.cfg.runs / 'manifests' / 's17-ext--r1.json').exists())

    def test_cli_cut_option(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(mk_manifests, 'Config', lambda **kw: self.cfg), \
                mock.patch.object(mk_manifests.r10_cut, 'load_old_pins', lambda path: self.world.pins):
            mk_manifests.main(['s17-ext', 'r1', '--cut', str(self.cut_path)])
        self.assertTrue(out.getvalue().strip().endswith('s17-ext--r1.json'))
