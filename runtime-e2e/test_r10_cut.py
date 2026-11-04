# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W2: the cut checker (contract 3.3, 5.1, 8.1). One RED per rule K1-K10, each refused with its rule and accepted with
that rule switched off (the C6 seam); the K4 exemption refused in a product kind; the guarded-row REDs of 8.1 (rows 02, 11, 22,
24, 26, 41, 52); a passing cut. No Docker, no real artifact: every jar and binary is a small file in a temp tree."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import r10_cut

SHAS = {'assets': 'a' * 40, 'match': 'b' * 40, 'cluster-kit': 'c' * 40, 'cluster-tools': 'd' * 40, 'tools': 'e' * 40}
TAG = {'match': '1' * 40, 'assets': '2' * 40}
SCHEMA_TEXT = {'money': b'<money v7/>', 'order': b'<order v12/>', 'me_journal': b'<journal v1/>'}
OLD_SCHEMA_TEXT = {'money': b'<money v4/>', 'order': b'<order v7/>'}
KIT_PIN = '0.1.12-runtime.20261104.rc2s17w12.g43847fb'


def h(data):
    return hashlib.sha256(data).hexdigest()


SCHEMAS = {k: h(v) for k, v in SCHEMA_TEXT.items()}


def jar_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, data in sorted(members.items()):
            z.writestr(zipfile.ZipInfo(name, (2026, 11, 1, 0, 0, 0)), data)
    return buf.getvalue()


def engine_jar(name, kit=KIT_PIN, schema_text=SCHEMA_TEXT, marker=b''):
    members = {'MANIFEST': b'jar ' + name.encode() + marker}
    spec = r10_cut.PRODUCT[name]
    for schema, member in spec['schemas'].items():
        if schema in schema_text:
            members[member] = schema_text[schema]
    if kit is not None:
        members[r10_cut.KIT_POM] = f'groupId=com.openexchange\nversion={kit}\n'.encode()
    return jar_bytes(members)


class World:
    """A cut with every product artifact, its build record (two builds of each jar), the harness and the pins."""

    def __init__(self, root):
        self.root = Path(root)
        self.pins = {}
        self.record = {}
        art = {}
        for name in ('match-cluster.jar', 'assets-cluster.jar', 'assets-projector.jar'):
            data = engine_jar(name)
            repo = r10_cut.PRODUCT[name]['repo']
            p = self.put('artifacts/' + name, data)
            self.build(name, repo, SHAS[repo], data, 2)
            art[name] = self.entry(p, SHAS[repo], 'rebuild-equal')
        ct = SHAS['cluster-tools']
        for name, schemas in (('ct-forwarder', ('money', 'order')), ('ct-bridge', ('money', 'me_journal'))):
            data = b'ELF ' + name.encode() + b' ' + ct.encode() + b' ' + b' '.join(SCHEMAS[s].encode() for s in schemas)
            p = self.put('artifacts/' + name, data)
            self.build(name, 'cluster-tools', ct, data, 1)
            art[name] = self.entry(p, ct, 'binary-build-info')
        for name in ('aeronmd', 'libaeron_driver.so', 'libaeron.so'):
            data = b'ELF ' + name.encode() + b' aeron 1.53.1'
            p = self.put('artifacts/' + name, data)
            self.build(name, 'cluster-tools', ct, data, 1)
            art[name] = self.entry(p, ct, 'binary-build-info')
        kit = jar_bytes({'kit': b'kit'})
        kp = self.put('artifacts/cluster-kit.jar', kit)
        self.build('cluster-kit.jar', 'cluster-kit', SHAS['cluster-kit'], kit, 2)
        harness = {}
        for key, mode in (('core_probe', 'embedded'), ('journal_probe', 'embedded'), ('t1_me_driver', 'external'),
                          ('t1_core_driver', 'external')):
            p = self.put('harness/' + key, key.encode()); src = self.put('harness/' + key + '.java', b'src ' + key.encode())
            harness[key] = {'path': str(p), 'sha256': h(key.encode()), 'kind': 'harness', 'driver_mode': mode,
                            'source_path': str(src), 'source_sha256': h(src.read_bytes())}
        for key in ('probe_aeronmd', 'probe_libaeron_driver.so', 'probe_libaeron.so'):
            p = self.put('harness/' + key, b'S16 probe ' + key.encode())
            harness[key] = {'path': str(p), 'sha256': h(p.read_bytes()), 'kind': 'harness', 'driver_mode': 'external'}
        self.write_record()
        self.m = {
            'schema': r10_cut.SCHEMA, 'class': 'product', 'cut_id': 'rc2-cut-1', 'created': '2026-11-04T00:00:00Z',
            'harness_commit': SHAS['tools'], 'repos': dict(SHAS), 'schemas': dict(SCHEMAS),
            'substrate': {'aeron': {k: '1.53.1' for k in r10_cut.SUBSTRATE_AERON}, 'kit_pin': KIT_PIN,
                          'kit_jar': {'path': str(kp), 'sha256': h(kit), 'source_sha': SHAS['cluster-kit'],
                                      'derivation': 'rebuild-equal', 'tree_dirty': False}, 'sbe': '1.40.1'},
            'artifacts': art, 'harness': harness,
            'genesis': {'me': {'configVersion': 1, 'behaviorVersion': 2, 'commandLedgerCapacity': 100000, 'maxWireVersion': 12,
                               'genesisId': 'per-genesis'},
                        'core': {'configVersions': [1, 2, 3], 'genesisId': 'per-genesis'}, 'order': ['me', 'bridges', 'core']},
            'driver_profiles': {'prod': {p: 'external' for p in r10_cut.PROCESSES},
                                'dev': {**{p: 'embedded' for p in ('me', 'ae', 'projector')}, 'forwarder': 'external',
                                        'bridge': 'external'}},
            'retired': sorted(r10_cut.RETIRED) + ['rc1-tools'], 'excluded': ['oms-execution-projector'],
            'build_record': self.record_ref(),
        }

    def put(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def build(self, name, repo, source, data, times, tag=''):
        for i in range(times):
            p = self.put(f'builds/{name}{tag}-{source[:4]}-{i}', data)
            self.record.setdefault(name, []).append({'repo': repo, 'source_sha': source, 'path': str(p), 'sha256': h(data)})

    def write_record(self):
        self.put('builds/record.json', json.dumps(self.record).encode())

    def record_ref(self):
        p = self.root / 'builds/record.json'
        return {'path': str(p), 'sha256': h(p.read_bytes())}

    def refresh_record(self, m):
        self.write_record()
        m['build_record'] = self.record_ref()
        self.m['build_record'] = self.record_ref()

    @staticmethod
    def entry(path, source, derivation):
        return {'path': str(path), 'sha256': h(Path(path).read_bytes()), 'source_sha': source, 'derivation': derivation,
                'tree_dirty': False, 'kind': 'product'}

    def pin(self, path, source, name):
        self.pins[h(Path(path).read_bytes())] = {'name': name, 'source_sha': source, 'recipe': 'r', 'recipe_sha256': '0' * 64}

    def tag_jar(self, name, kit='0.1.2'):
        repo = r10_cut.PRODUCT[name]['repo']
        p = self.put('old/' + name, engine_jar(name, kit=kit, schema_text={**SCHEMA_TEXT, **OLD_SCHEMA_TEXT}, marker=b' tag'))
        self.pin(p, TAG[repo], name)
        return p, TAG[repo]


class CheckerBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.w = World(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m, rules=r10_cut.RULES, cls=None):
        return r10_cut.check(m, cls=cls, rules=rules, old_pins=self.w.pins)

    def refused(self, m, expected, cls=None, exact=True):
        """``expected`` rules refuse ``m``; with exactly those switched off it passes (C6: the RED is the rule's)."""
        found = self.check(m, cls=cls)
        rules = set(found.by_rule())
        if exact:
            self.assertEqual(rules, set(expected), found.items)
        else:
            self.assertTrue(set(expected) <= rules, found.items)
        off = self.check(m, rules=tuple(r for r in r10_cut.RULES if r not in rules), cls=cls)
        self.assertEqual(off.items, [], 'passes with the refusing rules switched off')
        return found


class PassingCutTest(CheckerBase):
    def test_the_cut_passes(self):
        self.assertEqual(self.check(self.w.m).items, [])

    def test_cli_exit_codes(self):
        good = self.w.put('cut.json', json.dumps(self.w.m).encode())
        pins = self.w.put('pins.txt', b'')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(r10_cut.main(['check', str(good), '--old-pins', str(pins)]), 0)
            bad = copy.deepcopy(self.w.m); bad['genesis']['me']['behaviorVersion'] = 1
            badp = self.w.put('bad.json', json.dumps(bad).encode())
            self.assertEqual(r10_cut.main(['check', str(badp), '--old-pins', str(pins)]), 1)
        self.assertIn('K6 genesis.me.behaviorVersion must be 2', out.getvalue())


class RuleRedTest(CheckerBase):
    def test_k1_rehash_dirty_tree_and_missing_source(self):
        m = copy.deepcopy(self.w.m)
        Path(m['harness']['core_probe']['path']).write_bytes(b'changed')
        self.refused(m, {'K1'})
        m = copy.deepcopy(self.w.m); m['artifacts']['aeronmd']['tree_dirty'] = True
        self.refused(m, {'K1'})

    def test_k2_embedded_schema_identity(self):
        m = copy.deepcopy(self.w.m); m['schemas']['me_journal'] = '9' * 64      # the C++ bridge and the ME jar both disagree
        self.refused(m, {'K2'})
        m = copy.deepcopy(self.w.m)
        data = engine_jar('assets-cluster.jar', schema_text={**SCHEMA_TEXT, 'money': b'<money v6/>'})
        p = self.w.put('artifacts/assets-cluster-v6.jar', data)
        self.w.record['assets-cluster.jar'] = []
        self.w.build('assets-cluster.jar', 'assets', SHAS['assets'], data, 2, tag='v6')
        self.w.refresh_record(m)
        m['artifacts']['assets-cluster.jar'] = World.entry(p, SHAS['assets'], 'rebuild-equal')
        self.refused(m, {'K2'})

    def test_k3_negative_build_in_a_product_kind(self):
        m = copy.deepcopy(self.w.m)
        p = self.w.put('artifacts/ct_forwarder_nc_norelease', b'nc')
        m['artifacts']['ct_forwarder_nc_norelease'] = World.entry(p, SHAS['cluster-tools'], 'binary-build-info')
        self.refused(m, {'K3'})
        m = copy.deepcopy(self.w.m)
        m['artifacts']['forwarder_b'] = World.entry(p, SHAS['cluster-tools'], 'binary-build-info')
        self.refused(m, {'K3'})

    def test_k4_source_not_the_repo_entry_and_not_derived(self):
        m = copy.deepcopy(self.w.m); m['artifacts']['ct-bridge']['source_sha'] = 'f' * 40
        self.refused(m, {'K4'})
        m = copy.deepcopy(self.w.m); m['artifacts']['match-cluster.jar']['derivation'] = 'attested'
        self.refused(m, {'K4'})
        self.assertEqual(self.check(m, cls='rig').items, [])     # attested is refused in a product kind only
        m = copy.deepcopy(self.w.m); self.w.record['match-cluster.jar'].pop(); self.w.refresh_record(m)
        self.refused(m, {'K4'})                                   # one build is not rebuild-equal

    def test_k4_exemption_refused_in_a_product_kind(self):
        m = copy.deepcopy(self.w.m)
        p, src = self.w.tag_jar('match-cluster.jar')
        m['upgrade_from'] = {'match-cluster.jar': {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': src}}
        self.refused(m, {'K4'})
        self.assertEqual(self.check(m, cls='rig').items, [])
        m['upgrade_from']['match-cluster.jar']['source_sha'] = 'f' * 40       # pinned under another source: refused in a rig too
        self.assertEqual(self.check(m, cls='rig').by_rule(), ['K4'])

    def test_k5_retired_artifact(self):
        m = copy.deepcopy(self.w.m)
        p = self.w.put('artifacts/oms-app.jar', b'oms')
        m['artifacts']['oms-app'] = World.entry(p, SHAS['assets'], 'attested')
        self.refused(m, {'K5'})

    def test_k6_genesis_block(self):
        for edit in (lambda m: m['genesis']['me'].update(behaviorVersion=1),
                     lambda m: m['genesis']['me'].update(maxWireVersion=11),
                     lambda m: m['genesis']['core'].update(configVersions=[1, 3]),
                     lambda m: m['genesis']['core'].update(genesisId=7),
                     lambda m: [m['genesis'][k].update(genesisId=15112027) for k in ('me', 'core')]):
            m = copy.deepcopy(self.w.m); edit(m)
            with self.subTest(m=m['genesis']):
                self.refused(m, {'K6'})
        m = copy.deepcopy(self.w.m); [m['genesis'][k].update(genesisId=15112027) for k in ('me', 'core')]
        self.assertEqual(self.check(m, cls='rig').items, [])     # a rig manifest may carry the genesis it ran

    def test_k7_driver_profiles(self):
        m = copy.deepcopy(self.w.m); m['driver_profiles']['prod']['projector'] = 'embedded'
        self.refused(m, {'K7'})
        m = copy.deepcopy(self.w.m); m['driver_profiles']['dev']['me'] = 'java_media_driver'
        self.refused(m, {'K7'})
        m = copy.deepcopy(self.w.m); m['harness']['t1_core_driver']['driver_mode'] = 'host'
        self.refused(m, {'K7'})

    def test_k8_mixed_aeron(self):
        m = copy.deepcopy(self.w.m); m['substrate']['aeron']['ae'] = '1.53.0'   # the S16 W9b set (8.1 vii)
        self.refused(m, {'K8'})

    def test_k9_unknown_missing_and_short(self):
        for edit in (lambda m: m['substrate'].update(aeron_mixed=True),          # 8.1 (vii): no exception key exists
                     lambda m: m['driver_profiles'].update(projector_embedded=True),
                     lambda m: m.pop('genesis'),
                     lambda m: m['repos'].update(match='c356895'),
                     lambda m: m.update(members={'ae2': {'artifact': 'x'}})):
            m = copy.deepcopy(self.w.m); edit(m)
            with self.subTest():
                self.refused(m, {'K9'}, exact=False)

    def test_k10_kit_pins(self):
        m = copy.deepcopy(self.w.m)
        data = engine_jar('assets-projector.jar', kit='0.1.11-runtime.20261104.rc2s17.g80502de')
        p = self.w.put('artifacts/assets-projector-k11.jar', data)
        self.w.record['assets-projector.jar'] = []
        self.w.build('assets-projector.jar', 'assets', SHAS['assets'], data, 2, tag='k11')
        self.w.refresh_record(m)
        m['artifacts']['assets-projector.jar'] = World.entry(p, SHAS['assets'], 'rebuild-equal')
        self.refused(m, {'K10'})


class GuardedRowRedTest(CheckerBase):
    """8.1: each GUARDED row's manifest is refused by the checker (rows 02, 11, 22, 24, 26, 41, 52)."""

    def swap(self, name, path, source, derivation='rebuild-equal'):
        m = copy.deepcopy(self.w.m)
        m['artifacts'][name] = World.entry(path, source, derivation)
        return m

    def test_row_02_tag_me_jar_in_a_product_cut(self):
        p, src = self.w.tag_jar('match-cluster.jar')
        found = self.refused(self.swap('match-cluster.jar', p, src), {'K2', 'K4'}, exact=False)
        self.assertIn('K10', found.by_rule())                 # the tag jar was also built on kit 0.1.2
        m = copy.deepcopy(self.w.m)
        m['old_artifacts'] = {'match-cluster.jar': {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': src}}
        self.refused(m, {'K4'})                               # the same jar under old_artifacts in a product kind

    def test_row_11_tag_ae_jar_in_a_product_cut(self):
        p, src = self.w.tag_jar('assets-cluster.jar')
        self.refused(self.swap('assets-cluster.jar', p, src), {'K2', 'K4'}, exact=False)
        m = copy.deepcopy(self.w.m)
        m['old_artifacts'] = {'assets-cluster.jar': {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': src}}
        self.refused(m, {'K4'})

    def test_row_22_assets_bridge_in_a_core_manifest(self):
        m = copy.deepcopy(self.w.m)
        p = self.w.put('old/assets-bridge.jar', b'bridge'); self.w.pin(p, TAG['assets'], 'assets-bridge.jar')
        m['artifacts']['assets-bridge'] = World.entry(p, TAG['assets'], 'attested')
        self.refused(m, {'K5'})
        m = copy.deepcopy(self.w.m)                            # nor as the upgrade source of a rig manifest
        m['upgrade_from'] = {'bridge': {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': TAG['assets']}}
        self.assertEqual(self.check(m, cls='rig').by_rule(), ['K5'])

    def test_row_24_oms_app_in_a_core_manifest(self):
        m = copy.deepcopy(self.w.m)
        p = self.w.put('old/oms-app.jar', b'oms'); self.w.pin(p, '3' * 40, 'oms-app.jar')
        m['artifacts']['oms-app'] = World.entry(p, '3' * 40, 'attested')
        self.refused(m, {'K5'})

    def test_row_26_tag_projector_jar_in_a_product_cut(self):
        p, src = self.w.tag_jar('assets-projector.jar', kit=None)      # the tag projector carries no kit pom
        self.refused(self.swap('assets-projector.jar', p, src), {'K2', 'K4'}, exact=False)

    def test_row_41_a_second_jar_for_one_engine_member(self):
        p, src = self.w.tag_jar('assets-cluster.jar')
        m = copy.deepcopy(self.w.m)
        m['members'] = {'ae2': {'artifact': {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': src}}}
        self.refused(m, {'K9', 'K4'})
        m = copy.deepcopy(self.w.m)
        m['artifacts']['assets-cluster.jar@ae2'] = World.entry(p, src, 'rebuild-equal')
        self.refused(m, {'K9', 'K4'})

    def test_row_52_pre_w12_match_jar_in_an_s17_cut(self):
        w11 = '4' * 40          # match cd3d79e (W11), built and labelled honestly, beside the cut assets jar
        data = engine_jar('match-cluster.jar', kit='0.1.11-runtime.20261104.rc2s17.g80502de', marker=b' w11')
        p = self.w.put('old/match-cluster-w11.jar', data)
        m = self.swap('match-cluster.jar', p, w11)
        self.w.build('match-cluster.jar', 'match', w11, data, 2, tag='w11'); self.w.refresh_record(m)
        found = self.refused(m, {'K4'}, exact=False)
        self.assertIn('K10', found.by_rule())
        m = copy.deepcopy(self.w.m)
        m['artifacts']['match-cluster.jar@me1'] = World.entry(p, w11, 'rebuild-equal')
        self.refused(m, {'K9', 'K4'})


class FixtureManifestTest(CheckerBase):
    """5.3 / 8.1 (i): a fixture manifest is checked against its cut; a ``*_b`` stage is refused in a product kind."""

    def fixture(self, b=False):
        a = self.w.m['artifacts']
        libs = {n: {'path': a[n]['path'], 'sha256': a[n]['sha256']} for n in ('aeronmd', 'libaeron_driver.so', 'libaeron.so')}
        slot = lambda n, key: {'path': a[n]['path'], 'sha256': a[n]['sha256'], 'source_sha': a[n]['source_sha'],
                               'driver': 'external', 'target': n, 'libs': libs}
        art = {'me': {k: a['match-cluster.jar'][k] for k in ('path', 'sha256', 'source_sha')},
               'ae': {k: a['assets-cluster.jar'][k] for k in ('path', 'sha256', 'source_sha')},
               'projector': {k: a['assets-projector.jar'][k] for k in ('path', 'sha256', 'source_sha')},
               'forwarder': slot('ct-forwarder', 'forwarder'), 'bridge': slot('ct-bridge', 'bridge'),
               'forwarder_b': slot('ct-forwarder', 'forwarder_b') if b else None,
               'bridge_b': slot('ct-bridge', 'bridge_b') if b else None, 'shadow': None}
        h_ = self.w.m['harness']
        return {'schema_version': 2, 'topology': 'core', 'manifest_kind': 's17-ext', 'artifacts': art,
                'engine_driver': 'external', 'projector_driver': 'external',
                **{k: {'path': h_[k]['path'], 'sha256': h_[k]['sha256']} for k in ('core_probe', 'journal_probe',
                                                                                    't1_me_driver', 't1_core_driver')}}

    def test_derived_rig_manifest_passes(self):
        self.assertEqual(r10_cut.check(self.fixture(), self.w.m, 'rig', old_pins=self.w.pins).items, [])

    def test_a_b_stage_is_refused_in_a_product_kind(self):
        found = r10_cut.check(self.fixture(b=True), self.w.m, 'product', old_pins=self.w.pins)
        self.assertEqual(found.by_rule(), ['K3'])
        self.assertEqual(r10_cut.check(self.fixture(b=True), self.w.m, 'rig', old_pins=self.w.pins).items, [])

    def test_bytes_outside_the_cut_are_refused(self):
        m = self.fixture()
        p = self.w.put('foreign.jar', b'foreign')
        m['artifacts']['ae'] = {'path': str(p), 'sha256': h(b'foreign'), 'source_sha': SHAS['assets']}
        self.assertEqual(r10_cut.check(m, self.w.m, 'rig', old_pins=self.w.pins).by_rule(), ['K4'])

    def test_a_fixture_manifest_needs_its_cut(self):
        self.assertEqual(r10_cut.check(self.fixture(), None).by_rule(), ['K9'])


if __name__ == '__main__':
    unittest.main()
