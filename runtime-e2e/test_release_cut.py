# SPDX-License-Identifier: Apache-2.0
"""The cut checker. One RED per rule K1-K10, each refused with its rule and accepted with
that rule switched off (the rules seam); the K4 exemption refused in a product kind; the guarded-row REDs (rows 02, 11, 22,
24, 26, 41, 52); a passing cut. No Docker, no real artifact: every jar and binary is a small file in a temp tree."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

import release_cut

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


def engine_jar(name, kit=KIT_PIN, schema_text=SCHEMA_TEXT, marker=b'', aeron='1.53.1'):
    members = {'MANIFEST': b'jar ' + name.encode() + marker}
    if aeron is not None:                                  # K8 reads the version the jar carries
        members[release_cut.AERON_VERSION_CLASS] = b'\xca\xfe\x01\x00\x06' + aeron.encode() + b'\x01'
    spec = release_cut.PRODUCT[name]
    for schema, member in spec['schemas'].items():
        if schema in schema_text:
            members[member] = schema_text[schema]
    if kit is not None:
        members[release_cut.KIT_POM] = f'groupId=com.openexchange\nversion={kit}\n'.encode()
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
            repo = release_cut.PRODUCT[name]['repo']
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
            p = self.put('harness/' + key, b'old probe ' + key.encode())
            harness[key] = {'path': str(p), 'sha256': h(p.read_bytes()), 'kind': 'harness', 'driver_mode': 'external'}
        self.write_record()
        self.m = {
            'schema': release_cut.SCHEMA, 'class': 'product', 'cut_id': 'rc2-cut-1', 'created': '2026-11-04T00:00:00Z',
            'harness_commit': SHAS['tools'], 'repos': dict(SHAS), 'schemas': dict(SCHEMAS),
            'substrate': {'aeron': {k: '1.53.1' for k in release_cut.SUBSTRATE_AERON}, 'kit_pin': KIT_PIN,
                          'kit_jar': {'path': str(kp), 'sha256': h(kit), 'source_sha': SHAS['cluster-kit'],
                                      'derivation': 'rebuild-equal', 'tree_dirty': False}, 'sbe': '1.40.1'},
            'artifacts': art, 'harness': harness,
            'genesis': {'me': {'configVersion': 1, 'behaviorVersion': 2, 'commandLedgerCapacity': 100000, 'maxWireVersion': 12,
                               'genesisId': 'per-genesis'},
                        'core': {'configVersions': [1, 2, 3], 'genesisId': 'per-genesis'}, 'order': ['me', 'bridges', 'core']},
            'driver_profiles': {'prod': {p: 'external' for p in release_cut.PROCESSES},
                                'dev': {**{p: 'embedded' for p in ('me', 'ae', 'projector')}, 'forwarder': 'external',
                                        'bridge': 'external'}},
            'retired': sorted(release_cut.RETIRED) + ['rc1-tools'], 'excluded': ['oms-execution-projector'],
            'build_record': self.record_ref(),
        }

    def put(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def build(self, name, repo, source, data, times, tag=''):
        for i in range(times):
            p = self.put(f'builds/b{i}{tag}-{source[:4]}/{name}', data)      # one build root per build
            self.record.setdefault(name, []).append({'repo': repo, 'source_sha': source, 'path': str(p), 'sha256': h(data)})

    def blob(self, repo, commit, rel):
        """The git seam: the harness source at the cut's commit is the source file the World wrote."""
        name = {v[1]: k for k, v in release_cut.HARNESS_SOURCES.items()}.get(rel)
        want = self.m['harness_commit'] if repo == 'tools' else self.m['repos']['cluster-tools']
        if name is None or commit != want:
            return None
        return Path(self.m['harness'][name]['source_path']).read_bytes()

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
        repo = release_cut.PRODUCT[name]['repo']
        p = self.put('old/' + name, engine_jar(name, kit=kit, schema_text={**SCHEMA_TEXT, **OLD_SCHEMA_TEXT}, marker=b' tag'))
        self.pin(p, TAG[repo], name)
        return p, TAG[repo]


class CheckerBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.w = World(self.temp.name)
        patch = mock.patch.object(release_cut, 'git_blob', self.w.blob); patch.start(); self.addCleanup(patch.stop)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m, rules=release_cut.RULES, cls=None):
        return release_cut.check(m, cls=cls, rules=rules, old_pins=self.w.pins)

    def refused(self, m, expected, cls=None, exact=True):
        """``expected`` rules refuse ``m``; with exactly those switched off it passes (the RED is the rule's)."""
        found = self.check(m, cls=cls)
        rules = set(found.by_rule())
        if exact:
            self.assertEqual(rules, set(expected), found.items)
        else:
            self.assertTrue(set(expected) <= rules, found.items)
        off = self.check(m, rules=tuple(r for r in release_cut.RULES if r not in rules), cls=cls)
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
            self.assertEqual(release_cut.main(['check', str(good), '--old-pins', str(pins)]), 0)
            bad = copy.deepcopy(self.w.m); bad['genesis']['me']['behaviorVersion'] = 1
            badp = self.w.put('bad.json', json.dumps(bad).encode())
            self.assertEqual(release_cut.main(['check', str(badp), '--old-pins', str(pins)]), 1)
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
        import core_contracts
        m = copy.deepcopy(self.w.m); [m['genesis'][k].update(genesisId=core_contracts.GENESIS_DERIVATION) for k in ('me', 'core')]
        self.assertEqual(self.check(m).items, [])               # the per-run derivation is accepted in a product kind

    def test_k7_driver_profiles(self):
        m = copy.deepcopy(self.w.m); m['driver_profiles']['prod']['projector'] = 'embedded'
        self.refused(m, {'K7'})
        m = copy.deepcopy(self.w.m); m['driver_profiles']['dev']['me'] = 'java_media_driver'
        self.refused(m, {'K7'})
        m = copy.deepcopy(self.w.m); m['harness']['t1_core_driver']['driver_mode'] = 'host'
        self.refused(m, {'K7'})

    def test_k8_mixed_aeron(self):
        m = copy.deepcopy(self.w.m); m['substrate']['aeron']['ae'] = '1.53.0'   # the older Aeron set
        self.refused(m, {'K8'})

    def test_k9_unknown_missing_and_short(self):
        for edit in (lambda m: m['substrate'].update(aeron_mixed=True),          # No exception key exists
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
    """Each GUARDED row's manifest is refused by the checker (rows 02, 11, 22, 24, 26, 41, 52)."""

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

    def test_row_52_older_match_jar_in_an_s17_cut(self):
        older = '4' * 40        # match cd3d79e, built and labelled honestly, beside the cut assets jar
        data = engine_jar('match-cluster.jar', kit='0.1.11-runtime.20261104.rc2s17.g80502de', marker=b' older')
        p = self.w.put('old/match-cluster-older.jar', data)
        m = self.swap('match-cluster.jar', p, older)
        self.w.build('match-cluster.jar', 'match', older, data, 2, tag='older'); self.w.refresh_record(m)
        found = self.refused(m, {'K4'}, exact=False)
        self.assertIn('K10', found.by_rule())
        m = copy.deepcopy(self.w.m)
        m['artifacts']['match-cluster.jar@me1'] = World.entry(p, older, 'rebuild-equal')
        self.refused(m, {'K9', 'K4'})


class FixtureManifestTest(CheckerBase):
    """A fixture manifest is checked against its cut; a ``*_b`` stage is refused in a product kind."""

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
                'harness_commit': self.w.m['harness_commit'], 'harness_dirty': False,
                'engine_driver': 'external', 'projector_driver': 'external',
                **{k: {'path': h_[k]['path'], 'sha256': h_[k]['sha256']} for k in ('core_probe', 'journal_probe',
                                                                                    't1_me_driver', 't1_core_driver')}}

    def test_derived_rig_manifest_passes(self):
        self.assertEqual(release_cut.check(self.fixture(), self.w.m, 'rig', old_pins=self.w.pins).items, [])

    def test_a_b_stage_is_refused_in_a_product_kind(self):
        found = release_cut.check(self.fixture(b=True), self.w.m, 'product', old_pins=self.w.pins)
        self.assertEqual(found.by_rule(), ['K3'])
        self.assertEqual(release_cut.check(self.fixture(b=True), self.w.m, 'rig', old_pins=self.w.pins).items, [])

    def test_bytes_outside_the_cut_are_refused(self):
        m = self.fixture()
        p = self.w.put('foreign.jar', b'foreign')
        m['artifacts']['ae'] = {'path': str(p), 'sha256': h(b'foreign'), 'source_sha': SHAS['assets']}
        self.assertEqual(release_cut.check(m, self.w.m, 'rig', old_pins=self.w.pins).by_rule(), ['K4'])

    def a03(self, kind, target='ct_forwarder_nc_norelease', slots=None):
        """An A03-shaped rig manifest: ``forwarder_b`` a negative target of the cut's ct commit (its stamp inside)."""
        m = self.fixture()
        p = self.w.put(f'artifacts/{target}', b'nc ' + SHAS['cluster-tools'].encode())
        m['manifest_kind'] = kind
        m['artifacts']['forwarder_b'] = {'path': str(p), 'sha256': h(p.read_bytes()), 'source_sha': SHAS['cluster-tools'],
                                         'driver': 'external', 'target': target}
        m['slot_artifacts'] = slots or {'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b', 'bridge0': 'bridge', 'bridge1': 'bridge',
                                        'shadow0': None}
        return m

    def test_the_declared_a03_phase_1_exception_and_nowhere_else(self):
        """A negative target in a GREEN rig kind is refused; the A03
        kinds stage ct_forwarder_nc_norelease in both forwarder slots with build A as forwarder; the RED kinds stage theirs.
        RED 5d0339f: the checker accepted the A03 negative staging on any rig kind (s17 included)."""
        for kind in ('s17-a03', 's17-a03-embedded'):
            with self.subTest(kind=kind):
                self.assertEqual(release_cut.check(self.a03(kind), self.w.m, 'rig', old_pins=self.w.pins).items, [])
        red = self.a03('s17-red-a03'); red['artifacts']['forwarder'] = None
        self.assertEqual(release_cut.check(red, self.w.m, 'rig', old_pins=self.w.pins).items, [])
        for why, m in {'GREEN kind': self.a03('s17'), 'A05 kind': self.a03('s17-a05'),
                       'other nc target': self.a03('s17-a03', target='ct_forwarder_nc_noresync'),
                       'one slot only': self.a03('s17-a03', slots={'fwd0': 'forwarder_b', 'fwd1': 'forwarder',
                                                                   'bridge0': 'bridge', 'bridge1': 'bridge', 'shadow0': None})}.items():
            with self.subTest(refused=why):
                found = release_cut.check(m, self.w.m, 'rig', old_pins=self.w.pins)
                self.assertEqual(found.by_rule(), ['K3'], found.items)
                self.assertIn('the declared A03 phase 1', ' '.join(t for _, t in found.items))

    def test_a_fixture_manifest_needs_its_cut(self):
        self.assertEqual(release_cut.check(self.fixture(), None).by_rule(), ['K9'])



# ------------------------------------------------------------------ log reader, audit, precheck, activation record

import struct
import shutil

MONEY_SCHEMA = b"""<?xml version="1.0" encoding="UTF-8"?>
<sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" package="t" id="2" version="7" byteOrder="littleEndian">
  <types>
    <composite name="messageHeader"><type name="blockLength" primitiveType="uint16"/><type name="templateId" primitiveType="uint16"/>
      <type name="schemaId" primitiveType="uint16"/><type name="version" primitiveType="uint16"/></composite>
    <composite name="groupSizeEncoding"><type name="blockLength" primitiveType="uint16"/><type name="numInGroup" primitiveType="uint16"/></composite>
  </types>
  <sbe:message name="CoreConfig" id="70">
    <field name="correlationId" id="1" type="int64"/>
    <field name="configVersion" id="2" type="uint32"/>
    <field name="behaviorVersion" id="3" type="uint32"/>
    <field name="genesisId" id="4" type="int64" sinceVersion="7"/>
    <group name="markets" id="10" dimensionType="groupSizeEncoding"><field name="marketId" id="1" type="int32"/></group>
    <group name="assets" id="11" dimensionType="groupSizeEncoding"><field name="assetId" id="1" type="int32"/></group>
  </sbe:message>
</sbe:messageSchema>
"""
import core_contracts
GID = int(core_contracts.derive_genesis_id('rc2-000000000001'), 16)     # The run's derived id


def log_entry(recording_id, term_id, position, kind, service_id=-1):
    return struct.pack('<qqqqqiI', recording_id, term_id, 0, position, 1793726197000, service_id, kind) + b'\0' * 16


def data_frame(payload, flags=0xC0, term_offset=0):
    length = 32 + len(payload)
    frame = struct.pack('<iBBHiiiiq', length, 0, flags, 1, term_offset, 7, 100, 0, 0) + payload
    return frame + b'\0' * (((length + 31) & ~31) - length)


def core_config_payload(version, genesis_id, schema_version=7):
    app = struct.pack('<HHHH', 24, 70, 2, schema_version) + struct.pack('<qIIq', 0x7000 + version, version, version, genesis_id)
    app += struct.pack('<HH', 4, 0) + struct.pack('<HH', 4, 0)
    return struct.pack('<HHHH', 24, 1, 111, 8) + b'\0' * 24 + app


def write_ae_member(state_root, member, frames, snapshot=False):
    base = Path(state_root) / 'state' / member / 'state'
    (base / 'cluster').mkdir(parents=True, exist_ok=True)
    (base / 'archive').mkdir(parents=True, exist_ok=True)
    entries = log_entry(0, 0, -1, 0)
    if snapshot:
        entries += log_entry(2, 0, 4096, 1, 0)
    (base / 'cluster' / 'recording.log').write_bytes(entries)
    data = b''.join(data_frame(p, term_offset=i * 32) for i, p in enumerate(frames))
    (base / 'archive' / '0-0.rec').write_bytes(data + b'\0' * 256)
    (base / 'archive' / '2-0.rec').write_bytes(data_frame(core_config_payload(1, 999)))     # a snapshot recording: not walked


class LogReaderTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.schema = self.root / 'money-schema.xml'; self.schema.write_bytes(MONEY_SCHEMA)

    def tearDown(self):
        self.temp.cleanup()

    def test_recording_log_entries_are_parsed(self):
        path = self.root / 'recording.log'
        path.write_bytes(log_entry(0, 0, -1, 0) + log_entry(1, 1, 13088, 1, 0) + log_entry(2, 1, 13088, 1 | (1 << 31), -1))
        entries = release_cut.recording_log(path)
        self.assertEqual([e['type'] for e in entries], ['TERM', 'SNAPSHOT', 'SNAPSHOT'])
        self.assertEqual([e['valid'] for e in entries], [True, True, False])
        self.assertEqual(entries[1]['log_position'], 13088)
        self.assertEqual(release_cut.snapshot_count(path), 1)
        path.write_bytes(b'\0' * 65)
        with self.assertRaisesRegex(ValueError, 'not a whole number of 64-byte entries'):
            release_cut.recording_log(path)

    def test_genesis_reader_walks_the_log_recording_of_every_member(self):
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.root, m, [b'\0' * 40] + [core_config_payload(v, GID) for v in (1, 2, 3)], snapshot=True)
        out = release_cut.genesis_reader(self.root, self.schema)
        self.assertEqual(out['genesis_id'], GID)
        self.assertTrue(out['equal'])
        self.assertEqual([f['configVersion'] for f in out['members']['ae1']['frames']], [1, 2, 3])
        self.assertEqual(out['members']['ae0']['recordings'], [0])      # the snapshot recording 2 is not walked

    def test_genesis_reader_reassembles_fragments_and_reports_a_refused_new_id(self):
        whole = core_config_payload(1, GID)
        frames = data_frame(whole[:20], flags=0x80) + data_frame(whole[20:], flags=0x40, term_offset=64)
        frames += data_frame(core_config_payload(1, GID + 2), term_offset=192)
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.root, m, [])
            (self.root / 'state' / m / 'state' / 'archive' / '0-0.rec').write_bytes(frames)
        out = release_cut.genesis_reader(self.root, self.schema)
        self.assertEqual(out['genesis_id'], GID)                          # the first CoreConfig 1 recorded the id
        self.assertEqual(out['other_ids_in_log'], [GID + 2])

    def test_genesis_reader_without_frames_is_not_observable(self):
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.root, m, [b'\0' * 40])
        out = release_cut.genesis_reader(self.root, self.schema)
        self.assertIsNone(out['genesis_id'])
        self.assertEqual(out['status'], 'not observable')

    def test_members_that_disagree_are_not_equal(self):
        write_ae_member(self.root, 'ae0', [core_config_payload(1, GID)])
        write_ae_member(self.root, 'ae1', [core_config_payload(1, GID)])
        write_ae_member(self.root, 'ae2', [core_config_payload(1, GID + 4)])
        out = release_cut.genesis_reader(self.root, self.schema)
        self.assertFalse(out['equal'])
        self.assertIsNone(out['genesis_id'])


def audit_manifest(directory):
    def art(name, data):
        p = Path(directory) / name; p.write_bytes(data)
        return {'path': str(p), 'sha256': h(data), 'source_sha': 'd' * 40}
    m = {'schema_version': 2, 'run_id': 'rc2-000000000001', 'manifest_kind': 's17-ext',
         'artifacts': {'me': art('me.jar', b'me'), 'ae': art('ae.jar', b'ae'), 'projector': art('projector.jar', b'pj'),
                       'forwarder': dict(art('fwd', b'fwd'), driver='external', libs={'aeronmd': {'path': '', 'sha256': h(b'md')}}),
                       'forwarder_b': dict(art('fwdb', b'fwdb'), driver='external', libs={'aeronmd': {'path': '', 'sha256': h(b'md')}}),
                       'bridge': dict(art('br', b'br'), driver='external', libs={'aeronmd': {'path': '', 'sha256': h(b'md')}}),
                       'bridge_b': None, 'shadow': None},
         'slot_artifacts': {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge', 'shadow0': None},
         'engine_driver': 'external', 'engine_libs': {'aeronmd': {'path': '', 'sha256': h(b'md')}},
         'projector_driver': 'external', 'projector_libs': {'aeronmd': {'path': '', 'sha256': h(b'md')}},
         'probe_libs': {'aeronmd': {'path': '', 'sha256': h(b'probe-md')}}}
    return m


def listing_for(m, overrides=None, drop=(), extra=()):
    """A recorded process listing equal to the manifest (the unit-test input of the audit)."""
    expected = release_cut.audit_expected(m)
    procs = []
    for role, files in sorted(expected.items()):
        if role in drop:
            procs.append({'role': role, 'running': False, 'files': {}})
            continue
        row = {'role': role, 'running': True, 'ready': True, 'files': {f['path']: f['sha256'] for f in files['files']}}
        if files.get('build'):
            row['build'] = files['build']
        if files.get('aeron_version_of'):
            row['aeron_version'] = '1.53.1'
        procs.append(row)
    for role, path, sha in (overrides or []):
        row = next(p for p in procs if p['role'] == role)
        row['files'][path] = sha
    procs += list(extra)
    return {'source': 'unit test', 'processes': procs}


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.m = audit_manifest(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def audit(self, listing, **kw):
        return release_cut.audit_check(listing, self.m, aeron_version='1.53.1', **kw)

    def test_a_listing_equal_to_the_manifest_passes(self):
        report = self.audit(listing_for(self.m))
        self.assertEqual(report['status'], 'OK', report['findings'])
        self.assertEqual(report['members_up'], {'me': 3, 'ae': 3})

    def test_red_a_slot_replaced_by_a_binary_not_in_the_manifest(self):
        report = self.audit(listing_for(self.m, [('fwd1', '/artifacts/forwarder/bin', 'f' * 64)]))
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIn('fwd1: /artifacts/forwarder/bin sha256 ffffffffffff', ' '.join(report['findings']))

    def test_the_declared_swap_pair_is_accepted_in_its_window_only(self):
        listing = listing_for(self.m, [('fwd0', '/artifacts/forwarder/bin', self.m['artifacts']['forwarder_b']['sha256'])])
        self.assertEqual(self.audit(listing)['status'], 'REFUSED')
        self.assertEqual(self.audit(listing, swap={'fwd0': ('forwarder', 'forwarder_b')})['status'], 'OK')
        # a replace_slot recorded in the registry names the slot's new artifact
        reg = {'slot_override': {'fwd0': 'forwarder_b'}}
        listing2 = listing_for(self.m)
        row = next(p for p in listing2['processes'] if p['role'] == 'fwd0')
        row['files'] = {'/artifacts/forwarder_b/bin': self.m['artifacts']['forwarder_b']['sha256'],
                        '/artifacts/forwarder_b/aeronmd': h(b'md')}
        self.assertEqual(release_cut.audit_check(listing2, self.m, registry=reg, aeron_version='1.53.1')['status'], 'OK')

    def test_build_a_without_a_health_build_field_is_judged_by_its_bytes(self):
        """RED 5d0339f: the genesis audit of every A05 kind (slots on build A, ct 2be3a19) was
        REFUSED, 'fwd0: /health.build None is not the source sha 2be3a1999ca1' x4, so the final records of entries 12, 13, 14,
        21, 27 read REFUSED in all three passes. Build A predates the field; its identity is its pinned sha256. Only those
        bytes may answer no build; build A answering one, or any other binary answering none, is still refused."""
        import core_contracts
        a = self.m['artifacts']
        for name in ('forwarder', 'bridge'):
            a[name]['source_sha'] = '2' * 40
        absent = {a['forwarder']['sha256']: 'ct-2be3a19/ct-forwarder', a['bridge']['sha256']: 'ct-2be3a19/ct-bridge'}
        listing = listing_for(self.m)
        for row in listing['processes']:
            if row['role'] in release_cut.SLOT_ROLES:
                row.pop('build', None)
        self.assertEqual(self.audit(listing)['status'], 'REFUSED')                  # not pinned as build-field-absent
        with mock.patch.dict(core_contracts.HEALTH_BUILD_ABSENT, absent):
            report = self.audit(listing)
            self.assertEqual(report['status'], 'OK', report['findings'])
            reporting = copy.deepcopy(listing)
            next(p for p in reporting['processes'] if p['role'] == 'fwd0')['build'] = '2' * 40
            self.assertIn('fwd0: /health.build 222222222222 but ct-2be3a19/ct-forwarder has no build field',
                          ' '.join(self.audit(reporting)['findings']))
            foreign = listing_for(self.m, [('bridge1', '/artifacts/bridge/bin', 'f' * 64)])
            next(p for p in foreign['processes'] if p['role'] == 'bridge1').pop('build', None)
            self.assertEqual(self.audit(foreign)['status'], 'REFUSED')
            # the declared upgrade pair in its window: build A (none) or build B (its source sha) both answer
            swapped = copy.deepcopy(listing)
            row = next(p for p in swapped['processes'] if p['role'] == 'fwd0')
            row.update(build=a['forwarder_b']['source_sha'], files=dict(row['files'], **{
                '/artifacts/forwarder/bin': a['forwarder_b']['sha256']}))
            self.assertEqual(self.audit(swapped, swap={'fwd0': ('forwarder', 'forwarder_b')})['status'], 'OK')
            self.assertEqual(self.audit(swapped)['status'], 'REFUSED')

    def test_red_a_host_aeronmd_of_another_version(self):
        listing = listing_for(self.m)
        next(p for p in listing['processes'] if p['role'] == 'probe')['aeron_version'] = '1.53.0'
        report = self.audit(listing)
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIn('probe: aeronmd version 1.53.0, the cut substrate is 1.53.1', report['findings'])

    def test_red_cpp_build_differs_from_the_source_sha(self):
        listing = listing_for(self.m)
        next(p for p in listing['processes'] if p['role'] == 'bridge0')['build'] = 'e' * 40
        self.assertIn('bridge0: /health.build eeeeeeeeeeee', ' '.join(self.audit(listing)['findings']))

    def test_guarded_rows_name_the_foreign_member(self):
        tag = 't' * 64
        for row, role, path in (('02', 'me1', '/artifacts/me.jar'), ('11', 'ae2', '/artifacts/ae.jar'),
                                ('26', 'projector', '/artifacts/projector.jar'), ('41', 'ae0', '/artifacts/ae.jar'),
                                ('52', 'me2', '/artifacts/me.jar')):
            with self.subTest(row=row):
                report = self.audit(listing_for(self.m, [(role, path, tag)]))
                self.assertEqual(report['status'], 'REFUSED')
                text = ' '.join(report['findings'])
                self.assertIn(f'{role}: {path} sha256 tttttttttttt', text)
                if role[:2] in ('me', 'ae'):
                    self.assertIn(f'{role} differs from its peers', text)
        for row, name in (('22', 'assets-bridge'), ('24', 'oms-app')):
            with self.subTest(row=row):
                report = self.audit(listing_for(self.m, extra=[{'role': name, 'running': True, 'files': {}}]))
                self.assertIn(f'{name}: a process that is not on the manifest (retired artifact)', report['findings'])

    def test_started_only_names_the_roles_an_x_run_never_started(self):
        listing = listing_for(self.m)
        listing['processes'] = [p for p in listing['processes'] if p['role'][:2] in ('me', 'pr')]
        self.assertEqual(self.audit(listing)['status'], 'REFUSED')
        report = self.audit(listing, started_only=True)
        self.assertEqual(report['status'], 'OK', report['findings'])
        self.assertIn('ae0', report['not_started'])
        row = next(p for p in listing['processes'] if p['role'] == 'me1')
        row.update(running=False, files={'/artifacts/me.jar': 't' * 64}, exit_code=1)
        report = self.audit(listing, registry={'fault_targets': {'me1': {'reason': 'exited 1'}}}, started_only=True)
        self.assertIn('me1: /artifacts/me.jar sha256 tttttttttttt is not the manifest\'s', ' '.join(report['findings']))

    def test_a_stopped_member_is_named_and_counted(self):
        report = self.audit(listing_for(self.m, drop=('me0',)), registry={'fault_targets': {'me0': {'row_id': 1}}})
        self.assertEqual(report['status'], 'OK', report['findings'])
        self.assertEqual(report['members_up'], {'me': 2, 'ae': 3})
        self.assertEqual([(s['role'], s['registered_fault_target']) for s in report['stopped']], [('me0', True)])
        report = self.audit(listing_for(self.m, drop=('me0',)))
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIn('me0: stopped and not a registered fault target', report['findings'])


class PrecheckTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name) / 'fx'
        for m in ('me0', 'me1', 'me2', 'ae0', 'ae1', 'ae2'):
            (self.root / 'state' / m).mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_empty_roots_pass_and_list_what_the_forward_order_wipes(self):
        report = release_cut.precheck([self.root], pg_rows={})
        self.assertEqual(report['status'], 'CLEAN', report['refusals'])
        labels = {w['label'] for w in report['wipe_list']}
        self.assertEqual(labels, {'ME state', 'ME journal archive', 'AE state', 'AE archive (money journal)',
                                  'projection database rows'})

    def test_red_a_non_empty_me_journal_archive(self):
        p = self.root / 'state/me1/journal/node0/archive'; p.mkdir(parents=True); (p / '0-0.rec').write_bytes(b'x' * 10)
        report = release_cut.precheck([self.root], pg_rows={})
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIn(f'ME journal archive not empty: {self.root}/state/me1/journal (1 file(s), 10 byte(s))', report['refusals'])

    def test_red_a_row_in_the_projection_database(self):
        report = release_cut.precheck([self.root], pg_rows={'money_journal_events': 1, 'empty': 0})
        self.assertIn('projection database holds 1 row(s) in money_journal_events', report['refusals'])
        self.assertEqual(release_cut.precheck([self.root])['status'], 'REFUSED')      # the database is never assumed empty

    def test_red_a_root_with_an_older_bare_snapshot(self):
        c = self.root / 'state/me0/state/cluster'; c.mkdir(parents=True)
        (c / 'recording.log').write_bytes(log_entry(0, 0, -1, 0) + log_entry(1, 0, 96, 1, 0))
        report = release_cut.precheck([self.root], pg_rows={})
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIn(f'{self.root}/state/me0: recording.log lists 1 snapshot(s); an older bare snapshot (row 51) is '
                      'unsupported: archive it and wipe', report['refusals'])

    def test_a_fresh_root_is_clean_and_a_missing_one_refused(self):
        fresh = Path(self.temp.name) / 'fresh'; fresh.mkdir()
        self.assertEqual(release_cut.precheck([fresh], pg_rows={})['status'], 'CLEAN')
        self.assertIn(f'{fresh}x: state root not found', release_cut.precheck([Path(str(fresh) + 'x')], pg_rows={})['refusals'])

    def test_red_a_non_empty_host_aeronmd_dir(self):
        d = Path(self.temp.name) / 'aeron'; d.mkdir(); (d / 'cnc.dat').write_bytes(b'c')
        report = release_cut.precheck([self.root], pg_rows={}, aeron_dirs=[d])
        self.assertIn(f'host aeronmd dir not empty: {d}', report['refusals'])


ME_JOURNAL = Path(__file__).resolve().parent / 'schemas' / 'me-journal-schema-4.xml'


def record5(gid, behavior=2, source='me0', capacity=100000, wire=12):
    block = struct.pack('<qqqIIIHB', 1, gid, 1472, 1, behavior, capacity, wire, 0)
    frame = struct.pack('<HHHH', len(block), 5, 4, 1) + block
    return '\n'.join([json.dumps({'kind': 'recording', 'source': source, 'recording': 0, 'start': 0, 'stop': 96, 'active': True}),
                      json.dumps({'kind': 'frame', 'source': source, 'recording': 0, 'position': 96, 'fragmented': False,
                                  'hex': frame.hex()}),
                      json.dumps({'kind': 'end', 'source': source, 'recordings': 1, 'frames': 1})]) + '\n'


class RunDir:
    """A minimal genesis run dir with the layout of a real core run (result.json -> state_root, owner.json, commands.jsonl
    and its logs, core-requests.jsonl, the tap rows, the AE archive recordings) plus the audit report."""

    def __init__(self, root, gid=GID):
        self.base = Path(root); self.run = self.base / 'run'; self.state = self.base / 'fx'
        self.run.mkdir(parents=True); (self.state / 'logs').mkdir(parents=True); (self.state / 'state/probe').mkdir(parents=True)
        jar = self.base / 'ae.jar'
        jar.write_bytes(jar_bytes({'sbe/money-schema.xml': MONEY_SCHEMA}))
        self.manifest = {'schema_version': 2, 'run_id': 'rc2-000000000001', 'manifest_kind': 's17-ext', 'seed': GID - 1,
                         'artifacts': {'ae': {'path': str(jar), 'sha256': h(jar.read_bytes())}}, 'cut_id': None}
        (self.run / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.run / 'result.json').write_text(json.dumps({'status': 'PASS', 'state_root': str(self.state)}))
        t0 = 1_793_726_196_000_000_000
        phases = {'genesis_snapshot_ns': t0 + 1, 'tap_started_ns': t0 + 2, 'me_genesis_ns': t0 + 3, 'bridges_ready_ns': t0 + 4,
                  'core_bound_ns': t0 + 5, 'first_deposit_ns': t0 + 6, 'funded_ns': t0 + 7, 'forwarders_ready_ns': t0 + 9 * 10**9}
        self.owner = {'run_id': 'rc2-000000000001', 'boot': {'phases': phases},
                      'lives': {'1': {'me': {'genesis_id': hex(gid)}, 'core': {'genesis_id': hex(gid)}}},
                      'genesis': {'genesis_id': hex(gid), 'ledger_capacity': 100000, 'life': 1},
                      'tap': {'path': str(self.state / 'state/probe/tap-life1.jsonl')}, 'fault_targets': {}}
        self.owner['genesis']['derivation'] = {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': 'rc2-000000000001'}
        self.commands = []
        self.command(['T1CoreDriver', 'genesis', '/dev/shm/probe-aeron', 'x', hex(gid)], 0,
                     'CoreConfig 1 result 0\nCoreConfig 2 result 0\nCoreConfig 3 result 0\nGLOBAL OPEN (bound through the bridge)\n')
        for m in ('me0', 'me1', 'me2'):
            self.command(['JournalProbe', 'dump', f'source={m}'], 0, record5(gid, source=m))
        self.requests = [{'verb': 'money-dump', 'reply': {'meEpoch': 0, 'lastAppliedJournalSeq': 0}, 'at_ns': t0},
                         {'verb': 'money-dump', 'reply': {'meEpoch': gid, 'lastAppliedJournalSeq': 1, 'journalEnabled': True},
                          'at_ns': t0 + 8}]
        self.tap = [{'tap': 'admission', 'row': {'market': 0, 'state': 'SUSPENDED', 'reason': 'GENESIS', 'log_position': 6304,
                                                 'at_ms': t0 // 10**6 + 1000}},
                    {'tap': 'admission', 'row': {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN', 'log_position': 90912,
                                                 'at_ms': t0 // 10**6 + 5000}}]
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.state, m, [core_config_payload(v, gid) for v in (1, 2, 3)])
        self.audit = {'status': 'OK', 'findings': [], 'members_up': {'me': 3, 'ae': 3}, 'stopped': []}
        self.write()

    def command(self, argv, code, output):
        n = len(self.commands)
        log = self.state / 'logs' / f'command-{n:05d}.log'
        log.write_text(output)
        self.commands.append({'argv': ['docker', 'exec', '-i', 'cid', 'java', '-cp', 'x', *argv], 'exit_code': code,
                              'output': str(log), 'accepted_exit_codes': [0]})

    def write(self):
        (self.state / 'owner.json').write_text(json.dumps(self.owner))
        (self.state / 'commands.jsonl').write_text(''.join(json.dumps(c) + '\n' for c in self.commands))
        (self.state / 'core-requests.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in self.requests))
        (self.state / 'state/probe/tap-life1.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in self.tap))
        (self.run / 'audit.json').write_text(json.dumps(self.audit))


class ActivationRecordTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.d = RunDir(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def record(self):
        return release_cut.activation_record(self.d.run, journal_schema=ME_JOURNAL)

    def refused(self, text, status='REFUSED'):
        rec = self.record()
        self.assertEqual(rec['status'], status, rec['refusals'])
        self.assertTrue(any(text in r for r in rec['refusals']), rec['refusals'])
        return rec

    def test_the_unedited_run_dir_reads_ok_from_three_sources(self):
        rec = self.record()
        self.assertEqual(rec['status'], 'OK', rec['refusals'])
        self.assertEqual(rec['me']['genesisId'], GID)
        self.assertEqual(rec['core']['genesisId'], GID)
        self.assertEqual(rec['core']['bound_epoch'], GID)
        self.assertEqual(len({rec['sources'][k] for k in ('me_genesis_id', 'core_genesis_id', 'core_bound_epoch')}), 3)
        self.assertEqual(rec['me']['record5'], {'journal_seq': 1, 'behavior_version': 2, 'ledger_capacity': 100000,
                                                'max_wire_version': 12, 'decision': 'FRESH'})
        self.assertEqual(rec['core']['config_sequence'], [[1, 'ACCEPTED'], [2, 'ACCEPTED'], [3, 'ACCEPTED']])
        self.assertEqual(rec['gate'], [['SUSPENDED', 'GENESIS', 6304], ['OPEN', 'ADMIN', 90912]])
        self.assertEqual(rec['members_up'], {'me': 3, 'ae': 3})
        with contextlib.redirect_stdout(io.StringIO()):
            out = release_cut.main(['activation-record', str(self.d.run), '--journal-schema', str(ME_JOURNAL)])
        self.assertEqual(out, 0)
        self.assertEqual(json.loads((self.d.run / 'rc2-activation-record.json').read_text())['status'], 'OK')

    def test_red_1_me_and_core_genesis_ids_differ(self):
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.d.state, m, [core_config_payload(v, GID + 2) for v in (1, 2, 3)])
        self.refused(f'core genesisId {GID + 2} != ME genesisId {GID}')

    def test_red_2_record_5_at_behaviour_1(self):
        self.d.commands[1]['output'] and Path(self.d.commands[1]['output']).write_text(record5(GID, behavior=1))
        self.refused('ME record 5 on me0: behaviorVersion 1, the activation needs 2')

    def test_red_3_coreconfig_3_missing(self):
        Path(self.d.commands[0]['output']).write_text('CoreConfig 1 result 0\nCoreConfig 2 result 0\n')
        self.d.commands[0]['exit_code'] = 1; self.d.write()
        self.refused('CoreConfig 3 not accepted', status='ABORTED')

    def test_red_4_gate_never_open_admin(self):
        self.d.tap = self.d.tap[:1]; self.d.write()
        self.refused('the gate never reached [OPEN, ADMIN]', status='INCOMPLETE')

    def test_red_5_a_forwarder_ready_before_the_gate_opened(self):
        self.d.owner['boot']['phases']['forwarders_ready_ns'] = self.d.tap[1]['row']['at_ms'] * 10**6 - 10**9
        self.d.write()
        self.refused('forwarders ready before the gate opened')

    def test_red_6_run_evidence_missing(self):
        (self.d.state / 'core-requests.jsonl').unlink()
        self.refused('run evidence missing: ' + str(self.d.state / 'core-requests.jsonl'))

    def test_red_7_bound_epoch_differs_from_record_5(self):
        self.d.requests[1]['reply']['meEpoch'] = GID + 2; self.d.write()
        self.refused(f'core bound epoch {GID + 2} != ME record 5 meEpoch {GID}')

    def test_red_8_members_up_below_three_without_an_audit_line(self):
        self.d.audit['members_up'] = {'me': 2, 'ae': 3}; self.d.write()
        self.refused('members_up me 2/3 but the audit names no stopped me member')
        self.d.audit['stopped'] = [{'role': 'me0', 'registered_fault_target': True}]; self.d.write()
        rec = self.record()
        self.assertEqual(rec['status'], 'OK', rec['refusals'])          # the X-A1 shape
        self.assertEqual(rec['members_up'], {'me': 2, 'ae': 3})

    def test_red_9_core_genesis_id_from_the_same_source_as_the_me(self):
        rec = self.record()
        rec['sources']['core_genesis_id'] = rec['sources']['me_genesis_id']
        self.assertIn('core genesisId and ME genesisId read from one source (' + rec['sources']['me_genesis_id'] + ')',
                      release_cut.check_record(rec))

    def test_no_core_frame_reads_not_observable_and_never_ok(self):
        for m in ('ae0', 'ae1', 'ae2'):
            write_ae_member(self.d.state, m, [b'\0' * 40])
        rec = self.record()
        self.assertEqual(rec['core']['genesisId'], 'not observable')
        self.assertNotEqual(rec['status'], 'OK')

    def test_the_record_carries_the_derived_id_and_refuses_another(self):
        import core_contracts
        rid = self.d.manifest['run_id']
        gid = int(core_contracts.derive_genesis_id(rid), 16)
        d = RunDir(Path(self.temp.name) / 'derived', gid=gid)
        d.owner['genesis']['derivation'] = {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': rid}; d.write()
        rec = release_cut.activation_record(d.run, journal_schema=ME_JOURNAL)
        self.assertEqual(rec['status'], 'OK', rec['refusals'])
        self.assertEqual(rec['genesis_id_derivation'], {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': rid,
                                                        'derived': gid, 'equal': True})
        d.owner['genesis']['derivation']['run_id'] = 'rc2-ffffffffffff'; d.write()
        rec = release_cut.activation_record(d.run, journal_schema=ME_JOURNAL)
        self.assertIn(f'the run_id rc2-ffffffffffff is not the run\'s {rid}', ' '.join(rec['refusals']))
        d.owner['genesis']['derivation']['run_id'] = rid; d.write()
        (d.run / 'manifest.json').write_text(json.dumps(dict(d.manifest, run_id='rc2-000000000002')))
        rec = release_cut.activation_record(d.run, journal_schema=ME_JOURNAL)
        self.assertEqual(rec['status'], 'REFUSED')

    def two_lives(self, d, gid2=None, capture=True, boundary=True):
        """The A04 regenesis shape on a RunDir: life 1 as built, then regenesis('me') (boundary, ME wiped, a life-2 record 5),
        regenesis('core') (boundary, the life-1 core reader captured before the AE wipe, life-2 CoreConfig frames, life-2
        genesis tool, money-dump, tap, phases, audit-life2.json)."""
        rid = d.manifest['run_id']
        gid1 = int(core_contracts.derive_genesis_id(rid, 1), 16)
        gid2 = int(core_contracts.derive_genesis_id(rid, 2), 16) if gid2 is None else gid2
        t0 = 1_793_726_196_000_000_000 + 600 * 10**9
        lives = d.owner['lives']
        lives['2'] = {'me': {'genesis_id': hex(gid2)}}
        if boundary:
            lives['2']['evidence_from'] = {'me': {'commands': len(d.commands), 'core_requests': len(d.requests)}}
        for m in ('me0', 'me1', 'me2'):
            d.command(['JournalProbe', 'dump', f'source={m}'], 0, record5(gid2, source=m))
        d.requests.append({'verb': 'money-dump', 'reply': {'meEpoch': gid1, 'lastAppliedJournalSeq': 40}, 'at_ns': t0})
        if boundary:
            lives['2']['evidence_from']['core'] = {'commands': len(d.commands), 'core_requests': len(d.requests)}
        lives['1']['records'] = {'genesis': copy.deepcopy(d.owner['genesis']), 'tap': copy.deepcopy(d.owner['tap'])}
        lives['1']['tap'] = copy.deepcopy(d.owner['tap'])
        if capture:
            reader = release_cut.genesis_reader(d.state, release_cut.load_money_schema(d.manifest['artifacts']['ae']['path']))
            path = d.state / 'core-genesis-life1.json'; path.write_text(json.dumps(reader))
            lives['1']['core_genesis_reader'] = {'path': str(path), 'sha256': h(path.read_bytes())}
        for m in ('ae0', 'ae1', 'ae2'):                    # the AE wipe: life 2's frames only
            write_ae_member(d.state, m, [core_config_payload(v, gid2) for v in (1, 2, 3)])
        lives['2']['core'] = {'genesis_id': hex(gid2)}
        d.command(['T1CoreDriver', 'genesis', '/dev/shm/probe-aeron', 'x', hex(gid2)], 0,
                  'CoreConfig 1 result 0\nCoreConfig 2 result 0\nCoreConfig 3 result 0\nGLOBAL OPEN (bound through the bridge)\n')
        d.requests.append({'verb': 'money-dump', 'reply': {'meEpoch': gid2, 'lastAppliedJournalSeq': 1}, 'at_ns': t0 + 8})
        tap2 = d.state / 'state/probe/tap-life2.jsonl'
        tap2.write_text(''.join(json.dumps({'tap': 'admission', 'row': {'market': 0, 'state': s, 'reason': r, 'log_position': p,
                                                                     'at_ms': t0 // 10**6 + k * 1000}}) + '\n'
                                for k, (s, r, p) in enumerate((('SUSPENDED', 'GENESIS', 6304), ('OPEN', 'ADMIN', 9000)), 1)))
        lives['2']['tap'] = {'path': str(tap2)}
        d.owner['tap'] = {'path': str(tap2)}
        d.owner['boot']['lives'] = {'2': {'phases': {'genesis_snapshot_ns': t0 + 1, 'tap_started_ns': t0 + 2,
                                                     'bridges_ready_ns': t0 + 4, 'core_bound_ns': t0 + 5,
                                                     'first_deposit_ns': t0 + 6, 'funded_ns': t0 + 7,
                                                     'forwarders_ready_ns': t0 + 9 * 10**9}}}
        d.owner['genesis'] = {'genesis_id': hex(gid2), 'ledger_capacity': 100000, 'life': 2,
                              'derivation': {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': rid}}
        d.write()
        (d.run / 'audit-life2.json').write_text(json.dumps(d.audit))
        return gid1, gid2

    def test_a_regenesis_run_gets_one_final_record_per_life(self):
        """RED 5d0339f: entry 10 (s17-ext a04-regenesis) wrote ONE record, life 1, REFUSED 3/3:
        'genesisId derivation missing' (owner.genesis was life 2's, written without the derivation) and 'core genesisId
        ...141 != ME genesisId ...139' (the core id read from the life-2 AE, the ME id from the first, life-1, dump). A04 has
        two lives with two ids by design: one final record per life, each from that life's evidence."""
        rid = 'rc2-000000000001'
        d = RunDir(Path(self.temp.name) / 'regen', gid=int(core_contracts.derive_genesis_id(rid, 1), 16))
        gid1, gid2 = self.two_lives(d)
        life1 = release_cut.activation_record(d.run, journal_schema=ME_JOURNAL)        # the nightly call: life 1, from the run dir
        self.assertEqual(life1['status'], 'OK', life1['refusals'])
        self.assertEqual(life1['core']['genesisId'], gid1)
        recs = release_cut.write_activation_records(d.run, journal_schema=ME_JOURNAL)
        self.assertEqual([(r['life'], p.name) for r, p in recs],
                         [(1, 'rc2-activation-record.json'), (2, 'rc2-activation-record-life2.json')])
        for rec, _ in recs:
            with self.subTest(life=rec['life']):
                self.assertEqual(rec['status'], 'OK', rec['refusals'])
        (r1, _), (r2, _) = recs
        self.assertEqual((r1['me']['genesisId'], r1['core']['genesisId'], r1['core']['bound_epoch']), (gid1, gid1, gid1))
        self.assertEqual((r2['me']['genesisId'], r2['core']['genesisId'], r2['core']['bound_epoch']), (gid2, gid2, gid2))
        self.assertEqual(r2['core']['config_sequence'], [[1, 'ACCEPTED'], [2, 'ACCEPTED'], [3, 'ACCEPTED']])
        self.assertEqual(release_cut.check_record_set([r1, r2]), [])
        self.assertTrue((d.run / 'rc2-activation-record-life2.json').is_file())

    def test_a_regenesis_without_its_life_evidence_is_refused(self):
        rid = 'rc2-000000000001'
        g1 = int(core_contracts.derive_genesis_id(rid, 1), 16)
        cases = {'no boundary': dict(boundary=False), 'life 1 core id not captured before the wipe': dict(capture=False),
                 'life 2 reuses the life 1 id': dict(gid2=g1)}
        texts = {'no boundary': 'life 2 has no me evidence boundary', 'life 1 core id not captured before the wipe':
                 'core genesisId of life 1 was not captured before the AE wipe',
                 'life 2 reuses the life 1 id': 'ME genesisId'}
        for why, kw in cases.items():
            with self.subTest(why=why):
                d = RunDir(Path(self.temp.name) / why.replace(' ', '-'), gid=g1)
                self.two_lives(d, **kw)
                recs = [r for r, _ in release_cut.write_activation_records(d.run, journal_schema=ME_JOURNAL)]
                bad = [r for r in recs if r['status'] != 'OK']
                self.assertTrue(bad, [r['refusals'] for r in recs])
                self.assertTrue(any(texts[why] in t for r in bad for t in r['refusals']), [r['refusals'] for r in recs])
                if why == 'life 2 reuses the life 1 id':
                    self.assertIn('repeats across genesis runs', ' '.join(release_cut.check_record_set(recs)))

    def test_a_single_life_run_keeps_one_record(self):
        recs = release_cut.write_activation_records(self.d.run, journal_schema=ME_JOURNAL)
        self.assertEqual([(r['life'], r['status'], p.name) for r, p in recs], [(1, 'OK', 'rc2-activation-record.json')])

    def test_a_repeated_genesis_id_across_records_is_refused(self):
        rec = self.record()
        self.assertEqual(release_cut.check_record_set([rec]), [])
        self.assertIn(f'genesisId {GID} repeats across genesis runs', ' '.join(release_cut.check_record_set([rec, dict(rec)])))


if __name__ == '__main__':
    unittest.main()
