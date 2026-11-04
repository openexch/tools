#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 cut checker (contract 3.1, 3.3, 5.1, 8.1; critic X5, D-S17-4, D-S17-6). The R10-A03 "artifact bound to a single source
SHA" mechanism of the RC2 lane: a harness tool, not the R10 release gate.

usage: r10_cut.py check <manifest> [--cut <cut manifest>] [--class product|rig|rig-xver|nightly] [--old-pins <file>]
       r10_cut.py record-builds <out.json> <name>=<repo>:<source_sha>:<path>[,<path>...] ...

``check`` takes either the cut manifest itself (schema ``rc2-cut/1``) or a fixture manifest derived from it (schema_version 2,
``manifest_kind`` s17-*, checked against ``--cut``). It prints one line per refusal, ``K<n> <text>``, and exits 1 when any rule
refuses, 0 when none does. The rules (3.3):
  K1  an artifact without sha256, without a 40-hex source_sha, with tree_dirty true, or whose file re-hash differs
  K2  an embedded schema identity that differs from ``schemas`` (Java: the sha256 of the schema XML resources in the jar; C++: the
      schema sha256 strings compiled into the binary, the identity its start line prints, ct/app/bridge/main.cpp:143-144)
  K3  a test or negative build (ct_*_nc_*, ct_*_tc_*, *_b) in a product kind
  K4  a source_sha that is not its repo's single entry, or that is not DERIVED as its derivation says (rebuild-equal: two builds
      of that source in the build record are byte-equal and equal the artifact; binary-build-info: the build record holds the
      artifact and the binary carries the source sha (or, for the Aeron driver files, the substrate Aeron version); attested is
      refused in a product kind); the upgrade_from / old_artifacts exemption only in rig kinds and only when pinned in
      R10/old-artifacts.sha256
  K5  a retired artifact (assets-bridge, oms-app, match-gateway) in a core-topology manifest
  K6  a genesis block with ME behaviour != 2, maxWireVersion != 12, a core sequence other than 1 -> 2 -> 3, two genesisId values,
      or a constant genesisId in a product kind
  K7  a driver profile value other than external or embedded, or a prod profile with an embedded process
  K8  a substrate block whose Aeron versions differ
  K9  an unknown key, a missing required key, a short sha (a per-member artifact key is unknown by design)
  K10 two engine jars built against different cluster-kit pins, or a pin other than the substrate's

``rules`` is the test seam of 5.1 (C6): a RED manifest is refused with the rule's text, and passes with that rule switched off.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

SCHEMA = 'rc2-cut/1'
RULES = tuple(f'K{n}' for n in range(1, 11))
CLASSES = ('product', 'rig', 'rig-xver', 'nightly')
RIG_CLASSES = ('rig', 'rig-xver', 'nightly')
REPOS = ('assets', 'match', 'cluster-kit', 'cluster-tools', 'tools')
SCHEMA_NAMES = ('money', 'order', 'me_journal')
# The one heavy-job lock of S17 (0.2, 20.1 line 1): set here and in S17/evidence/dry-run/env.sh, recorded in every summary.json.
HEAVY_LOCK = '/tmp/claude-1000/-home-emre-Apps-openexchange/de45670d-240c-4516-be8a-a5827d03f716/scratchpad/heavy.lock'
B0 = Path('/home/emre/Apps/openexchange/.runtime-handoff/20260927-r00')
R10 = B0 / 'workspace/notebook/reports/runtime-handoff-execution/R10'
OLD_PINS = R10 / 'old-artifacts.sha256'

# Product artifacts of the cut (3.1): repo, language, derivations accepted in a product kind, embedded schema identities.
PRODUCT = {
    'match-cluster.jar': {'repo': 'match', 'lang': 'java', 'engine': True,
                          'schemas': {'order': 'sbe/order-schema.xml', 'me_journal': 'sbe/me-journal-schema.xml'}},
    'assets-cluster.jar': {'repo': 'assets', 'lang': 'java', 'engine': True, 'schemas': {'money': 'sbe/money-schema.xml'}},
    'assets-projector.jar': {'repo': 'assets', 'lang': 'java', 'engine': True, 'schemas': {'money': 'sbe/money-schema.xml'}},
    'ct-forwarder': {'repo': 'cluster-tools', 'lang': 'cpp', 'stamped': True, 'schemas': ('money', 'order')},
    'ct-bridge': {'repo': 'cluster-tools', 'lang': 'cpp', 'stamped': True, 'schemas': ('money', 'me_journal')},
    'aeronmd': {'repo': 'cluster-tools', 'lang': 'cpp', 'schemas': ()},
    'libaeron_driver.so': {'repo': 'cluster-tools', 'lang': 'cpp', 'schemas': ()},
    'libaeron.so': {'repo': 'cluster-tools', 'lang': 'cpp', 'schemas': ()},
}
RETIRED = {'assets-bridge', 'oms-app', 'match-gateway'}
RETIRED_FILE = re.compile(r'(assets-bridge|oms-app|match-gateway)[^/]*$')
TEST_BUILD = re.compile(r'(^|/)(ct_[a-z0-9]+_(nc|tc)_[a-z0-9_]+|[^/]*_b)$')
DERIVATIONS = {'rebuild-equal', 'binary-build-info', 'attested'}
KIT_POM = 'META-INF/maven/com.openexchange/cluster-kit/pom.properties'
HARNESS = {'core_probe', 'journal_probe', 't1_me_driver', 't1_core_driver', 'probe_aeronmd', 'probe_libaeron_driver.so',
           'probe_libaeron.so'}
PROCESSES = {'me', 'ae', 'projector', 'forwarder', 'bridge'}
SUBSTRATE_AERON = {'ae', 'me', 'projector', 'cpp', 'host_aeronmd'}

TOP_KEYS = {'schema', 'class', 'cut_id', 'created', 'harness_commit', 'repos', 'schemas', 'substrate', 'artifacts', 'harness',
            'genesis', 'driver_profiles', 'retired', 'excluded', 'build_record'}
TOP_OPTIONAL = {'upgrade_from', 'old_artifacts', 'note'}
ARTIFACT_KEYS = {'path', 'sha256', 'source_sha', 'derivation', 'tree_dirty', 'kind'}
OLD_KEYS = {'path', 'sha256', 'source_sha', 'derivation', 'tree_dirty', 'kind', 'role'}
HARNESS_KEYS = {'path', 'sha256', 'kind', 'driver_mode', 'source_path', 'source_sha256'}
SUBSTRATE_KEYS = {'aeron', 'kit_pin', 'kit_jar', 'sbe'}
KIT_JAR_KEYS = {'path', 'sha256', 'source_sha', 'derivation', 'tree_dirty'}
GENESIS_KEYS = {'me', 'core', 'order'}
ME_GENESIS_KEYS = {'configVersion', 'behaviorVersion', 'commandLedgerCapacity', 'maxWireVersion', 'genesisId'}
CORE_GENESIS_KEYS = {'configVersions', 'genesisId'}
PER_GENESIS = 'per-genesis'
PROFILE_NAMES = {'prod', 'dev'}
BUILD_RECORD_KEYS = {'path', 'sha256'}
HEX40 = re.compile(r'[0-9a-f]{40}')
HEX64 = re.compile(r'[0-9a-f]{64}')


class Findings:
    def __init__(self, rules):
        self.rules = set(rules)
        self.items = []

    def add(self, rule, text):
        if rule in self.rules and (rule, text) not in self.items:
            self.items.append((rule, text))

    def by_rule(self):
        return sorted({rule for rule, _ in self.items}, key=lambda r: int(r[1:]))


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_old_pins(path):
    """R10/old-artifacts.sha256: ``<sha256>  <name>  source_sha=<40 hex>  recipe=<path>  recipe_sha256=<64 hex>`` per line."""
    pins = {}
    path = Path(path)
    if not path.is_file():
        return pins
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split()
        fields = dict(p.split('=', 1) for p in parts[2:] if '=' in p)
        pins[parts[0]] = {'name': parts[1], **fields}
    return pins


def _unknown(f, what, entry, allowed, required=None):
    if not isinstance(entry, dict):
        f.add('K9', f'{what}: must be an object')
        return False
    extra = sorted(set(entry) - set(allowed))
    if extra:
        f.add('K9', f'{what}: unknown key(s) ' + ', '.join(extra))
    missing = sorted(set(required if required is not None else allowed) - set(entry))
    if missing:
        f.add('K9', f'{what}: missing key(s) ' + ', '.join(missing))
    return True


def _shas(f, what, entry):
    for key, value in entry.items():
        if key == 'sha256' or key.endswith('_sha256'):
            if not (isinstance(value, str) and HEX64.fullmatch(value)):
                f.add('K9', f'{what}.{key}: not a 64-hex sha256 ({value!r})')
        elif key in ('source_sha',) or key.endswith('_commit'):
            if not (isinstance(value, str) and HEX40.fullmatch(value)):
                f.add('K9', f'{what}.{key}: not a 40-hex commit ({value!r})')


def _rehash(f, what, entry, need_source=True):
    """K1: sha256 present, 40-hex source_sha, tree_dirty false, the file re-hash equal."""
    digest = entry.get('sha256')
    if not (isinstance(digest, str) and HEX64.fullmatch(digest)):
        f.add('K1', f'{what}: no sha256')
        return False
    if need_source and not (isinstance(entry.get('source_sha'), str) and HEX40.fullmatch(entry['source_sha'])):
        f.add('K1', f'{what}: no 40-hex source_sha')
    if 'tree_dirty' in entry and entry['tree_dirty'] is not False:
        f.add('K1', f'{what}: built from a dirty tree (tree_dirty {entry["tree_dirty"]!r})')
    path = Path(str(entry.get('path', '')))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        f.add('K1', f'{what}: file missing or not a plain absolute path: {path}')
        return False
    if sha256_file(path) != digest:
        f.add('K1', f'{what}: file re-hash differs from the manifest sha256 ({path})')
        return False
    return True


def _jar_member(path, member):
    try:
        with zipfile.ZipFile(path) as jar:
            return jar.read(member)
    except (KeyError, zipfile.BadZipFile, OSError):
        return None


def kit_pin_of(path):
    data = _jar_member(path, KIT_POM)
    if data is None:
        return None
    for line in data.decode('utf-8', 'replace').splitlines():
        if line.startswith('version='):
            return line.split('=', 1)[1].strip()
    return None


def _schemas_k2(f, name, entry, schemas, spec):
    path = Path(str(entry.get('path', '')))
    if not path.is_file():
        return
    if spec['lang'] == 'java':
        for schema, member in spec['schemas'].items():
            data = _jar_member(path, member)
            if data is None:
                f.add('K2', f'{name}: carries no {member} (schema {schema} identity unreadable)')
            elif hashlib.sha256(data).hexdigest() != schemas.get(schema):
                f.add('K2', f'{name}: {member} sha256 {hashlib.sha256(data).hexdigest()} != schemas.{schema} {schemas.get(schema)}')
    else:
        blob = path.read_bytes()
        for schema in spec['schemas']:
            want = schemas.get(schema) or ''
            if not want or want.encode() not in blob:
                f.add('K2', f'{name}: the build identity does not carry schemas.{schema} {want}')


def _derived_k4(f, name, entry, spec, repos, record, aeron_version, cls):
    source = entry.get('source_sha')
    want = repos.get(spec['repo'])
    if source != want:
        f.add('K4', f'{name}: source_sha {source} is not the single {spec["repo"]} entry {want}')
    derivation = entry.get('derivation')
    if derivation not in DERIVATIONS:
        f.add('K9', f'{name}: derivation must be one of ' + ', '.join(sorted(DERIVATIONS)) + f', got {derivation!r}')
        return
    builds = [b for b in record.get(name, []) if b.get('source_sha') == source]
    shas = [b.get('sha256') for b in builds]
    if derivation == 'attested':
        if cls == 'product':
            f.add('K4', f'{name}: derivation attested (a builder-set label only) is refused in a product kind')
        return
    if derivation == 'rebuild-equal':
        if spec['lang'] != 'java':
            f.add('K4', f'{name}: rebuild-equal is the Java jars\' derivation; a C++ binary is binary-build-info')
        if len(shas) < 2 or len(set(shas)) != 1:
            f.add('K4', f'{name}: no two byte-equal builds of {source} in the build record (rebuild-equal not shown)')
        elif shas[0] != entry.get('sha256'):
            f.add('K4', f'{name}: the rebuild of {source} is {shas[0]}, the artifact is {entry.get("sha256")} (not derived)')
        return
    if spec['lang'] == 'java':
        f.add('K4', f'{name}: binary-build-info is the C++ derivation; a jar is derived by rebuild-equal')
        return
    if entry.get('sha256') not in shas:
        f.add('K4', f'{name}: the build record holds no build of {source} with sha256 {entry.get("sha256")}')
    path = Path(str(entry.get('path', '')))
    if path.is_file():
        blob = path.read_bytes()
        token = (source if spec.get('stamped') else aeron_version) or ''
        if not token or token.encode() not in blob:
            what = 'source sha' if spec.get('stamped') else 'Aeron version'
            f.add('K4', f'{name}: the binary does not carry its {what} {token} (binary-build-info not shown)')


def load_record(f, ref):
    """The build record (``record-builds``): {name: [{source_sha, path, sha256}, ...]}, pinned by sha256 in the manifest; every
    listed build output is re-hashed (K1)."""
    if not isinstance(ref, dict) or not _rehash(f, 'build_record', ref, need_source=False):
        return {}
    try:
        record = json.loads(Path(ref['path']).read_text())
    except (OSError, ValueError):
        f.add('K1', 'build_record: unreadable')
        return {}
    for name, builds in record.items():
        for i, build in enumerate(builds):
            path = Path(str(build.get('path', '')))
            if not path.is_file() or sha256_file(path) != build.get('sha256'):
                f.add('K1', f'build_record {name}[{i}]: build output missing or re-hash differs ({path})')
    return record


def _old_entries(f, m, cls, old_pins):
    for block in ('upgrade_from', 'old_artifacts'):
        entries = m.get(block)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            f.add('K9', f'{block}: must be an object')
            continue
        if cls == 'product' and entries:
            f.add('K4', f'{block}: the K4 exemption is refused in a product kind')
        if block == 'old_artifacts' and cls not in ('rig-xver',) and entries:
            f.add('K4', 'old_artifacts: only the xver rig kinds may declare old artifacts')
        for name, entry in entries.items():
            what = f'{block}.{name}'
            if not _unknown(f, what, entry, OLD_KEYS, {'path', 'sha256', 'source_sha'}):
                continue
            _shas(f, what, entry)
            _rehash(f, what, entry)
            if block != 'old_artifacts' and (name in RETIRED or RETIRED_FILE.search(str(entry.get('path', ''))) or
                                             entry.get('role') in RETIRED):
                f.add('K5', f'{what}: retired artifact in a core-topology manifest')
            pin = old_pins.get(entry.get('sha256'))
            if pin is None or pin.get('source_sha') != entry.get('source_sha'):
                f.add('K4', f'{what}: not pinned in R10/old-artifacts.sha256 with source {entry.get("source_sha")}')
            if cls == 'product' and TEST_BUILD.search(name):
                f.add('K3', f'{what}: test or negative build in a product kind')


def check_cut(m, rules=RULES, cls=None, old_pins=None):
    """The checks of 3.3 over a cut manifest (``rc2-cut/1``). Returns the Findings (empty = accepted)."""
    f = Findings(rules)
    if not isinstance(m, dict):
        f.add('K9', 'manifest is not an object')
        return f
    if m.get('schema') != SCHEMA:
        f.add('K9', f'schema must be {SCHEMA}, got {m.get("schema")!r}')
    cls = cls or m.get('class')
    if cls not in CLASSES:
        f.add('K9', 'class must be one of ' + ', '.join(CLASSES) + f', got {cls!r}')
        cls = 'product'
    old_pins = load_old_pins(OLD_PINS) if old_pins is None else old_pins
    _unknown(f, 'manifest', m, TOP_KEYS | TOP_OPTIONAL, TOP_KEYS)
    if 'harness_commit' in m and not (isinstance(m['harness_commit'], str) and HEX40.fullmatch(m['harness_commit'])):
        f.add('K9', f'harness_commit: not a 40-hex commit ({m.get("harness_commit")!r})')
    repos = m.get('repos') if isinstance(m.get('repos'), dict) else {}
    _unknown(f, 'repos', repos, REPOS)
    for repo, value in repos.items():
        if not (isinstance(value, str) and HEX40.fullmatch(value)):
            f.add('K9', f'repos.{repo}: not a 40-hex commit ({value!r})')
    schemas = m.get('schemas') if isinstance(m.get('schemas'), dict) else {}
    _unknown(f, 'schemas', schemas, SCHEMA_NAMES)
    for name, value in schemas.items():
        if not (isinstance(value, str) and HEX64.fullmatch(value)):
            f.add('K9', f'schemas.{name}: not a 64-hex sha256 ({value!r})')

    substrate = m.get('substrate') if isinstance(m.get('substrate'), dict) else {}
    _unknown(f, 'substrate', substrate, SUBSTRATE_KEYS)
    aeron = substrate.get('aeron') if isinstance(substrate.get('aeron'), dict) else {}
    _unknown(f, 'substrate.aeron', aeron, SUBSTRATE_AERON)
    versions = sorted(set(map(str, aeron.values())))
    if len(versions) > 1:
        f.add('K8', 'substrate Aeron versions differ: ' + ', '.join(f'{k} {v}' for k, v in sorted(aeron.items())))
    aeron_version = str(aeron['cpp']) if aeron.get('cpp') else None      # the C++ driver files carry the C++ Aeron version
    record = load_record(f, m.get('build_record'))
    kit_pin = substrate.get('kit_pin')
    kit_jar = substrate.get('kit_jar')
    if isinstance(kit_jar, dict) and _unknown(f, 'substrate.kit_jar', kit_jar, KIT_JAR_KEYS):
        _shas(f, 'substrate.kit_jar', kit_jar)
        _rehash(f, 'substrate.kit_jar', kit_jar)
        _derived_k4(f, 'cluster-kit.jar', kit_jar, {'repo': 'cluster-kit', 'lang': 'java'}, repos, record, aeron_version, cls)

    artifacts = m.get('artifacts') if isinstance(m.get('artifacts'), dict) else {}
    pins = {}
    for name, entry in artifacts.items():
        what = 'artifacts.' + name
        if name in RETIRED or RETIRED_FILE.search(name) or (isinstance(entry, dict) and RETIRED_FILE.search(str(entry.get('path', '')))):
            f.add('K5', f'{what}: retired artifact in a core-topology manifest')
            if isinstance(entry, dict):
                _rehash(f, what, entry)
            continue
        if TEST_BUILD.search(name) or (isinstance(entry, dict) and TEST_BUILD.search(str(entry.get('path', '')))):
            if cls == 'product':
                f.add('K3', f'{what}: test or negative build in a product kind')
            else:
                f.add('K9', f'{what}: a test build is never a cut artifact (rig kinds stage it from their own build)')
            continue
        spec = PRODUCT.get(name)
        if spec is None:
            f.add('K9', f'{what}: unknown artifact key (one artifact per role; a per-member key is unknown by design)')
            base = PRODUCT.get(name.split('@', 1)[0])
            if base is not None and isinstance(entry, dict):      # rows 41, 52: the second jar's bytes are judged too (K4)
                _derived_k4(f, name, {**entry, 'derivation': entry.get('derivation', 'attested')}, base, repos, record,
                            aeron_version, 'product')
            continue
        if not _unknown(f, what, entry, ARTIFACT_KEYS):
            continue
        _shas(f, what, entry)
        if entry.get('kind') != 'product':
            f.add('K9', f'{what}: kind must be product, got {entry.get("kind")!r}')
        _rehash(f, what, entry)
        _schemas_k2(f, name, entry, schemas, spec)
        _derived_k4(f, name, entry, spec, repos, record, aeron_version, cls)
        if spec.get('engine') and Path(str(entry.get('path', ''))).is_file():
            pins[name] = kit_pin_of(entry['path'])
    missing = sorted(set(PRODUCT) - set(artifacts))
    if missing:
        f.add('K9', 'artifacts: missing ' + ', '.join(missing))
    distinct = sorted({str(v) for v in pins.values()})
    if len(distinct) > 1:
        f.add('K10', 'engine jars built against different cluster-kit pins: ' + ', '.join(f'{k} {v}' for k, v in sorted(pins.items())))
    for name, pin in sorted(pins.items()):
        if pin != kit_pin:
            f.add('K10', f'{name}: cluster-kit pin {pin} is not the substrate kit_pin {kit_pin}')

    harness = m.get('harness') if isinstance(m.get('harness'), dict) else {}
    for name, entry in harness.items():
        what = 'harness.' + name
        if name not in HARNESS:
            f.add('K9', f'{what}: unknown harness key')
            continue
        if not _unknown(f, what, entry, HARNESS_KEYS, {'path', 'sha256', 'kind', 'driver_mode'}):
            continue
        _shas(f, what, entry)
        if entry.get('kind') != 'harness':
            f.add('K9', f'{what}: kind must be harness (never product)')
        if entry.get('driver_mode') not in ('embedded', 'external'):
            f.add('K7', f'{what}: driver mode must be embedded or external, got {entry.get("driver_mode")!r}')
        _rehash(f, what, entry, need_source=False)
        if entry.get('source_path'):
            src = {'path': entry['source_path'], 'sha256': entry.get('source_sha256')}
            _rehash(f, what + ' source', src, need_source=False)

    genesis = m.get('genesis') if isinstance(m.get('genesis'), dict) else {}
    _unknown(f, 'genesis', genesis, GENESIS_KEYS)
    me = genesis.get('me') if isinstance(genesis.get('me'), dict) else {}
    core = genesis.get('core') if isinstance(genesis.get('core'), dict) else {}
    _unknown(f, 'genesis.me', me, ME_GENESIS_KEYS)
    _unknown(f, 'genesis.core', core, CORE_GENESIS_KEYS)
    if me.get('behaviorVersion') != 2:
        f.add('K6', f'genesis.me.behaviorVersion must be 2, got {me.get("behaviorVersion")!r}')
    if me.get('maxWireVersion') != 12:
        f.add('K6', f'genesis.me.maxWireVersion must be 12, got {me.get("maxWireVersion")!r}')
    if me.get('configVersion') != 1:
        f.add('K6', f'genesis.me.configVersion must be 1, got {me.get("configVersion")!r}')
    if core.get('configVersions') != [1, 2, 3]:
        f.add('K6', f'genesis.core.configVersions must be 1 -> 2 -> 3, got {core.get("configVersions")!r}')
    ids = {me.get('genesisId'), core.get('genesisId')}
    if len(ids) != 1:
        f.add('K6', 'genesis: two different genesisId values ' + ', '.join(map(repr, sorted(ids, key=repr))))
    if cls == 'product' and ids != {PER_GENESIS}:
        f.add('K6', f'genesis: a product kind fills genesisId per genesis ("{PER_GENESIS}"), never a constant')

    profiles = m.get('driver_profiles') if isinstance(m.get('driver_profiles'), dict) else {}
    _unknown(f, 'driver_profiles', profiles, PROFILE_NAMES)
    for profile, procs in profiles.items():
        if not isinstance(procs, dict):
            f.add('K9', f'driver_profiles.{profile}: must be an object')
            continue
        _unknown(f, f'driver_profiles.{profile}', procs, PROCESSES)
        for proc, mode in procs.items():
            if mode not in ('external', 'embedded'):
                f.add('K7', f'driver_profiles.{profile}.{proc}: {mode!r} is neither external nor embedded')
            elif profile == 'prod' and mode == 'embedded':
                f.add('K7', f'driver_profiles.prod.{proc}: embedded in the prod profile (production is external aeronmd)')
    retired = m.get('retired')
    if not isinstance(retired, list) or not RETIRED <= set(retired):
        f.add('K9', 'retired: must list ' + ', '.join(sorted(RETIRED)))
    _old_entries(f, m, cls, old_pins)
    for member, block in (m.get('members') or {}).items() if isinstance(m.get('members'), dict) else ():
        entry = block.get('artifact') if isinstance(block, dict) else None
        base = PRODUCT.get({'me': 'match-cluster.jar', 'ae': 'assets-cluster.jar'}.get(str(member)[:2], ''))
        if base is not None and isinstance(entry, dict):          # row 41: a per-member jar is unknown (K9) and not derived (K4)
            _derived_k4(f, f'members.{member}.artifact', {**entry, 'derivation': entry.get('derivation', 'attested')}, base,
                        repos, record, aeron_version, 'product')
    return f


# ------------------------------------------------------------------ fixture manifests derived from the cut (5.3)

FIXTURE_NAMES = {'me': 'match-cluster.jar', 'ae': 'assets-cluster.jar', 'projector': 'assets-projector.jar',
                 'forwarder': 'ct-forwarder', 'bridge': 'ct-bridge', 'forwarder_b': 'ct-forwarder', 'bridge_b': 'ct-bridge'}


def _cut_index(cut):
    index = {}
    for name, entry in (cut.get('artifacts') or {}).items():
        index[entry['sha256']] = ('artifacts', name, entry.get('source_sha'))
    for name, entry in (cut.get('harness') or {}).items():
        index.setdefault(entry['sha256'], ('harness', name, None))
    for block in ('upgrade_from', 'old_artifacts'):
        for name, entry in (cut.get(block) or {}).items():
            index.setdefault(entry['sha256'], (block, name, entry.get('source_sha')))
    return index


def check_fixture(m, cut, cls, rules=RULES, old_pins=None):
    """5.3: a fixture manifest derived from the cut stages only the cut's bytes. Every staged file is found in the cut by sha256:
    a product artifact (its role and source must agree), a harness program, or, in a rig kind only, a pinned upgrade_from /
    old_artifacts entry; a ``*_b`` or negative target is refused in a product kind (K3)."""
    f = Findings(rules)
    old_pins = load_old_pins(OLD_PINS) if old_pins is None else old_pins
    cut_findings = check_cut(cut, rules, cls=cut.get('class'), old_pins=old_pins)
    for rule, text in cut_findings.items:
        f.add(rule, 'cut: ' + text)
    index = _cut_index(cut)

    def staged(what, entry, name=None):
        if not isinstance(entry, dict):
            return
        if not _rehash(f, what, entry, need_source=False):
            return
        hit = index.get(entry['sha256'])
        if hit is None:
            pin = old_pins.get(entry['sha256'])
            if pin is None:
                f.add('K4', f'{what}: sha256 {entry["sha256"]} is not an artifact of cut {cut.get("cut_id")} and not pinned in '
                            'R10/old-artifacts.sha256')
            elif cls == 'product':
                f.add('K4', f'{what}: an old artifact ({pin["name"]}, the K4 exemption) is refused in a product kind')
            elif 'source_sha' in entry and entry['source_sha'] != pin.get('source_sha'):
                f.add('K4', f'{what}: source_sha {entry["source_sha"]} is not the pinned {pin.get("source_sha")}')
            elif RETIRED_FILE.search(pin.get('name', '')):
                f.add('K5', f'{what}: retired artifact {pin["name"]} in a core-topology manifest')
            return
        block, cut_name, source = hit
        if block in ('upgrade_from', 'old_artifacts'):
            if cls == 'product':
                f.add('K4', f'{what}: {block}.{cut_name} (the K4 exemption) is refused in a product kind')
            if block == 'old_artifacts' and cls != 'rig-xver':
                f.add('K4', f'{what}: old_artifacts only in the xver rig kinds')
            pin = old_pins.get(entry['sha256'])
            if pin is None:
                f.add('K4', f'{what}: {block}.{cut_name} not pinned in R10/old-artifacts.sha256')
            return
        if name is not None and block == 'artifacts' and cut_name != name:
            f.add('K4', f'{what}: carries the bytes of {cut_name}, not of {name}')
        if 'source_sha' in entry and source is not None and entry['source_sha'] != source:
            f.add('K4', f'{what}: source_sha {entry["source_sha"]} != the cut\'s {source} for {cut_name}')

    artifacts = m.get('artifacts') or {}
    for key, entry in artifacts.items():
        if entry is None:
            continue
        what = 'artifacts.' + key
        if key.endswith('_b') and cls == 'product':
            f.add('K3', f'{what}: a second build ({key}) in a product kind')
        target = entry.get('target') if isinstance(entry, dict) else None
        if target and TEST_BUILD.search(target):
            if cls == 'product':
                f.add('K3', f'{what}: negative target {target} in a product kind')
            # rig kinds: a negative target is a RED control built from the cut's cluster-tools sha (binary-build-info)
            if isinstance(entry, dict) and _rehash(f, what, entry):
                want = (cut.get('repos') or {}).get('cluster-tools')
                if entry.get('source_sha') != want or want.encode() not in Path(entry['path']).read_bytes():
                    f.add('K4', f'{what}: negative target {target} is not a build of the cut\'s cluster-tools {want}')
            continue
        staged(what, entry, FIXTURE_NAMES.get(key))
        for lib, lentry in ((entry or {}).get('libs') or {}).items():
            staged(f'{what}.libs.{lib}', lentry, lib)
    for block in ('engine_libs', 'projector_libs', 'probe_libs'):
        for lib, lentry in (m.get(block) or {}).items():
            if lib in PRODUCT:
                staged(f'{block}.{lib}', lentry, lib)
    for key in ('core_probe', 'journal_probe', 't1_me_driver', 't1_core_driver'):
        if key in m:
            staged(key, {'path': m[key]['path'], 'sha256': m[key]['sha256']})
    if m.get('manifest_kind') and not str(m['manifest_kind']).startswith('s17'):
        f.add('K9', f'manifest_kind {m["manifest_kind"]} is not derived from an S17 cut')
    if cls == 'product':
        for key in ('engine_driver', 'projector_driver'):
            if m.get(key, 'embedded') == 'embedded' and m.get('topology') == 'core':
                f.add('K7', f'{key}: embedded in a product kind (production is external aeronmd)')
    return f


def check(manifest, cut=None, cls=None, rules=RULES, old_pins=None):
    if isinstance(manifest, dict) and manifest.get('schema') == SCHEMA:
        return check_cut(manifest, rules, cls, old_pins)
    if cut is None:
        f = Findings(rules)
        f.add('K9', 'a fixture manifest is checked against its cut: --cut <rc2-cut-manifest.json>')
        return f
    return check_fixture(manifest, cut, cls or 'rig', rules, old_pins)


def record_builds(out, specs):
    """``<name>=<repo>:<source_sha>:<path>[,<path>...]``: the build outputs of the cut recipe with their sha256 (the K4 record)."""
    record = {}
    for spec in specs:
        name, _, rest = spec.partition('=')
        repo, source, paths = rest.split(':', 2)
        if not HEX40.fullmatch(source):
            raise SystemExit(f'{name}: source sha must be 40 hex')
        for path in paths.split(','):
            p = Path(path).absolute()
            record.setdefault(name, []).append({'repo': repo, 'source_sha': source, 'path': str(p), 'sha256': sha256_file(p)})
    Path(out).write_text(json.dumps(record, indent=1, sort_keys=True) + '\n')
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    c = sub.add_parser('check')
    c.add_argument('manifest', type=Path)
    c.add_argument('--cut', type=Path)
    c.add_argument('--class', dest='cls', choices=CLASSES)
    c.add_argument('--old-pins', type=Path)
    r = sub.add_parser('record-builds')
    r.add_argument('out', type=Path)
    r.add_argument('spec', nargs='+')
    args = parser.parse_args(argv)
    if args.cmd == 'record-builds':
        record_builds(args.out, args.spec)
        print(args.out)
        return 0
    manifest = json.loads(args.manifest.read_text())
    cut = json.loads(args.cut.read_text()) if args.cut else None
    pins = load_old_pins(args.old_pins) if args.old_pins else None
    findings = check(manifest, cut, args.cls, old_pins=pins)
    for rule, text in findings.items:
        print(f'{rule} {text}')
    if findings.items:
        print(f'REFUSED {args.manifest.name}: ' + ', '.join(findings.by_rule()))
        return 1
    print(f'ACCEPTED {args.manifest.name}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
