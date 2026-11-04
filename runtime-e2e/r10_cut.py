#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 cut checker (contract 3.1, 3.3, 5.1, 8.1; critic X5, D-S17-4, D-S17-6). The R10-A03 "artifact bound to a single source
SHA" mechanism of the RC2 lane: a harness tool, not the R10 release gate.

usage: r10_cut.py check <manifest> [--cut <cut manifest>] [--class product|rig|rig-xver|nightly] [--old-pins <file>]
       r10_cut.py record-builds <out.json> <name>=<repo>:<source_sha>:<path>[,<path>...] ...
       r10_cut.py audit <state root | listing.json> --manifest <m> [--cut <cut>] [--swap SLOT=A,B]     (3.5, RC2 S17 W3)
       r10_cut.py precheck <state root>... [--pg-rows <rows.json>] [--aeron-dir <dir>]                (3.5, runbook step 1)
       r10_cut.py activation-record <run dir> [--audit <audit.json>]                                   (section 10)
       r10_cut.py genesis-ids <state root> --schema <money-schema.xml | AE jar>                        (5.2 (v))

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
import os
from pathlib import Path
import subprocess
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
        self.waived = []          # RC2 S17 review V2: harness drift findings a rig manifest waived with a named reason

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
        else:
            # RC2 S17 review V3: two BUILDS, not one file listed twice: distinct real paths in distinct build roots, neither of
            # them the artifact itself
            art = os.path.realpath(str(entry.get('path', '')))
            paths = {os.path.realpath(str(b.get('path', ''))) for b in builds}
            roots = {os.path.dirname(p) for p in paths}
            if len(paths) < 2 or len(roots) < 2 or art in paths:
                f.add('K4', f'{name}: rebuild-equal needs two distinct builds (distinct paths in distinct build roots, neither the '
                            f'artifact): {sorted(paths)}')
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


# RC2 S17 review V2: the harness programs come from the cut's own commits (the probe sources of tools at harness_commit, the T1
# drivers of cluster-tools at repos.cluster-tools); a stale probe or a stale harness_commit is refused.
HARNESS_SOURCES = {'core_probe': ('tools', 'runtime-e2e/java/CoreProbe.java'),
                   'journal_probe': ('tools', 'runtime-e2e/java/JournalProbe.java'),
                   't1_me_driver': ('cluster-tools', 'app/forwarder/it/T1MeDriver.java'),
                   't1_core_driver': ('cluster-tools', 'app/forwarder/it/T1CoreDriver.java')}
REPO_PATHS = {'tools': Path(os.environ.get('R10_TOOLS_REPO', str(Path(__file__).resolve().parent.parent))),
              'cluster-tools': Path(os.environ.get('R10_CT_REPO', str(B0 / 'workspace/cluster-tools-s16wt')))}


def git_blob(repo, commit, rel):
    """The bytes of ``rel`` at ``commit`` of a repo of REPO_PATHS, or None (the test seam of V2)."""
    r = subprocess.run(['git', '-C', str(REPO_PATHS[repo]), 'show', f'{commit}:{rel}'], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def _harness_at_commit(f, m, harness, repos):
    commit = m.get('harness_commit')
    if commit is not None and repos.get('tools') is not None and commit != repos.get('tools'):
        f.add('K4', f'harness_commit {commit} is not repos.tools {repos.get("tools")} (one tools commit per cut)')
    for name, (repo, rel) in HARNESS_SOURCES.items():
        entry = harness.get(name)
        if not isinstance(entry, dict) or not entry.get('source_sha256'):
            continue
        at = commit if repo == 'tools' else repos.get('cluster-tools')
        where = 'harness_commit' if repo == 'tools' else 'repos.cluster-tools'
        blob = git_blob(repo, at, rel) if at else None
        if blob is None:
            f.add('K4', f'harness.{name}: {rel} not found at {where} {at}')
        elif hashlib.sha256(blob).hexdigest() != entry['source_sha256']:
            f.add('K4', f'harness.{name}: source_sha256 {entry["source_sha256"][:12]} is not {rel} at {where} {at} '
                        f'({hashlib.sha256(blob).hexdigest()[:12]}): a stale probe')


AERON_VERSION_CLASS = 'io/aeron/AeronVersion.class'
AERON_ROLE = {'match-cluster.jar': 'me', 'assets-cluster.jar': 'ae', 'assets-projector.jar': 'projector',
              'libaeron_driver.so': 'cpp'}
AERON_RE = re.compile(rb'(?<![0-9.])(1\.\d{1,3}\.\d{1,3})(?![0-9.])')


def aeron_version_of(name, path):
    """The Aeron version an artifact carries: ``io/aeron/AeronVersion.class`` of a jar, the version string of the C++ lib."""
    data = _jar_member(path, AERON_VERSION_CLASS) if name.endswith('.jar') else (Path(path).read_bytes() if Path(path).is_file() else None)
    if data is None:
        return None
    found = sorted(set(AERON_RE.findall(data)))
    return found[0].decode() if len(found) == 1 else (None if not found else ','.join(v.decode() for v in found))


def _aeron_k8(f, artifacts, aeron):
    """RC2 S17 review V4: K8 reads the version from the artifacts, not only the substrate's declared strings."""
    for name, role in AERON_ROLE.items():
        entry = artifacts.get(name)
        if not isinstance(entry, dict) or not Path(str(entry.get('path', ''))).is_file():
            continue
        found = aeron_version_of(name, entry['path'])
        want = aeron.get(role)
        if found is None:
            f.add('K8', f'{name}: {AERON_VERSION_CLASS if name.endswith(".jar") else "the Aeron version string"} unreadable')
        elif str(found) != str(want):
            f.add('K8', f'{name}: carries Aeron {found} ({AERON_VERSION_CLASS if name.endswith(".jar") else "version string"}), '
                        f'substrate.aeron.{role} is {want}')


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

    _harness_at_commit(f, m, harness, repos)
    _aeron_k8(f, artifacts, aeron)

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
    import core_contracts
    if cls == 'product' and ids not in ({PER_GENESIS}, {core_contracts.GENESIS_DERIVATION}):
        f.add('K6', f'genesis: a product kind fills genesisId per genesis ("{PER_GENESIS}" or the per-run derivation '
                    f'"{core_contracts.GENESIS_DERIVATION}"), never a constant')

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
    # RC2 S17 review V2: the derived manifest runs the cut's harness, clean; a rig manifest may waive the drift with a named reason
    # (harness_drift, recorded), never a product or nightly one
    drift = []
    if m.get('harness_commit') != cut.get('harness_commit'):
        drift.append(f'harness_commit {m.get("harness_commit")} is not the cut\'s harness_commit {cut.get("harness_commit")}')
    if m.get('harness_dirty') is not False:
        drift.append(f'built from a dirty harness (harness_dirty {m.get("harness_dirty")!r}; 5.4 needs false)')
    waiver = m.get('harness_drift')
    if drift and isinstance(waiver, dict) and waiver.get('reason') and cls in ('rig', 'rig-xver'):
        f.waived.extend(drift)
    else:
        for text in drift:
            f.add('K4', text)
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



# ------------------------------------------------------------------ RC2 S17 W3: the recording log and the genesisId log reader

RECORDING_LOG_ENTRY = 64                      # Aeron RecordingLog: recordingId, termId, base, logPosition, timestamp, serviceId, type
ENTRY_TYPES = {0: 'TERM', 1: 'SNAPSHOT', 2: 'STANDBY_SNAPSHOT'}
ENTRY_INVALID = 1 << 31
FRAME_HEADER = 32                             # Aeron data frame header; payload follows, frames are 32-byte aligned
FLAG_BEGIN, FLAG_END = 0x80, 0x40
CLUSTER_SCHEMA_ID, SESSION_MESSAGE_TEMPLATE = 111, 1     # the cluster SessionMessageHeader in front of every log message
CORE_CONFIG_TEMPLATE = 70
AE_MEMBERS = ('ae0', 'ae1', 'ae2')
ME_MEMBERS = ('me0', 'me1', 'me2')


def recording_log(path):
    """The entries of a cluster ``recording.log`` (fixed 64-byte entries, the same layout in the tag's Aeron and in 1.53.1)."""
    import struct
    data = Path(path).read_bytes()
    if len(data) % RECORDING_LOG_ENTRY:
        raise ValueError(f'{path}: not a whole number of 64-byte entries ({len(data)} bytes)')
    out = []
    for offset in range(0, len(data), RECORDING_LOG_ENTRY):
        rid, term, base, position, stamp, service, kind = struct.unpack_from('<qqqqqii', data, offset)
        raw = kind & 0xFFFFFFFF
        out.append({'recording_id': rid, 'term_id': term, 'base': base, 'log_position': position, 'timestamp': stamp,
                    'service_id': service, 'type': ENTRY_TYPES.get(raw & ~ENTRY_INVALID, f'UNKNOWN({raw & ~ENTRY_INVALID})'),
                    'valid': not raw & ENTRY_INVALID})
    return out


def snapshot_count(path):
    """Valid SNAPSHOT entries in a recording.log (the seed witness of 5.2 and the row-51 precheck)."""
    return sum(1 for e in recording_log(path) if e['type'] == 'SNAPSHOT' and e['valid'])


def log_frames(data):
    """(offset, payload) of every data frame in an archive segment, fragments reassembled; stops at the first unwritten frame."""
    import struct
    offset, partial = 0, None
    while offset + FRAME_HEADER <= len(data):
        length, _, flags, kind = struct.unpack_from('<iBBH', data, offset)
        if length <= 0:
            break
        if kind == 1:
            payload = data[offset + FRAME_HEADER: offset + length]
            if flags & (FLAG_BEGIN | FLAG_END) == FLAG_BEGIN | FLAG_END:
                yield offset, payload
            elif flags & FLAG_BEGIN:
                partial = (offset, bytearray(payload))
            elif partial is not None:
                partial[1].extend(payload)
                if flags & FLAG_END:
                    yield partial[0], bytes(partial[1])
                    partial = None
        offset += (length + 31) & ~31


def load_money_schema(source):
    """The money schema layout: a schema XML path, or an AE jar (its ``sbe/money-schema.xml``, the bytes K2 checks)."""
    import sbe_layout
    import tempfile
    source = Path(source)
    if source.suffix == '.jar':
        data = _jar_member(source, PRODUCT['assets-cluster.jar']['schemas']['money'])
        if data is None:
            raise ValueError(f'{source}: no {PRODUCT["assets-cluster.jar"]["schemas"]["money"]}')
        with tempfile.NamedTemporaryFile('wb', suffix='.xml', delete=False) as out:
            out.write(data)
        try:
            return sbe_layout.load(out.name)
        finally:
            Path(out.name).unlink()
    return sbe_layout.load(source)


def core_config_frames(member_dir, schema):
    """The CoreConfig (template 70) frames of one AE member's LOG recordings (the TERM entries of its recording.log; snapshot
    recordings are not walked): the core's own replicated bytes (section 10, 20.1 line 16; no engine change)."""
    import struct
    base = Path(member_dir) / 'state'
    log = base / 'cluster' / 'recording.log'
    recordings = sorted({e['recording_id'] for e in recording_log(log) if e['type'] == 'TERM'})
    message = schema.messages[CORE_CONFIG_TEMPLATE]
    frames = []
    for rid in recordings:
        segments = sorted((base / 'archive').glob(f'{rid}-*.rec'), key=lambda p: int(p.stem.split('-')[1]))
        for segment in segments:
            for offset, payload in log_frames(segment.read_bytes()):
                if len(payload) < 8:
                    continue
                block, template, schema_id, _ = struct.unpack_from('<HHHH', payload, 0)
                if template != SESSION_MESSAGE_TEMPLATE or schema_id != CLUSTER_SCHEMA_ID:
                    continue
                app = payload[8 + block:]
                if len(app) < 8:
                    continue
                _, template, schema_id, version = struct.unpack_from('<HHHH', app, 0)
                if template != CORE_CONFIG_TEMPLATE or schema_id != schema.schema_id:
                    continue
                row = {'recording': rid, 'file': segment.name, 'path': str(segment), 'offset': offset, 'schema_version': version}
                row.update({f.name: f.decode(app, 8, schema.order) for f in message.fields if f.since <= version})
                frames.append(row)
    return {'recordings': recordings, 'frames': frames}


def genesis_reader(state_root, schema, members=AE_MEMBERS):
    """5.2 (v): the core's recorded genesisId per AE member (the genesisId of the first CoreConfig 1 in its log), compared
    across members. A later CoreConfig with another id (a refused re-genesis, X-A2 (b)) is listed, never taken."""
    if not hasattr(schema, 'messages'):
        schema = load_money_schema(schema)
    out = {'source': 'AE log recordings: CoreConfig (template 70) frames, r10_cut.genesis_reader', 'members': {}}
    firsts, ids = {}, set()
    for member in members:
        directory = Path(state_root) / 'state' / member
        if not (directory / 'state' / 'cluster' / 'recording.log').is_file():
            out['members'][member] = {'error': 'no recording.log', 'frames': [], 'recordings': []}
            continue
        row = core_config_frames(directory, schema)
        first = next((f.get('genesisId') for f in row['frames'] if f.get('configVersion') == 1), None)
        if first is None and row['frames']:
            first = row['frames'][0].get('genesisId')
        row['genesis_id'] = first
        ids.update(f.get('genesisId') for f in row['frames'] if f.get('genesisId') is not None)
        out['members'][member] = row
        if first is not None:
            firsts[member] = first
    values = set(firsts.values())
    out['equal'] = len(values) == 1 and len(firsts) == len(members)
    if not firsts:
        out.update(status='not observable', genesis_id=None)
    elif not out['equal']:
        out.update(status='members differ', genesis_id=None)
    else:
        out.update(status='observed', genesis_id=values.pop())
    out['other_ids_in_log'] = sorted(ids - {out['genesis_id']}) if out['genesis_id'] is not None else sorted(ids)
    return out


# ------------------------------------------------------------------ RC2 S17 W3: the runtime audit (3.5)

SLOT_ROLES = ('fwd0', 'fwd1', 'bridge0', 'bridge1')
VERSION_RE = re.compile(rb'\x00(1\.\d{1,3}\.\d{1,3})\x00')


def audit_expected(m, registry=None):
    """{role: {'files': [{path, sha256, what}], 'build': C++ source sha or None, 'aeron_version_of': in-container aeronmd path}}:
    what each process of the manifest must run, at its in-container path (the staging of core_fixture.stage_artifacts). A slot a
    replace_slot swapped (registry ``slot_override``) is expected on its new artifact."""
    registry = registry or {}
    art = m['artifacts']
    out = {}

    def aeronmd(libs, where):
        entry = (libs or {}).get('aeronmd')
        return [{'path': where + '/aeronmd', 'sha256': entry['sha256'], 'what': 'aeronmd'}] if entry else []

    for engine in ('me', 'ae'):
        for i in range(3):
            files = [{'path': f'/artifacts/{engine}.jar', 'sha256': art[engine]['sha256'], 'what': f'{engine} jar'}]
            if m.get('engine_driver') == 'external':
                files += aeronmd(m.get('engine_libs'), '/artifacts/engine_libs')
            out[f'{engine}{i}'] = {'files': files, 'build': None,
                                   'aeron_version_of': files[-1]['path'] if len(files) > 1 else None}
    if art.get('projector'):
        files = [{'path': '/artifacts/projector.jar', 'sha256': art['projector']['sha256'], 'what': 'projector jar'}]
        if m.get('projector_driver') == 'external':
            files += aeronmd(m.get('projector_libs'), '/artifacts/projector_libs')
        out['projector'] = {'files': files, 'build': None, 'aeron_version_of': files[-1]['path'] if len(files) > 1 else None}
    overrides = registry.get('slot_override') or {}
    for slot in SLOT_ROLES:
        name = overrides.get(slot, (m.get('slot_artifacts') or {}).get(slot))
        entry = art.get(name) if name else None
        if entry is None:
            continue
        files = [{'path': f'/artifacts/{name}/bin', 'sha256': entry['sha256'], 'what': f'{name} binary'}]
        if entry.get('driver') == 'external':
            files += aeronmd(entry.get('libs'), f'/artifacts/{name}')
        out[slot] = {'files': files, 'build': entry.get('source_sha'), 'artifact': name,
                     'aeron_version_of': files[-1]['path'] if len(files) > 1 else None}
    probe = aeronmd(m.get('probe_libs'), '/artifacts/probe')
    if probe:
        out['probe'] = {'files': probe, 'build': None, 'aeron_version_of': probe[0]['path']}
    return out


def audit_check(listing, m, registry=None, swap=None, aeron_version=None, started_only=False, not_started=()):
    """Compare a process listing (live, from ``audit_collect``, or recorded: R08's host list, the unit-test REDs) with the
    manifest. ``swap``: {slot: (artifact a, artifact b)}, the declared upgrade_from pair accepted during that slot's swap window
    only. A member that is not Running is named; it is a finding unless it is a registered fault target (5.2 (ii))."""
    registry = registry or {}
    expected = audit_expected(m, registry)
    procs = {p['role']: p for p in listing.get('processes', [])}
    targets = registry.get('fault_targets') or {}
    findings, stopped, rows, unstarted = [], [], [], []
    for role, want in expected.items():
        proc = procs.get(role)
        if proc is None and (started_only or role in not_started):
            # W5 item 2: a role the step has not started yet (an activation stopped before start_bridges or
            # start_forwarders) is named; a role that ran and stopped, or any foreign process, is still a finding
            # an X run starts only the engine under test (6): a role the scenario never started is named, not a finding
            unstarted.append(role)
            continue
        if proc is None or not proc.get('running'):
            stopped.append({'role': role, 'registered_fault_target': role in targets,
                            'exit_code': (proc or {}).get('exit_code'), 'reason': (targets.get(role) or {}).get('reason')})
            if role not in targets:
                findings.append(f'{role}: stopped and not a registered fault target')
            for f in want['files'] if proc else []:
                got = (proc.get('files') or {}).get(f['path'])
                if got is not None and got != f['sha256']:
                    findings.append(f'{role}: {f["path"]} sha256 {got[:12]} is not the manifest\'s {f["sha256"][:12]} ({f["what"]})')
            continue
        pair = (swap or {}).get(role)
        for f in want['files']:
            got = (proc.get('files') or {}).get(f['path'])
            allowed = {f['sha256']}
            if pair and f['what'].endswith('binary'):
                allowed |= {m['artifacts'][a]['sha256'] for a in pair if m['artifacts'].get(a)}
            if got is None:
                findings.append(f'{role}: {f["path"]} was not read')
            elif got not in allowed:
                findings.append(f'{role}: {f["path"]} sha256 {got[:12]} is not the manifest\'s {f["sha256"][:12]} ({f["what"]})')
        if want.get('build') and proc.get('build') != want['build']:
            if not (pair and proc.get('build') in {m['artifacts'][a].get('source_sha') for a in pair if m['artifacts'].get(a)}):
                findings.append(f'{role}: /health.build {str(proc.get("build"))[:12]} is not the source sha {want["build"][:12]}')
        if aeron_version and want.get('aeron_version_of') and proc.get('aeron_version') != aeron_version:
            findings.append(f'{role}: aeronmd version {proc.get("aeron_version")}, the cut substrate is {aeron_version}')
        rows.append({'role': role, 'ready': proc.get('ready'), 'files': proc.get('files'), 'build': proc.get('build'),
                     'aeron_version': proc.get('aeron_version')})
    for role, proc in procs.items():
        if role not in expected and proc.get('running'):
            retired = role in RETIRED or bool(RETIRED_FILE.search(role))
            findings.append(f'{role}: a process that is not on the manifest' + (' (retired artifact)' if retired else ''))
    for engine in ('me', 'ae'):
        jar = f'/artifacts/{engine}.jar'
        shas = {r: (procs[r].get('files') or {}).get(jar) for r in (f'{engine}{i}' for i in range(3))
                if r in procs and procs[r].get('running')}
        for role, sha in shas.items():
            peers = {s for r, s in shas.items() if r != role}
            if len(peers) == 1 and sha not in peers:
                findings.append(f'{role} differs from its peers ({str(sha)[:12]} vs {str(next(iter(peers)))[:12]})')
    up = {e: sum(1 for i in range(3) if procs.get(f'{e}{i}', {}).get('running') and procs[f'{e}{i}'].get('ready', True)
                 is not False) for e in ('me', 'ae')}
    return {'status': 'REFUSED' if findings else 'OK', 'findings': findings, 'stopped': stopped, 'members_up': up,
            'processes': rows, 'source': listing.get('source'), 'swap': {k: list(v) for k, v in (swap or {}).items()},
            'not_started': unstarted,
            'aeron_version': aeron_version}


def _bind_source(state, dest):
    for mount in state.get('Mounts') or []:
        if mount.get('Destination') == dest:
            return Path(mount['Source'])
    return None


def audit_collect(f):
    """The live listing of a rig fixture (``CoreFixture``): per container, Running, /ready, the sha256 of every expected file read
    inside the container (``docker exec sha256sum``; for a stopped container through its /artifacts bind mount, said so),
    ``/health.build`` of the C++ slots and the Aeron version string of each staged driver library."""
    expected = audit_expected(f.m, f.registry)
    procs = []
    for role, cid in list(f.registry['containers'].items()):
        if role == 'netfilter':
            continue
        row = f.inspect('container', cid)
        running = bool(row['State']['Running'])
        want = expected.get(role, {'files': [], 'build': None, 'aeron_version_of': None})
        out = {'role': role, 'running': running, 'files': {}, 'container_id': cid, 'started_at': row['State']['StartedAt'],
               'exit_code': None if running else row['State']['ExitCode']}
        paths = [x['path'] for x in want['files']]
        if running and paths:
            r = f.execute(role, ['sha256sum', *paths], timeout=60, check=False, accepted=tuple(range(256)))
            for line in (r.stdout or '').splitlines():
                parts = line.split()
                if len(parts) == 2:
                    out['files'][parts[1]] = parts[0]
            out['read'] = 'docker exec sha256sum'
        source = _bind_source(row, '/artifacts')
        if source is not None:
            for path in paths:
                if path not in out['files']:
                    host = source / Path(path).relative_to('/artifacts')
                    if host.is_file():
                        out['files'][path] = sha256_file(host)
                        out['read'] = 'bind mount (container not running)' if not running else out.get('read')
            if want.get('aeron_version_of'):
                lib = (source / Path(want['aeron_version_of']).relative_to('/artifacts')).with_name('libaeron_driver.so')
                found = VERSION_RE.findall(lib.read_bytes()) if lib.is_file() else []
                out['aeron_version'] = found[0].decode() if found else None
        if running:
            try:
                port, path = f.ready_target(role) if role != 'probe' else (None, None)
                if port:
                    out['ready'] = f.http(role, port, path).get('status') == 200
                if want.get('build'):
                    body = f.http(role, port, '/health').get('body') or '{}'
                    out['build'] = json.loads(body).get('build')
            except Exception as error:          # recorded, never fatal: the check names the missing value
                out['ready_error'] = str(error)[:200]
        procs.append(out)
    return {'source': 'rig containers (r10_cut.audit_collect)', 'run_id': f.run_id, 'processes': procs}


def audit_fixture(f, out=None, swap=None, aeron_version=None, started_only=False, not_started=()):
    """``audit`` on a live fixture: collect, check, and (``out``) write the report: the evidence of 3.5."""
    report = audit_check(audit_collect(f), f.m, f.registry, swap=swap, aeron_version=aeron_version, started_only=started_only,
                         not_started=not_started)
    if out is not None:
        Path(out).write_text(json.dumps(report, indent=1) + '\n')
    return report


# ------------------------------------------------------------------ RC2 S17 W3: the wipe precheck (3.5)

WIPED = [('me', 'ME state', 'state'), ('me', 'ME journal archive', 'journal'), ('ae', 'AE state', 'state/cluster'),
         ('ae', 'AE archive (money journal)', 'state/archive')]


def _usage(path):
    files = [p for p in Path(path).rglob('*') if p.is_file() or p.is_symlink()]
    return len(files), sum(p.lstat().st_size for p in files)


def precheck(roots, pg_rows=None, aeron_dirs=()):
    """Runbook step 1: every dir the forward order wipes must be empty and the projection database must hold no row.
    ``roots`` are fixture state roots (``<root>/state/<member>``); ``pg_rows`` {table: rows} of the projection database (None =
    not read: refused, never assumed empty); ``aeron_dirs`` the host aeronmd dirs."""
    refusals, wipe = [], []
    for root in map(Path, roots):
        state = root / 'state'
        if not root.is_dir():
            refusals.append(f'{root}: state root not found')
            continue
        if not state.is_dir():
            wipe.append({'label': 'fixture state', 'path': str(state), 'absent': True})    # a fresh root: nothing to wipe
            continue
        for engine in ('me', 'ae'):
            for i in range(3):
                member = state / f'{engine}{i}'
                for e, label, sub in WIPED:
                    if e != engine:
                        continue
                    path = member / sub
                    wipe.append({'label': label, 'path': str(path)})
                    if path.exists():
                        n, size = _usage(path)
                        if n:
                            refusals.append(f'{label} not empty: {path} ({n} file(s), {size} byte(s))')
                log = member / 'state' / 'cluster' / 'recording.log'
                if log.is_file():
                    try:
                        snaps = snapshot_count(log)
                    except ValueError as error:
                        refusals.append(f'{member}: {error}')
                        snaps = 0
                    if snaps:
                        refusals.append(f'{member}: recording.log lists {snaps} snapshot(s); an S16-era bare RC2 snapshot '
                                        '(row 51) is unsupported: archive it and wipe')
    wipe.append({'label': 'projection database rows', 'path': 'r01_money'})
    if pg_rows is None:
        refusals.append('projection database not read: the precheck never assumes it empty')
    else:
        for table, rows in sorted(pg_rows.items()):
            if rows:
                refusals.append(f'projection database holds {rows} row(s) in {table}')
    for d in map(Path, aeron_dirs):
        wipe.append({'label': 'host aeronmd dir', 'path': str(d)})
        if d.exists() and any(d.iterdir()):
            refusals.append(f'host aeronmd dir not empty: {d}')
    return {'status': 'REFUSED' if refusals else 'CLEAN', 'refusals': refusals, 'wipe_list': wipe}


def projection_rows(f):
    """{table: rows} of a fixture's money projection database (``r01_money``); {} when the database does not exist yet."""
    exists = f.psql('postgres', "SELECT count(*) FROM pg_database WHERE datname = 'r01_money'").strip()
    if exists in ('', '0'):
        return {}
    tables = json.loads(f.psql('r01_money', "SELECT COALESCE(json_agg(table_name), '[]'::json) FROM information_schema.tables "
                                             "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'") or '[]')
    out = {}
    for table in tables:
        if re.fullmatch(r'[a-z_][a-z0-9_]*', table) and not table.startswith('flyway'):
            out[table] = int(f.psql('r01_money', f'SELECT count(*) FROM "{table}"').strip() or 0)
    return out


# ------------------------------------------------------------------ RC2 S17 W3: the activation record (section 10)

ADMIN_RESULTS = {0: 'ACCEPTED', 1: 'DUPLICATE', 2: 'REJECTED', 3: 'ADOPTED', 4: 'STALE'}
CONFIG_OK = {'ACCEPTED', 'DUPLICATE', 'ADOPTED'}
ME_JOURNAL_SCHEMA = Path(__file__).resolve().parent / 'schemas' / 'me-journal-schema-4.xml'
SOURCES = {'me_genesis_id': 'ME journal record 5 (JournalProbe dump)',
           'core_genesis_id': 'AE log recordings, CoreConfig frames (r10_cut.genesis_reader)',
           'core_bound_epoch': 'money-dump meEpoch (CoreProbe)'}
STATUS_ORDER = ['OK', 'INCOMPLETE', 'ABORTED', 'REFUSED']
DOWNGRADE_BOUNDARY = ('after this record no ME behaviour 1, no pre-RC2 jar, no S16 jar and no tag member may run on this state; '
                      'row 04 refused by measurement (S17/evidence row 04), rows 02, 11, 41, 52 unsupported, not measured, '
                      'guarded (test_r10_cut GuardedRowRedTest, AuditTest.test_guarded_rows_name_the_foreign_member)')


class _Record:
    def __init__(self):
        self.status, self.refusals = 'OK', []

    def say(self, status, text):
        self.refusals.append(text)
        if STATUS_ORDER.index(status) > STATUS_ORDER.index(self.status):
            self.status = status


def _jsonl(path, rec):
    path = Path(path)
    if not path.is_file():
        rec.say('REFUSED', f'run evidence missing: {path}')
        return []
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


def _decode_record5(lines, message, order):
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('kind') != 'frame':
            continue
        data = bytes.fromhex(row['hex'])
        import struct
        _, template, schema_id, _ = struct.unpack_from('<HHHH', data, 0)
        if template == 5:
            values = {f.name: f.decode(data, 8, order) for f in message.fields}
            return {'journal_seq': values['journalSeq'], 'me_epoch': values['meEpoch'], 'behavior_version': values['behaviorVersion'],
                    'ledger_capacity': values['ledgerCapacity'], 'max_wire_version': values['maxWireVersion'],
                    'decision': values['decision'], 'position': row.get('position'), 'source': row.get('source')}
    return None


def check_record(record):
    """Structural rules of a record (C3, C6): three values from three sources, never one value read twice. Review V10: the
    sources are the files actually read (JournalProbe dump outputs, AE .rec segments, core-requests.jsonl); a value without a
    file, or two values read from one file, is refused."""
    out = []
    src = record.get('sources') or {}
    if src.get('core_genesis_id') == src.get('me_genesis_id'):
        out.append(f'core genesisId and ME genesisId read from one source ({src.get("me_genesis_id")})')
    if src.get('core_bound_epoch') in (src.get('me_genesis_id'), src.get('core_genesis_id')):
        out.append(f'core bound epoch read from the source of a genesisId ({src.get("core_bound_epoch")})')
    files = src.get('files')
    if files is not None:
        keys = ('me_genesis_id', 'core_genesis_id', 'core_bound_epoch')
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                shared = set(files.get(a) or []) & set(files.get(b) or [])
                if shared:
                    out.append(f'{a} and {b} read from one file: {sorted(shared)}')
    return out


INVARIANTS = (('me', 'record5', 'behavior_version'), ('me', 'record5', 'max_wire_version'), ('me', 'record5', 'journal_seq'),
              ('me', 'record5', 'decision'))


def check_record_set(records):
    """RC2 step 7: a genesisId that repeats across genesis runs is a refused record; the invariant fields of section 10
    (behaviour 2, maxWireVersion 12, journalSeq 1 FRESH, the CoreConfig 1-2-3 acceptance, the gate transition) are equal."""
    seen, out = {}, []
    records = [r for r in records if r.get('record_kind', 'final') == 'final']
    for i, record in enumerate(records):
        gid = (record.get('me') or {}).get('genesisId')
        if gid is None:
            continue
        if gid in seen:
            out.append(f'genesisId {gid} repeats across genesis runs (records {seen[gid]} and {i})')
        seen.setdefault(gid, i)
    def value(record, path):
        for key in path:
            record = (record or {}).get(key) if isinstance(record, dict) else None
        return record
    for path in INVARIANTS:
        values = {json.dumps(value(r, path)) for r in records}
        if len(values) > 1:
            out.append(f'invariant {".".join(path)} differs across records: {sorted(values)}')
    accepted = {json.dumps(sorted({v for v, res in ((r.get('core') or {}).get('config_sequence') or []) if res in CONFIG_OK}))
                for r in records}
    if len(accepted) > 1:
        out.append(f'invariant CoreConfig acceptance differs across records: {sorted(accepted)}')
    gates = {json.dumps([g[:2] for g in (r.get('gate') or [])][:1] + ([['OPEN', 'ADMIN']] if any(g[:2] == ['OPEN', 'ADMIN']
             for g in (r.get('gate') or [])) else [])) for r in records}
    if len(gates) > 1:
        out.append(f'invariant gate transition differs across records: {sorted(gates)}')
    return out


def activation_record(run_dir, journal_schema=None, state_root=None, audit=None, cut=None, life=1, record_kind='final'):
    """``rc2-activation-record.json`` of one genesis, from the run's evidence only (C3: what happened, never what was sent):
    record 5 from the JournalProbe dumps, the core genesisId from the AE log recordings, the bound epoch from money-dump, the
    CoreConfig acknowledgements from the genesis driver's and the probe's outputs, the gate from the tap rows, the phases from
    the fixture registry, the audit report and ``members_up``. Status OK / INCOMPLETE / ABORTED (section 10) or REFUSED (the
    evidence is inconsistent or missing: no record can be issued)."""
    import sbe_layout
    run = Path(run_dir)
    rec = _Record()
    if record_kind not in ('final', 'intermediate'):
        raise ValueError('record_kind is final or intermediate')
    # rc2-cut-4: a pre-recovery record is intermediate (it shares the run's genesisId by design); RC2 step 7 reads finals only
    out = {'schema': 'rc2-activation-record/1', 'record_kind': record_kind, 'run_dir': str(run), 'life': life,
           'sources': dict(SOURCES),
           'downgrade_boundary': DOWNGRADE_BOUNDARY}
    manifest_path = run / 'manifest.json'
    if state_root is None:
        result = run / 'result.json'
        if result.is_file():
            state_root = json.loads(result.read_text()).get('state_root')
        if state_root is None and manifest_path.is_file():
            # W5 item 6: an X run's result.json carries no state_root (xver owns its fixtures); the manifest names it
            state_root = json.loads(manifest_path.read_text()).get('state_root')
        if state_root is None:
            rec.say('REFUSED', f'run evidence missing: {result} (state_root)')
    if not manifest_path.is_file():
        rec.say('REFUSED', f'run evidence missing: {manifest_path}')
        m = {}
    else:
        m = json.loads(manifest_path.read_text())
        out['manifest_sha256'] = sha256_file(manifest_path)
    out['cut_id'] = (cut or {}).get('cut_id') or m.get('cut_id')
    if state_root is None:
        out.update(status=rec.status, refusals=rec.refusals)
        return out
    root = Path(state_root)
    owner_path = root / 'owner.json'
    owner = json.loads(owner_path.read_text()) if owner_path.is_file() else None
    if owner is None:
        rec.say('REFUSED', f'run evidence missing: {owner_path}')
        owner = {}
    commands = _jsonl(root / 'commands.jsonl', rec)
    requests = _jsonl(root / 'core-requests.jsonl', rec)
    if audit is None:
        audit_path = run / 'audit.json'
        if audit_path.is_file():
            audit = json.loads(audit_path.read_text())
        else:
            rec.say('REFUSED', f'run evidence missing: {audit_path}')
    # ---- ME record 5 (JournalProbe dumps: the first successful dump of each member)
    schema = sbe_layout.load(journal_schema or ME_JOURNAL_SCHEMA)
    message = schema.messages[5]
    record5, me_files = {}, []
    for c in commands:
        argv = ' '.join(c.get('argv', []))
        hit = re.search(r'JournalProbe dump .*source=(me[0-2])', argv)
        if not hit or c.get('exit_code') != 0 or hit.group(1) in record5:
            continue
        log = Path(c['output'])
        if not log.is_file():
            rec.say('REFUSED', f'run evidence missing: {log}')
            continue
        r5 = _decode_record5(log.read_text().splitlines(), message, schema.order)
        if r5 is not None:
            record5[hit.group(1)] = r5
            me_files.append(str(log))
    me = {'members': sorted(record5)}
    if not record5:
        rec.say('INCOMPLETE', 'ME record 5 not dumped by any member')
        me_gid = None
    else:
        epochs = {r['me_epoch'] for r in record5.values()}
        if len(epochs) != 1:
            rec.say('REFUSED', f'ME record 5 meEpoch differs across members: {sorted(epochs)}')
        first = record5[sorted(record5)[0]]
        me_gid = first['me_epoch']
        me['record5'] = {k: first[k] for k in ('journal_seq', 'behavior_version', 'ledger_capacity', 'max_wire_version', 'decision')}
        want_capacity = (owner.get('genesis') or {}).get('ledger_capacity')
        for member, r in sorted(record5.items()):
            if r['behavior_version'] != 2:
                rec.say('REFUSED', f'ME record 5 on {member}: behaviorVersion {r["behavior_version"]}, the activation needs 2')
            if r['max_wire_version'] != 12:
                rec.say('REFUSED', f'ME record 5 on {member}: maxWireVersion {r["max_wire_version"]}, the activation needs 12')
            if r['journal_seq'] != 1 or r['decision'] != 'FRESH':
                rec.say('REFUSED', f'ME record 5 on {member}: journalSeq {r["journal_seq"]} decision {r["decision"]}, want 1 FRESH')
            if want_capacity is not None and r['ledger_capacity'] != want_capacity:
                rec.say('REFUSED', f'ME record 5 on {member}: commandLedgerCapacity {r["ledger_capacity"]} != the plan\'s '
                                   f'{want_capacity}')
    me['genesisId'] = me_gid
    out['me'] = me
    derivation = (owner.get('genesis') or {}).get('derivation')
    if not derivation and str(m.get('manifest_kind', '')).startswith('s17'):
        rec.say('REFUSED', 'genesisId derivation missing: an s17 run derives its genesisId from its run_id (review V12)')
    if derivation:
        import core_contracts
        derived = int(core_contracts.derive_genesis_id(derivation.get('run_id'), life), 16)
        out['genesis_id_derivation'] = dict(derivation, derived=derived, equal=me_gid == derived)
        if derivation.get('run_id') != m.get('run_id'):
            rec.say('REFUSED', f'genesisId derivation: the run_id {derivation.get("run_id")} is not the run\'s {m.get("run_id")}')
        if me_gid is not None and me_gid != derived:
            rec.say('REFUSED', f'ME genesisId {me_gid} != the id derived from run_id {derivation.get("run_id")} ({derived})')
    # ---- CoreConfig acknowledgements in time order: the probe's core-config verbs (at_ns) and the genesis driver's first run
    acks, driver_exit = [], None
    for r in requests:
        if r.get('verb') == 'core-config':
            for reply in ((r.get('reply') or {}).get('replies') or []):
                if reply.get('t') == 'AdminAck' and reply.get('ref') == CORE_CONFIG_TEMPLATE:
                    acks.append((r.get('at_ns') or 0, int((r.get('args') or {}).get('version', reply.get('configVersion', 0))),
                                 reply['result']))
    for c in commands:
        if re.search(r'\bT1CoreDriver genesis\b', ' '.join(c.get('argv', []))):
            log = Path(c['output'])
            text = log.read_text() if log.is_file() else ''
            stamp = log.stat().st_mtime_ns if log.is_file() else 0
            for k, (v, code) in enumerate(re.findall(r'CoreConfig (\d) result (\d+)', text)):
                acks.append((stamp + k, int(v), ADMIN_RESULTS.get(int(code), str(code))))
            driver_exit = c.get('exit_code')
            break
    acks.sort(key=lambda a: a[0])
    sequence = [[v, result] for _, v, result in acks]
    # ---- core genesisId (review V11): the CoreConfig 1 frame of each AE member's log recording that its ACCEPTED/ADOPTED
    # AdminAck answered (the i-th frame of a version pairs with the i-th ack of that version); a refused frame never wins
    core = {}
    ae_jar = ((m.get('artifacts') or {}).get('ae') or {}).get('path')
    reader = None
    if ae_jar and Path(ae_jar).is_file():
        try:
            reader = genesis_reader(root, load_money_schema(ae_jar))
        except (ValueError, OSError) as error:
            reader = {'status': 'not observable', 'genesis_id': None, 'error': str(error), 'members': {}}
    else:
        reader = {'status': 'not observable', 'genesis_id': None, 'error': f'AE jar not readable: {ae_jar}', 'members': {}}
    applied, core_files = {}, set()
    for member, row in (reader.get('members') or {}).items():
        seen = {}
        for frame in row.get('frames') or []:
            v = frame.get('configVersion')
            i = seen[v] = seen.get(v, -1) + 1
            same = [a for a in acks if a[1] == v]
            if v == 1 and i < len(same) and same[i][2] in ('ACCEPTED', 'ADOPTED') and member not in applied:
                applied[member] = frame.get('genesisId')
                core_files.add(frame.get('path'))
    values = set(applied.values())
    core['genesis_reader'] = {k: reader.get(k) for k in ('status', 'genesis_id', 'equal', 'other_ids_in_log', 'error') if k in reader}
    core['applied'] = applied
    # rc2-cut-4 (X-A4): the members that hold the applied CoreConfig are read; a member that has not applied it yet (a late
    # joiner still catching up) is named, never a disagreement; two different applied ids refuse; a majority must hold it
    core['read_from'] = sorted(applied)
    core['not_applied'] = sorted(set(AE_MEMBERS) - set(applied))
    core_gid = values.pop() if len(values) == 1 and len(applied) * 2 > len(AE_MEMBERS) else None
    core['genesisId'] = core_gid if core_gid is not None else 'not observable'
    if core_gid is None:
        if len(values) > 1:
            rec.say('REFUSED', f'core genesisId differs across AE members: {applied}')
        else:
            rec.say('INCOMPLETE', f'core genesisId not observable (the applied CoreConfig 1 on {sorted(applied)}, a majority of '
                                  f'{list(AE_MEMBERS)} needed; reader {reader.get("status")})')
    elif me_gid is not None and core_gid != me_gid:
        rec.say('REFUSED', f'core genesisId {core_gid} != ME genesisId {me_gid}')
    core['config_sequence'] = sequence
    core['driver_exit'] = driver_exit
    accepted = {v for v, result in sequence if result in CONFIG_OK}
    refused = [[v, result] for v, result in sequence if result not in CONFIG_OK]
    for v in (1, 2, 3):
        if v not in accepted:
            status = 'ABORTED' if refused or (driver_exit not in (None, 0)) else 'INCOMPLETE'
            rec.say(status, f'CoreConfig {v} not accepted' + (f' (refused: {refused})' if refused else ''))
    # ---- bound epoch and cursor (money-dump)
    bound = next((r['reply'] for r in requests if r.get('verb') == 'money-dump' and (r.get('reply') or {}).get('meEpoch')), None)
    if bound is None:
        rec.say('INCOMPLETE', 'the core never bound an ME epoch (money-dump meEpoch 0)')
        core['bound_epoch'] = None
    else:
        core['bound_epoch'], core['feed_cursor'] = bound['meEpoch'], bound.get('lastAppliedJournalSeq')
        if me_gid is not None and bound['meEpoch'] != me_gid:
            rec.say('REFUSED', f'core bound epoch {bound["meEpoch"]} != ME record 5 meEpoch {me_gid}')
    out['sources']['core_genesis_id'] = ('AE log recordings: the CoreConfig 1 frame paired with its accepted AdminAck (sequenced '
                                         'CoreConfig ingress; the snapshot CORE_CONFIG section is not read)')
    out['sources']['files'] = {'me_genesis_id': sorted(me_files), 'core_genesis_id': sorted(p for p in core_files if p),
                               'core_bound_epoch': [str(root / 'core-requests.jsonl')] if bound is not None else []}
    out['core'] = core
    # ---- gate (the tap's GLOBAL admission rows)
    tap = ((owner.get('lives') or {}).get(str(life)) or {}).get('tap') or owner.get('tap') or {}
    tap_path = Path(tap['path']) if tap.get('path') else root / 'state' / 'probe' / f'tap-life{life}.jsonl'
    gate = []
    for row in _jsonl(tap_path, rec):
        if row.get('tap') == 'admission' and (row.get('row') or {}).get('market') == 0:
            g = [row['row']['state'], row['row']['reason'], row['row'].get('log_position')]
            if not gate or gate[-1][:2] != g[:2]:
                gate.append(g + [row['row'].get('at_ms')])
    out['gate'] = [g[:3] for g in gate]
    opened = next((g for g in gate if g[:2] == ['OPEN', 'ADMIN']), None)
    if not gate or gate[0][:2] != ['SUSPENDED', 'GENESIS']:
        rec.say('INCOMPLETE', f'the gate rows do not start at [SUSPENDED, GENESIS]: {out["gate"][:2]}')
    if opened is None:
        rec.say('INCOMPLETE', 'the gate never reached [OPEN, ADMIN]')
    # ---- phases and the forwarders after the open
    phases = (owner.get('boot') or {}).get('phases') or {}
    out['phases'] = phases
    try:
        from core_fixture import check_genesis_order
        check_genesis_order(phases)
    except Exception as error:
        rec.say('INCOMPLETE' if 'missing' in str(error) else 'REFUSED', f'phase order: {error}')
    if opened is not None and phases.get('forwarders_ready_ns') and opened[3] is not None \
            and phases['forwarders_ready_ns'] < opened[3] * 1_000_000:
        rec.say('REFUSED', 'forwarders ready before the gate opened (the fixture order starts them last, CF:46-47)')
    # ---- audit and members_up
    if audit is not None:
        out['audit'] = {k: audit.get(k) for k in ('status', 'findings', 'stopped', 'members_up')}
        if audit.get('status') != 'OK':
            rec.say('REFUSED', f'audit {audit.get("status")}: {audit.get("findings")}')
        up = audit.get('members_up') or {}
        out['members_up'] = up
        for engine in ('me', 'ae'):
            n = up.get(engine)
            named = [s['role'] for s in audit.get('stopped') or [] if s['role'].startswith(engine)]
            if n is None:
                rec.say('REFUSED', f'members_up {engine} missing from the audit')
            elif n < 3 and len(named) < 3 - n:
                rec.say('REFUSED', f'members_up {engine} {n}/3 but the audit names no stopped {engine} member')
    for text in check_record(out):
        rec.say('REFUSED', text)
    out.update(status=rec.status, refusals=rec.refusals)
    return out


def write_activation_record(run_dir, out=None, **kw):
    record = activation_record(run_dir, **kw)
    path = Path(out) if out else Path(run_dir) / 'rc2-activation-record.json'
    path.write_text(json.dumps(record, indent=1) + '\n')
    return record, path

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
    a = sub.add_parser('audit', help='a live fixture state root (owner.json) or a recorded listing JSON, against --manifest')
    a.add_argument('target', type=Path)
    a.add_argument('--manifest', type=Path, required=True)
    a.add_argument('--cut', type=Path)
    a.add_argument('--swap', action='append', default=[], help='SLOT=ARTIFACT_A,ARTIFACT_B (the declared upgrade_from pair)')
    a.add_argument('--out', type=Path)
    p = sub.add_parser('precheck', help='runbook step 1: the dirs the forward order wipes must be empty')
    p.add_argument('roots', type=Path, nargs='+')
    p.add_argument('--manifest', type=Path)
    p.add_argument('--pg-rows', type=Path, help='{table: rows} of the projection database (JSON); without it the precheck refuses')
    p.add_argument('--aeron-dir', type=Path, action='append', default=[])
    ar = sub.add_parser('activation-record', help='rc2-activation-record.json of a genesis run dir (section 10)')
    ar.add_argument('run_dir', type=Path)
    ar.add_argument('--journal-schema', type=Path)
    ar.add_argument('--audit', type=Path)
    ar.add_argument('--out', type=Path)
    rs = sub.add_parser('activation-records', help='RC2 step 7: a set of records (files or dirs holding '
                        'rc2-activation-record.json): no repeated genesisId, equal invariant fields, every record OK')
    rs.add_argument('records', type=Path, nargs='+')
    g = sub.add_parser('genesis-ids', help='5.2 (v): the CoreConfig genesisId recorded in each AE member log')
    g.add_argument('state_root', type=Path)
    g.add_argument('--schema', type=Path, required=True, help='money schema XML or the AE jar')
    args = parser.parse_args(argv)
    if args.cmd == 'record-builds':
        record_builds(args.out, args.spec)
        print(args.out)
        return 0
    if args.cmd == 'audit':
        m = json.loads(args.manifest.read_text())
        cut = json.loads(args.cut.read_text()) if args.cut else None
        version = ((cut or {}).get('substrate') or {}).get('aeron', {}).get('host_aeronmd')
        swap = {}
        for spec in args.swap:
            slot, _, pair = spec.partition('=')
            swap[slot] = tuple(pair.split(','))
        if args.target.is_dir():
            from core_fixture import CoreFixture
            f = CoreFixture(args.manifest, attach=True)
            report = audit_check(audit_collect(f), m, f.registry, swap=swap, aeron_version=version)
        else:
            report = audit_check(json.loads(args.target.read_text()), m, swap=swap, aeron_version=version)
        text = json.dumps(report, indent=1)
        if args.out:
            args.out.write_text(text + '\n')
        print(text)
        return 0 if report['status'] == 'OK' else 1
    if args.cmd == 'precheck':
        rows = json.loads(args.pg_rows.read_text()) if args.pg_rows else None
        report = precheck(args.roots, pg_rows=rows, aeron_dirs=args.aeron_dir)
        print(json.dumps(report, indent=1))
        return 0 if report['status'] == 'CLEAN' else 1
    if args.cmd == 'activation-record':
        audit = json.loads(args.audit.read_text()) if args.audit else None
        record, path = write_activation_record(args.run_dir, args.out, journal_schema=args.journal_schema, audit=audit)
        print(json.dumps({'status': record['status'], 'refusals': record['refusals'], 'record': str(path)}, indent=1))
        return 0 if record['status'] == 'OK' else 1
    if args.cmd == 'activation-records':
        found = []
        for p in args.records:
            found += sorted(p.rglob('rc2-activation-record*.json')) if p.is_dir() else [p]
        loaded = [(p, json.loads(p.read_text())) for p in found]
        paths = [p for p, r in loaded if r.get('record_kind', 'final') == 'final']
        skipped = [str(p) for p, r in loaded if r.get('record_kind', 'final') != 'final']
        records = [r for p, r in loaded if r.get('record_kind', 'final') == 'final']
        refusals = check_record_set(records) + [f'{p}: status {r.get("status")}' for p, r in zip(paths, records)
                                                if r.get('status') != 'OK']
        print(json.dumps({'records': [str(p) for p in paths], 'skipped_intermediate': skipped, 'refusals': refusals},
                         indent=1))
        return 1 if refusals or not records else 0
    if args.cmd == 'genesis-ids':
        out = genesis_reader(args.state_root, args.schema)
        print(json.dumps(out, indent=1, default=str))
        return 0 if out['status'] == 'observed' else 1
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
