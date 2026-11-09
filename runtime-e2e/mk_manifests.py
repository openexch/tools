#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Core-topology fixture manifest builder.
Usage: mk_manifests.py <kind> <tag> [--b-source-sha SHA] [--build-b DIR] [--octet N] [--pg-port P]
                       [--shm ROLE=MB ...] [--memory ROLE=MB ...]          prints the manifest path
       mk_manifests.py <s17 kind> <tag> --cut <cut manifest> [...]   derived from the cut;
                       written only when ``release_cut.py check`` accepts it (build A must be pinned in the old-artifact pins)

Kinds (the eleven base manifests; ``core_contracts.BASE_KINDS``):
  s16                  C++ slots external (build A), engines embedded (dev profile)
  s16-ext              s16 with the engines external too: A04-regenesis, C13-enginedriverkill
  s16-embedded         C++ slots embedded
  s16-n1               s16 with fwd1 null (a06-n1, the N = 1 cost cells)
  s16-a03(-embedded)   both forwarder slots on ct_forwarder_nc_norelease (forwarder_b), build A as forwarder for the
                       replace_slot swap
  s16-a05(-embedded)   forwarder_b / bridge_b = build B, slots on build A
  s16-red-a03          forwarder_b = ct_forwarder_nc_norelease in both forwarder slots
  s16-red-a04          bridge_b = ct_bridge_nc_noepoch in both bridge slots, engines external
  s16-ctl-edk-cnctimeout  s16-ext; the only manifest ENGINE_DRIVER_SKIP=1 is accepted on

Every manifest of one kind differs from its siblings only in run_id and state_root: subnet, ports, seed, pins and cpu plan are
constants of the kind. The file is ``$RUNS/manifests/<kind>--<tag>.json`` (the kind is pinned in ``manifest_kind`` and checked
against the file name). Resource sizes are SETTINGS with defaults (engine members shm 2048 / memory 5120, bridges and
probe shm 1024, forwarders and projector shm 256), never acceptance limits.

Host paths are settings read from the environment (``machine_paths.env_path``); there is no machine default, and a path a
build needs stops it with a message naming the variable when it is unset. A ``Config`` field set explicitly wins.
  MK_RUNS               runs root; manifests go to ``$MK_RUNS/manifests`` (``--runs`` wins)
  MK_BIN_A              directory holding build A (``ct-forwarder``, ``ct-bridge`` and the Aeron driver files)
  MK_BUILD_B            directory holding build B (the A05 kinds' second build; ``--build-b`` wins)
  MK_NC_DIR             test-config build holding the nc targets of the base kinds
  MK_CUT_NC_DIR         test-config build of the cut's cluster-tools commit (the nc targets of the negative cut kinds)
  MK_DRIVER_PROPERTIES  the ME tree's ``deploy/media-driver/driver.properties`` (pinned by sha256 below)
  MK_AE_JAR, MK_ME_JAR, MK_PROJECTOR_JAR   the engine jars of the base kinds (their source commits are pinned below)
  MK_PROBE_MANIFEST     the ``probe-manifest.json`` written by ``build_core_probes.py``
  MK_NETFILTER_HELPER   the netfilter helper directory (``iptables-legacy`` and its extensions)
"""
import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys

from contracts import Violation
import core_contracts
from machine_paths import env_path
import release_cut

CT_A_SOURCE_SHA = '2be3a1999ca193c0f37db7f6e460edd652c55fa1'     # build A = the pinned older forwarder and bridge binaries
DP_SHA256 = '246ac150f5fb880f566ae4290786c47f83abe15a42024e0479e5b78bb57978ec'   # me/deploy/media-driver/driver.properties @ c53dd20
SEED = 15112026
# The launch-driver.sh dev profile overlay (LD:19-20; C driver tokens), byte-identical to the dry run's file
# SHARED threading, backoff idles, no pinning.
DEV_OVERLAY = ('# the LD dev profile overlay (launch-driver.sh:190-206, C driver tokens): SHARED threading, backoff idles\n'
               'aeron.threading.mode=SHARED\n'
               'aeron.conductor.idle.strategy=backoff\n'
               'aeron.sender.idle.strategy=backoff\n'
               'aeron.receiver.idle.strategy=backoff\n'
               'aeron.shared.idle.strategy=backoff\n')
# Settings with defaults, overridable per role on the command line.
SHM_MB = {**{r: 2048 for r in core_contracts.ENGINES}, 'bridge0': 1024, 'bridge1': 1024, 'probe': 1024,
          'fwd0': 256, 'fwd1': 256, 'projector': 256}
MEMORY_MB = {**{r: 5120 for r in core_contracts.ENGINES}, 'bridge0': 2048, 'bridge1': 2048}
CPU_SET_BY_ROLE = {'me0': [0], 'me1': [1], 'me2': [2], 'ae0': [3], 'ae1': [4], 'ae2': [5], 'fwd0': [6, 7, 8, 9],
                   'fwd1': [6, 7, 8, 9], 'bridge0': [6, 7, 8, 9], 'bridge1': [6, 7, 8, 9], 'projector': [6, 7, 8, 9],
                   'probe': [10, 11]}
CPU_QUOTA_BY_ROLE = {**{r: 1.0 for r in core_contracts.ENGINES}, 'fwd0': 0.8, 'fwd1': 0.8, 'bridge0': 0.8, 'bridge1': 0.8,
                     'projector': 0.8, 'probe': 2.0}

# kind -> (slot driver, engine driver, slot_artifacts, artifact sources); A = build A, B = build B, nc names a negative target
KINDS = {
    's16': ('external', 'embedded', 'A', {}),
    's16-ext': ('external', 'external', 'A', {}),
    's16-embedded': ('embedded', 'embedded', 'A', {}),
    's16-n1': ('external', 'embedded', 'N1', {}),
    's16-a03': ('external', 'embedded', 'A03', {'forwarder_b': 'ct_forwarder_nc_norelease'}),
    's16-a03-embedded': ('embedded', 'embedded', 'A03', {'forwarder_b': 'ct_forwarder_nc_norelease'}),
    's16-a05': ('external', 'embedded', 'A', {'forwarder_b': 'B', 'bridge_b': 'B'}),
    's16-a05-embedded': ('embedded', 'embedded', 'A', {'forwarder_b': 'B', 'bridge_b': 'B'}),
    's16-red-a03': ('external', 'embedded', 'REDA03', {'forwarder_b': 'ct_forwarder_nc_norelease', 'forwarder': None}),
    's16-red-a04': ('external', 'external', 'REDA04', {'bridge_b': 'ct_bridge_nc_noepoch', 'bridge': None}),
    's16-ctl-edk-cnctimeout': ('external', 'external', 'A', {}),
}
SLOTS = {'A': {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge'},
         'N1': {'fwd0': 'forwarder', 'fwd1': None, 'bridge0': 'bridge', 'bridge1': 'bridge'},
         'A03': {'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b', 'bridge0': 'bridge', 'bridge1': 'bridge'},
         'REDA03': {'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b', 'bridge0': 'bridge', 'bridge1': 'bridge'},
         'REDA04': {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge_b', 'bridge1': 'bridge_b'}}


def _jars():
    return {'ae': (env_path('MK_AE_JAR', 'the assets-cluster.jar of the base kinds'), '6fdf6721a8c09c61b7f7d4d249a05cd62d8c0efe'),
            'me': (env_path('MK_ME_JAR', 'the match-cluster.jar of the base kinds'), 'c53dd20afe404cc4482dbe0114117ddefc6f3a7f'),
            'projector': (env_path('MK_PROJECTOR_JAR', 'the projector.jar of the base kinds'),
                          'a9a865d6b3db65ac4d024382dcb5158e411c8bf6')}


def _setting(name, what):
    return field(default_factory=lambda: env_path(name, what))


@dataclass
class Config:
    runs: Path = _setting('MK_RUNS', 'the runs root (manifests are written to $MK_RUNS/manifests)')
    bin_a: Path = _setting('MK_BIN_A', 'the directory holding build A (ct-forwarder, ct-bridge, the Aeron driver files)')
    build_b: Path = _setting('MK_BUILD_B', 'the directory holding build B')
    nc_dir: Path = _setting('MK_NC_DIR', 'the test-config build holding the nc targets')
    b_source_sha: str = None                                   # required for the A05 kinds
    norelease_source_sha: str = CT_A_SOURCE_SHA                # the nc build of ct 2be3a19
    noepoch_source_sha: str = None                             # defaults to b_source_sha
    driver_properties: Path = _setting('MK_DRIVER_PROPERTIES', "the ME tree's deploy/media-driver/driver.properties")
    driver_properties_sha256: str = DP_SHA256
    jars: dict = field(default_factory=_jars)
    probe_manifest: Path = _setting('MK_PROBE_MANIFEST', 'the probe-manifest.json written by build_core_probes.py')
    netfilter_helper: Path = _setting('MK_NETFILTER_HELPER', 'the netfilter helper directory (iptables-legacy, extensions)')
    image: str = 'sha256:15c422d674673e5c017eb5c7e8b33abb01fab14c92654a24a04a8432f99d19b8'
    harness_commit: str = None                                 # None: read from the tools checkout this file lives in
    harness_dirty: bool = None
    octet: int = 216
    pg_port: int = 55481
    seed: int = SEED
    cut_nc_dir: Path = _setting('MK_CUT_NC_DIR', "the test-config build of the cut's cluster-tools commit (nc targets)")
    shm_mb: dict = field(default_factory=dict)                 # per-role overrides of SHM_MB (settings)
    harness_drift: str = None                                  # A named waiver (rig kinds only), recorded
    memory_mb: dict = field(default_factory=dict)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _need(path, what):
    path = Path(path)
    if not path.is_file():
        raise Violation(f'{what} is not built or not staged: {path}')
    return path


def _lib(path, exec_=False):
    entry = {'path': str(path), 'sha256': sha(path)}
    if exec_:
        entry['exec'] = True
    return entry


def _driver_libs(cfg):
    return {'aeronmd': _lib(_need(cfg.bin_a / 'aeronmd', 'aeronmd'), True),
            'libaeron_driver.so': _lib(_need(cfg.bin_a / 'libaeron_driver.so', 'libaeron_driver.so')),
            'libaeron.so': _lib(_need(cfg.bin_a / 'libaeron.so', 'libaeron.so'))}


def _source(value, what):
    if not re.fullmatch(r'[0-9a-f]{40}', value or ''):
        raise Violation(f'{what} needs a 40-hex source_sha (a staged build names the commit it was built from), got {value!r}')
    return value


def _binary(cfg, source, role, driver):
    """One slot artifact: build A (bin_a), build B (build_b/app/<role>/) or a negative target (nc_dir/app/<role>/<target>)."""
    sub = 'forwarder' if role.startswith('forwarder') else 'bridge'
    if source == 'A':
        path, src, target = cfg.bin_a / f'ct-{sub}', CT_A_SOURCE_SHA, f'ct-{sub}'
    elif source == 'B':
        path, src, target = cfg.build_b / 'app' / sub / f'ct-{sub}', _source(cfg.b_source_sha, role + ' (build B)'), f'ct-{sub}'
    else:
        target = source
        path = cfg.nc_dir / 'app' / sub / target
        src = cfg.norelease_source_sha if target == 'ct_forwarder_nc_norelease' else (cfg.noepoch_source_sha or cfg.b_source_sha)
        _source(src, f'{role} ({target})')
    _need(path, f'{role} {target}')
    return {'path': str(path), 'sha256': sha(path), 'source_sha': src, 'driver': driver, 'target': target,
            'libs': _driver_libs(cfg)}


def _engine_libs(cfg):
    if sha(_need(cfg.driver_properties, 'driver.properties')) != cfg.driver_properties_sha256:
        raise Violation(f'driver.properties is not the pinned c53dd20 copy ({cfg.driver_properties})')
    staged = Path(cfg.runs) / 'bin-s16'
    staged.mkdir(parents=True, exist_ok=True)
    props, overlay = staged / 'driver.properties', staged / 'driver-dev.properties'
    props.write_bytes(Path(cfg.driver_properties).read_bytes())
    overlay.write_text(DEV_OVERLAY)
    core_contracts.check_driver_properties(props.read_text(), overlay.read_text())
    return {**_driver_libs(cfg), 'driver.properties': _lib(props), 'driver-dev.properties': _lib(overlay)}


def _harness(cfg):
    if cfg.harness_commit is not None:
        return cfg.harness_commit, bool(cfg.harness_dirty)
    here = Path(__file__).resolve().parent
    head = subprocess.run(['git', '-C', str(here), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(['git', '-C', str(here), 'status', '--porcelain'], capture_output=True, text=True,
                                check=True).stdout.strip())
    return head, dirty


def build(kind, tag, cfg=None):
    """Write ``<runs>/manifests/<kind>--<tag>.json``; returns (path, manifest)."""
    cfg = cfg or Config()
    if kind not in KINDS:
        raise Violation('unknown kind ' + kind + '; kinds: ' + ', '.join(sorted(KINDS)))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', tag) or '--' in tag:
        raise Violation('a tag is a short name without "--"')
    slot_driver, engine_driver, slot_plan, sources = KINDS[kind]
    roles = sorted(core_contracts.ROLES)
    rid = 'rc2-' + secrets.token_hex(6)
    out_dir = Path(cfg.runs) / 'manifests'
    out = out_dir / f'{kind}--{tag}.json'
    commit, dirty = _harness(cfg)
    probes = json.loads(Path(cfg.probe_manifest).read_text())
    helper = Path(cfg.netfilter_helper)
    artifacts = {name: None for name in core_contracts.OPTIONAL_BINARIES}
    artifacts['forwarder'] = _binary(cfg, 'A', 'forwarder', slot_driver)
    artifacts['bridge'] = _binary(cfg, 'A', 'bridge', slot_driver)
    for name, source in sources.items():
        artifacts[name] = None if source is None else _binary(cfg, source, name, slot_driver)
    for role, (path, src) in cfg.jars.items():
        artifacts[role] = {'path': str(_need(path, role + ' jar')), 'sha256': sha(path), 'source_sha': _source(src, role)}
    m = {
        'schema_version': 2, 'topology': 'core', 'run_id': rid, 'timeouts': 'production', 'image': cfg.image,
        'state_root': str(out_dir / 'fixtures' / rid), 'failure_domain': 'single_host_process_loss',
        'host_loss_acceptance': 'NOT_RUN_REQUIRES_SEPARATE_HOSTS',
        'network': {'subnet': f'172.30.{cfg.octet}.0/24', 'internal': True},
        'nodes': {role: f'172.30.{cfg.octet}.{10 + i}' for i, role in enumerate(roles)},
        'ports': dict(core_contracts.PORT_PROFILE), 'seed': cfg.seed, 'cpu_set': list(range(10)),
        'limits': {'shm_mb': 1024, 'memory_mb': 2048, 'disk_min_free_mb': 20480,
                   'cpu_set_by_role': json.loads(json.dumps(CPU_SET_BY_ROLE)), 'cpu_quota_by_role': dict(CPU_QUOTA_BY_ROLE),
                   'shm_mb_by_role': {**SHM_MB, **cfg.shm_mb}, 'memory_mb_by_role': {**MEMORY_MB, **cfg.memory_mb}},
        'artifacts': artifacts,
        'slot_artifacts': {**SLOTS[slot_plan], 'shadow0': None},
        'credentials': {'ae': dict(core_contracts.AE_CREDENTIAL_ENV),
                        'me': {'mode': 'enforced', 'keys_env': 'ME_AUTH_KEYS', 'credential_env': 'ME_AUTH_CREDENTIAL'}},
        'me_journal_profile': 'me-journal-4', 'postgres_bin': '/usr/lib/postgresql/16/bin', 'postgres_port': cfg.pg_port,
        'probe_libs': _driver_libs(cfg),
        'netfilter_helper': {'path': str(helper), 'files': {str(p.relative_to(helper)): {'sha256': sha(p)}
                                                            for p in sorted(helper.rglob('*')) if p.is_file()}},
        'manifest_kind': kind, 'harness_commit': commit, 'harness_dirty': dirty,
        'profile_note': (f'{kind}: production timeouts; pinned cpu plan; C++ slots {slot_driver}, engines '
                         f'{engine_driver}; build A ct {CT_A_SOURCE_SHA[:7]}; shm/memory sizes are settings with '
                         'defaults, not acceptance limits'),
    }
    for key in ('core_probe', 'journal_probe', 't1_me_driver', 't1_core_driver'):
        m[key] = {k: probes[key][k] for k in ('path', 'sha256', 'source_path', 'source_sha256')}
    if engine_driver == 'external':
        m['engine_driver'] = 'external'
        m['engine_libs'] = _engine_libs(cfg)
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(m, indent=1) + '\n')
    return out, m


# ------------------------------------------------------------------ the s17 kinds, derived from the cut

# kind -> (slot driver, engine/projector driver, slot base build, slot plan, second builds); CUT = the cut manifest's ct
# binaries, A = build A (ct 2be3a19, the upgrade_from of the A05 rows, pinned in the old-artifact pins)
CUT_KINDS = {
    's17': ('external', 'embedded', 'CUT', 'A', {}),
    's17-ext': ('external', 'external', 'CUT', 'A', {}),
    's17-embedded': ('embedded', 'embedded', 'CUT', 'A', {}),
    's17-n1': ('external', 'embedded', 'CUT', 'N1', {}),
    's17-xver': ('external', 'embedded', 'CUT', 'A', {}),
    's17-xver-ext': ('external', 'external', 'CUT', 'A', {}),
    's17-act': ('external', 'external', 'CUT', 'A', {}),
    's17-rollback': ('external', 'external', 'CUT', 'A', {}),
    's17-a05': ('external', 'embedded', 'A', 'A', {'forwarder_b': 'CUT', 'bridge_b': 'CUT'}),
    's17-a05-embedded': ('embedded', 'embedded', 'A', 'A', {'forwarder_b': 'CUT', 'bridge_b': 'CUT'}),
    's17-a05-keep': ('external', 'embedded', 'A', 'A', {'forwarder_b': 'CUT', 'bridge_b': 'CUT'}),
    's17-a05-reverse': ('external', 'embedded', 'CUT', 'A', {'forwarder_b': 'A', 'bridge_b': 'A'}),
    's17-ctl-edk-cnctimeout': ('external', 'external', 'CUT', 'A', {}),
    # the negative kinds stage nc targets of a TEST-config build of the cut's cluster-tools commit (cut_nc_dir), never a product
    's17-a03': ('external', 'embedded', 'CUT', 'A03', {'forwarder_b': 'ct_forwarder_nc_norelease'}),
    's17-a03-embedded': ('embedded', 'embedded', 'CUT', 'A03', {'forwarder_b': 'ct_forwarder_nc_norelease'}),
    's17-red-a03': ('external', 'embedded', 'CUT', 'REDA03', {'forwarder_b': 'ct_forwarder_nc_norelease', 'forwarder': None}),
    's17-red-a04': ('external', 'external', 'CUT', 'REDA04', {'bridge_b': 'ct_bridge_nc_noepoch', 'bridge': None}),
    # RED-1 (forwarder without RESYNC) and RED-2 (legacy bridge) on the cut
    's17-red1': ('external', 'embedded', 'CUT', 'REDA03', {'forwarder_b': 'ct_forwarder_nc_noresync', 'forwarder': None}),
    's17-red2': ('external', 'embedded', 'CUT', 'REDA04', {'bridge_b': 'ct_bridge_nc_legacy', 'bridge': None}),
}
CUT_ROLES = {'me': 'match-cluster.jar', 'ae': 'assets-cluster.jar', 'projector': 'assets-projector.jar'}
CUT_HARNESS = {'core_probe': 'core_probe', 'journal_probe': 'journal_probe', 't1_me_driver': 't1_me_driver',
               't1_core_driver': 't1_core_driver'}
PROBE_LIBS = {'aeronmd': 'probe_aeronmd', 'libaeron_driver.so': 'probe_libaeron_driver.so', 'libaeron.so': 'probe_libaeron.so'}


# The kinds that start the v1 engines on a seeded v0.5.0-beta state (and X-R, which
# restores the tag line on the same addresses) give the members the legacy fixture's addresses: me .10-.12, ae .13-.15.
LEGACY_LAYOUT_KINDS = {'s17-xver', 's17-xver-ext', 's17-rollback'}


def legacy_nodes(roles, octet):
    nodes = {f'me{i}': f'172.30.{octet}.{10 + i}' for i in range(3)}
    nodes.update({f'ae{i}': f'172.30.{octet}.{13 + i}' for i in range(3)})
    others = [r for r in roles if r not in nodes]
    nodes.update({r: f'172.30.{octet}.{20 + j}' for j, r in enumerate(others)})
    return nodes


def cut_class(kind):
    """The checker class of a derived kind: the xver kinds may stage old artifacts, every other s17 kind is a rig."""
    return 'rig-xver' if kind.startswith('s17-xver') or kind == 's17-rollback' else 'rig'


def _cut_lib(entry, exec_=False):
    lib = {'path': entry['path'], 'sha256': entry['sha256']}
    if exec_:
        lib['exec'] = True
    return lib


def build_from_cut(kind, tag, cut_path, cfg=None, old_pins=None):
    """``mk_manifests.py <s17 kind> <tag> --cut <cut>``: the fixture manifest of ``kind`` whose every staged byte comes from the
    cut manifest (or, for build A, from a pin of the old-artifact pins); written only when ``release_cut.check`` accepts it."""
    cfg = cfg or Config()
    if kind not in CUT_KINDS:
        raise Violation('unknown s17 kind ' + kind + '; kinds: ' + ', '.join(sorted(CUT_KINDS)))
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,40}', tag) or '--' in tag:
        raise Violation('a tag is a short name without "--"')
    cut = json.loads(Path(cut_path).read_text())
    pins = release_cut.load_old_pins(release_cut.old_pins_path()) if old_pins is None else old_pins
    slot_driver, engine_driver, base, slot_plan, seconds = CUT_KINDS[kind]
    a, harness = cut['artifacts'], cut['harness']
    cut_libs = {'aeronmd': _cut_lib(a['aeronmd'], True), 'libaeron_driver.so': _cut_lib(a['libaeron_driver.so']),
                'libaeron.so': _cut_lib(a['libaeron.so'])}

    def binary(source, role):
        sub = 'forwarder' if role.startswith('forwarder') else 'bridge'
        if source == 'CUT':
            e = a['ct-' + sub]
            return {'path': e['path'], 'sha256': e['sha256'], 'source_sha': e['source_sha'], 'driver': slot_driver,
                    'target': 'ct-' + sub, 'libs': json.loads(json.dumps(cut_libs))}
        if source.startswith('ct_'):          # a negative target of the cut's ct commit (the checker verifies the stamp, K4)
            path = _need(Path(cfg.cut_nc_dir) / 'app' / sub / source, f'{role} {source}')
            return {'path': str(path), 'sha256': sha(path), 'source_sha': cut['repos']['cluster-tools'], 'driver': slot_driver,
                    'target': source, 'libs': json.loads(json.dumps(cut_libs))}
        path = _need(cfg.bin_a / f'ct-{sub}', f'{role} build A')
        return {'path': str(path), 'sha256': sha(path), 'source_sha': CT_A_SOURCE_SHA, 'driver': slot_driver,
                'target': f'ct-{sub}', 'libs': _driver_libs(cfg)}

    roles = sorted(core_contracts.ROLES)
    rid = 'rc2-' + secrets.token_hex(6)
    out_dir = Path(cfg.runs) / 'manifests'
    out = out_dir / f'{kind}--{tag}.json'
    commit, dirty = _harness(cfg)
    artifacts = {name: None for name in core_contracts.OPTIONAL_BINARIES}
    artifacts['forwarder'] = binary(base, 'forwarder')
    artifacts['bridge'] = binary(base, 'bridge')
    for name, source in seconds.items():
        artifacts[name] = None if source is None else binary(source, name)
    for role, name in CUT_ROLES.items():
        artifacts[role] = {k: a[name][k] for k in ('path', 'sha256', 'source_sha')}
    helper = Path(cfg.netfilter_helper)
    m = {
        'schema_version': 2, 'topology': 'core', 'run_id': rid, 'timeouts': 'production', 'image': cfg.image,
        'state_root': str(out_dir / 'fixtures' / rid), 'failure_domain': 'single_host_process_loss',
        'host_loss_acceptance': 'NOT_RUN_REQUIRES_SEPARATE_HOSTS',
        'network': {'subnet': f'172.30.{cfg.octet}.0/24', 'internal': True},
        'nodes': {role: f'172.30.{cfg.octet}.{10 + i}' for i, role in enumerate(roles)},
        'ports': dict(core_contracts.PORT_PROFILE), 'seed': cfg.seed, 'cpu_set': list(range(10)),
        'limits': {'shm_mb': 1024, 'memory_mb': 2048, 'disk_min_free_mb': 20480,
                   'cpu_set_by_role': json.loads(json.dumps(CPU_SET_BY_ROLE)), 'cpu_quota_by_role': dict(CPU_QUOTA_BY_ROLE),
                   'shm_mb_by_role': {**SHM_MB, **cfg.shm_mb}, 'memory_mb_by_role': {**MEMORY_MB, **cfg.memory_mb}},
        'artifacts': artifacts,
        'slot_artifacts': {**SLOTS[slot_plan], 'shadow0': None},
        'credentials': {'ae': dict(core_contracts.AE_CREDENTIAL_ENV),
                        'me': {'mode': 'enforced', 'keys_env': 'ME_AUTH_KEYS', 'credential_env': 'ME_AUTH_CREDENTIAL'}},
        'me_journal_profile': 'me-journal-4', 'postgres_bin': '/usr/lib/postgresql/16/bin', 'postgres_port': cfg.pg_port,
        'probe_libs': {lib: _cut_lib(harness[key], lib == 'aeronmd') for lib, key in PROBE_LIBS.items()},
        'netfilter_helper': {'path': str(helper), 'files': {str(p.relative_to(helper)): {'sha256': sha(p)}
                                                            for p in sorted(helper.rglob('*')) if p.is_file()}},
        'manifest_kind': kind, 'harness_commit': commit, 'harness_dirty': dirty,
        'profile_note': (f'{kind} from cut {cut.get("cut_id")}: production timeouts; pinned cpu plan; C++ slots '
                         f'{slot_driver} on {"build A ct " + CT_A_SOURCE_SHA[:7] if base == "A" else "the cut"}, engines and '
                         f'projector {engine_driver}; shm/memory sizes are settings, not acceptance limits'),
        'projector_driver': engine_driver,
    }
    if cfg.harness_drift:
        m['harness_drift'] = {'reason': cfg.harness_drift, 'cut_harness_commit': cut.get('harness_commit'),
                              'harness_commit': commit, 'harness_dirty': dirty}
    if kind in LEGACY_LAYOUT_KINDS:
        m['nodes'] = legacy_nodes(roles, cfg.octet)
        m['node_layout'] = 'legacy'
    for key, name in CUT_HARNESS.items():
        e = harness[name]
        m[key] = {'path': e['path'], 'sha256': e['sha256'], 'source_path': e['source_path'], 'source_sha256': e['source_sha256']}
    if engine_driver == 'external':
        m['engine_driver'] = 'external'
        libs = _engine_libs(cfg)
        libs.update(json.loads(json.dumps(cut_libs)))           # the cut's aeronmd under the pinned driver.properties
        m['engine_libs'] = libs
        m['projector_libs'] = json.loads(json.dumps(libs))
    findings = release_cut.check(m, cut, cut_class(kind), old_pins=pins)
    if findings.items:
        raise Violation(f'{kind}: the cut checker refuses the derived manifest: '
                        + '; '.join(f'{rule} {text}' for rule, text in findings.items))
    out_dir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(m, indent=1) + '\n')
    return out, m


def _sizes(pairs):
    sizes = {}
    for pair in pairs or []:
        role, _, value = pair.partition('=')
        if role not in core_contracts.ROLES or not value.isdigit():
            raise SystemExit('a size override is ROLE=MB, got ' + pair)
        sizes[role] = int(value)
    return sizes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('kind', choices=sorted(set(KINDS) | set(CUT_KINDS))); parser.add_argument('tag')
    parser.add_argument('--cut', type=Path, help='derive an s17 kind from this cut manifest')
    parser.add_argument('--b-source-sha'); parser.add_argument('--build-b', type=Path)
    parser.add_argument('--octet', type=int); parser.add_argument('--pg-port', type=int)
    parser.add_argument('--shm', action='append'); parser.add_argument('--memory', action='append')
    parser.add_argument('--harness-drift', metavar='REASON', help='run a rig kind on a harness other than the '
                        'cut\'s (recorded with this reason; never a product or nightly manifest)')
    parser.add_argument('--runs', type=Path, help='the runs root (default $MK_RUNS)')
    args = parser.parse_args(argv)
    cfg = Config(shm_mb=_sizes(args.shm), memory_mb=_sizes(args.memory), harness_drift=args.harness_drift)

    for key, value in (('b_source_sha', args.b_source_sha), ('build_b', args.build_b), ('octet', args.octet),
                       ('pg_port', args.pg_port), ('runs', args.runs)):
        if value is not None:
            setattr(cfg, key, value)
    if args.kind in CUT_KINDS:
        if args.cut is None:
            raise SystemExit(f'{args.kind} is derived from the cut: --cut <rc2-cut-manifest.json>')
        out, _ = build_from_cut(args.kind, args.tag, args.cut, cfg)
    elif args.cut is not None:
        raise SystemExit(f'--cut derives the s17 kinds only; {args.kind} is a base kind')
    else:
        out, _ = build(args.kind, args.tag, cfg)
    print(out)


if __name__ == '__main__':
    sys.exit(main())
