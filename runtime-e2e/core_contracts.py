# SPDX-License-Identifier: Apache-2.0
"""Manifest schema v2: the core topology.

The legacy schema v1 (OMS order entry, PostgreSQL order truth) stays in contracts.py for the frozen
v0.5 scenarios. v2 is the OMS + ledger core: ME x3, AE x3, two forwarder slots, two bridge slots, the
money projector, a reserved shadow replica slot and the probe. Slots whose product does not exist
yet (C++ forwarder and bridge, the shadow replica) declare ``null`` and are skipped, never faked.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

from contracts import Inconclusive, Violation, integer
import journal_decode

ENGINES = [e + str(i) for e in ('me', 'ae') for i in range(3)]
SLOTS = {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge', 'shadow0': 'shadow'}
ROLES = set(ENGINES) | set(SLOTS) | {'projector', 'probe'}
LEGACY_ROLES = {'oms', 'market', 'bridge', 'xprojector'}
REQUIRED_JARS = ['ae', 'me', 'projector']
OPTIONAL_BINARIES = ['forwarder', 'forwarder_b', 'bridge', 'bridge_b', 'shadow']
SLOT_ARTIFACTS = {'fwd0': {'forwarder', 'forwarder_b'}, 'fwd1': {'forwarder', 'forwarder_b'},
                  'bridge0': {'bridge', 'bridge_b'}, 'bridge1': {'bridge', 'bridge_b'}, 'shadow0': {'shadow'}}
PORT_PROFILE = {'me_base': 9000, 'ae_base': 19300, 'stride': 100, 'me_metrics': 19500, 'ae_metrics': 19700,
                'bridge_http': 9600, 'projector_http': 9601, 'forwarder_http': 9700, 'journal_replay': 19820}
AE_CREDENTIAL_ENV = {'keys_env': 'CORE_AUTH_KEYS', 'credential_env': 'CORE_AUTH_CREDENTIAL'}
# The environment names retired by the rename of the engine to core, old to new (the core's RetiredSettings table for the
# names this harness sets, plus the probe's own). A fixture that still sets one was written for the old names: it is
# refused naming the new one, never passed on and never translated.
RETIRED_ENV = {'ASSETS_NODE_PORT': 'CORE_NODE_PORT', 'ASSETS_AUTH_KEYS': 'CORE_AUTH_KEYS',
               'AE_AUTH_CREDENTIAL': 'CORE_AUTH_CREDENTIAL', 'BRIDGE_AE_CLUSTER_ADDRESSES': 'BRIDGE_CORE_CLUSTER_ADDRESSES',
               'BRIDGE_AE_PORT_BASE': 'BRIDGE_CORE_PORT_BASE', 'BRIDGE_AE_EGRESS_ENDPOINT': 'BRIDGE_CORE_EGRESS_ENDPOINT',
               'PROJECTOR_AE_JOURNAL_ARCHIVES': 'PROJECTOR_CORE_JOURNAL_ARCHIVES', 'CORE_AE_ADDRESSES': 'CORE_ADDRESSES',
               'CORE_AE_PORT_BASE': 'CORE_PORT_BASE'}


def retired_env_refusal(name):
    """The refusal line for a retired environment name, or None when the name is not retired."""
    if name not in RETIRED_ENV:
        return None
    return (f'the environment variable {name} is retired; it is now {RETIRED_ENV[name]} '
            '(rename the setting; the old name is never read)')

ME_AUTH_MODES = {'enforced', 'not_enforced_by_artifact'}
# The drills are about elections, so the fixture keeps every production timeout. Everything is an
# allowlist: the manifest's top-level keys, the environment names a fixture process may receive, and
# the environment the pinned image itself carries. Anything else is refused, never filtered.
MANIFEST_KEYS = {'schema_version', 'topology', 'run_id', 'timeouts', 'image', 'state_root', 'failure_domain',
                 'network', 'nodes', 'ports', 'seed', 'cpu_set', 'limits', 'artifacts', 'slot_artifacts', 'core_probe',
                 'journal_probe', 'credentials', 'me_journal_profile', 'postgres_bin', 'postgres_port'}
OPTIONAL_MANIFEST_KEYS = {'netfilter_helper', 'host_loss_acceptance', 'profile_note', 'measurement_purpose',
                          'harness_commit', 'harness_dirty',
                          # The probe's own aeronmd and the two T1 drivers, hash-pinned
                          'probe_libs', 't1_me_driver', 't1_core_driver',
                          # The engines' driver profile and its staged driver; the builder's kind
                          'engine_driver', 'engine_libs', 'manifest_kind',
                          # The money projector's driver profile and its staged driver
                          'projector_driver', 'projector_libs', 'node_layout',
                          # A rig manifest's named waiver of the harness pin (smokes before a cut regeneration)
                          'harness_drift'}
DRIVER_MODES = {'embedded', 'external'}
LIB_KEYS = {'path', 'sha256', 'exec'}
# Pinned single-file helper programs, checked like core_probe / journal_probe (path + source_path hashes).
PINNED_PROGRAMS = ['core_probe', 'journal_probe']
OPTIONAL_PROGRAMS = ['t1_me_driver', 't1_core_driver']
# Names the fixture itself sets (core_fixture: ENGINE_COMMON, engine_env, projector, slot_env, probe_env).
PROCESS_ENV = {
    'CLUSTER_PORT_STRIDE', 'BASE_DIR', 'TRANSPORT_DRIVER_MODE', 'TRANSPORT_IDLE_MODE', 'TRANSPORT_TERM_LENGTH',
    'TRANSPORT_LOG_TERM_LENGTH', 'TRANSPORT_SNAPSHOT_TERM_LENGTH', 'MATCH_ENGINE_BOOK_CAPACITY', 'SNAPSHOT_LOG_BYTES',
    'SNAPSHOT_INTERVAL_MINUTES', 'CLUSTER_NODE', 'CLUSTER_ADDRESSES', 'CLUSTER_PORT_BASE', 'METRICS_PORT',
    'SETTLEMENT_JOURNAL_ENABLED', 'SETTLEMENT_JOURNAL_DIR', 'SETTLEMENT_JOURNAL_ARCHIVE_BIND', 'CORE_NODE_PORT',
    'CORE_AUTH_KEYS', 'CORE_AUTH_CREDENTIAL',
    # The ME builds its engine config from the replicated EngineConfig record, not from env knobs (RUN:158)
    'MATCH_ENGINE_FROM_CONFIG',
    'PROJECTOR_POSTGRES_URL', 'PROJECTOR_POSTGRES_USER', 'PROJECTOR_POSTGRES_PASSWORD', 'PROJECTOR_CORE_JOURNAL_ARCHIVES',
    'PROJECTOR_LOCAL_HOST', 'PROJECTOR_METRICS_PORT',
    # Assets c68d163 ProjectorDriver (PROJECTOR_DRIVER_MODE embedded|external, strict; external reads AERON_DIR)
    'PROJECTOR_DRIVER_MODE',
    # ct-forwarder strict env (FC:156-265). ME_AUTH_CREDENTIAL is NOT here: a manifest's credentials.me names reach
    # processes through allowed_env() (validate_core_manifest refuses a credentials.me name that is in this set).
    'FWD_CORE_INGRESS', 'FWD_CORE_RESPONSE_CHANNEL', 'FWD_ME_INGRESS', 'FWD_ME_RESPONSE_CHANNEL', 'FWD_INGRESS_CHANNEL',
    'FWD_DRIVER_MODE', 'FWD_DRIVER_DIR', 'FWD_DRIVER_TIMEOUT_MS', 'FWD_INSTANCE_ID', 'FWD_HTTP_BIND', 'AERON_DIR',
    # ct-bridge strict env (BC:42-55, 235-327)
    'BRIDGE_ME_JOURNAL_ARCHIVES', 'BRIDGE_JOURNAL_CONTROL_STREAM', 'BRIDGE_JOURNAL_STREAM', 'BRIDGE_JOURNAL_CHANNEL',
    'BRIDGE_REPLAY_STREAM', 'BRIDGE_JOURNAL_MTU', 'BRIDGE_LOCAL_HOST', 'BRIDGE_DRIVER_MODE', 'BRIDGE_DRIVER_DIR',
    'BRIDGE_DRIVER_TIMEOUT_MS', 'BRIDGE_CORE_CLUSTER_ADDRESSES', 'BRIDGE_CORE_PORT_BASE', 'BRIDGE_CORE_EGRESS_ENDPOINT',
    'BRIDGE_INSTANCE_ID', 'BRIDGE_HTTP_BIND',
    # the staged aeronmd: deleted on start and shutdown so a restart never attaches to a dead driver
    'AERON_DIR_DELETE_ON_START', 'AERON_DIR_DELETE_ON_SHUTDOWN', 'LD_LIBRARY_PATH',
    'CORE_ADDRESSES', 'CORE_PORT_BASE', 'CORE_LOCAL_HOST'}
# Only `execute` on the probe container may carry these (the pinned T1 drivers). The values are
# session secrets except T1_ME_MARKETS and T1_LOCAL_HOST. T1_BRIDGE_KEY, T1_TAP_KEY and T1_ME_FORWARDER_KEY are
# never set: the via-bridge genesis needs no bridge key and the capture/resend verbs are not run from the probe.
PROBE_ENV = {'T1_ADMIN_KEY', 'T1_TOOL_KEY', 'T1_GATEWAY_KEY', 'T1_ME_ADMIN_KEY', 'T1_ME_MARKETS', 'T1_LOCAL_HOST'}
# The two names the C++ binaries require (no default, DT:28-35) and the one value the fixture
# passes. It is the client's liveness bound on its own media driver, not an election, heartbeat or session timeout.
DRIVER_TIMEOUT_EXEMPT = {'FWD_DRIVER_TIMEOUT_MS': '5000', 'BRIDGE_DRIVER_TIMEOUT_MS': '5000'}
IMAGE_ENV = {'PATH', 'JAVA_HOME', 'JAVA_VERSION', 'LANG', 'LANGUAGE', 'LC_ALL', 'HOME', 'TZ'}
TIMEOUT_WORDS = re.compile(r'TIMEOUT|HEARTBEAT|ELECTION|LIVENESS', re.IGNORECASE)
JVM_TIMEOUT = re.compile(r'-D\S*(timeout|heartbeat|election|liveness)', re.IGNORECASE)

# The engine container's staged driver. driver.properties is a byte copy of me/deploy/media-driver/driver.properties
# (c53dd20) and driver-dev.properties the overlay the launch-driver.sh dev profile applies (LD:19-20, SHARED threading and
# backoff idles: the engine member has one CPU). Nothing else, nothing missing.
ENGINE_LIBS = {'aeronmd', 'libaeron_driver.so', 'libaeron.so', 'driver.properties', 'driver-dev.properties'}
# The embedded driver overrides the external driver must equal (MEC:221-236, ME AeronCluster.launchWithEmbeddedDriver; the AE
# context AEC:205-214 sets the same values except the two untethered timeouts, which only the ME codes). driverTimeoutMs(500)
# is a client setting and has no driver counterpart. sparse.file=false is DP's own pin.
ENGINE_DRIVER_PROPERTIES = {
    'aeron.mtu.length': '8192', 'aeron.term.buffer.length': '16m', 'aeron.ipc.term.buffer.length': '16m',
    'aeron.term.buffer.sparse.file': 'false', 'aeron.socket.so_sndbuf': '4m', 'aeron.socket.so_rcvbuf': '4m',
    'aeron.rcv.initial.window.length': '4m', 'aeron.timer.interval': '500us', 'aeron.client.liveness.timeout': '5s',
    'aeron.publication.unblock.timeout': '10s', 'aeron.untethered.window.limit.timeout': '100ms',
    'aeron.untethered.resting.timeout': '100ms'}
DEV_OVERLAY_KEYS = {'aeron.threading.mode', 'aeron.conductor.idle.strategy', 'aeron.sender.idle.strategy',
                    'aeron.receiver.idle.strategy', 'aeron.shared.idle.strategy', 'aeron.sharednetwork.idle.strategy'}
# The eleven base manifests (mk_manifests.py). The kind is pinned in the manifest and is the file name's prefix
# ("<kind>--<tag>.json"), so a guard keyed on it cannot be satisfied by renaming a file.
BASE_KINDS = {'s16', 's16-ext', 's16-embedded', 's16-n1', 's16-a03', 's16-a03-embedded', 's16-a05', 's16-a05-embedded',
             's16-red-a03', 's16-red-a04', 's16-ctl-edk-cnctimeout'}
# The s17 kinds, derived from the cut manifest by ``mk_manifests.py --cut``. The RED and A03 kinds
# stage negative targets of a test-config build of the cut's cluster-tools commit.
CUT_KINDS = {'s17', 's17-ext', 's17-embedded', 's17-n1', 's17-xver', 's17-xver-ext', 's17-act', 's17-rollback', 's17-a05',
             's17-a05-embedded', 's17-a05-keep', 's17-a05-reverse', 's17-ctl-edk-cnctimeout',
             's17-a03', 's17-a03-embedded', 's17-red-a03', 's17-red-a04', 's17-red1', 's17-red2'}
KINDS = BASE_KINDS | CUT_KINDS
EDK_CNCTIMEOUT_KIND = 's16-ctl-edk-cnctimeout'
EDK_CNCTIMEOUT_KINDS = {EDK_CNCTIMEOUT_KIND, 's17-ctl-edk-cnctimeout'}
ENGINE_DRIVER_SKIP_MEMBERS = ('ae0', 'me0')          # cnc_timeout_loud: one AE member and one ME member
NC_TARGET = re.compile(r'ct_(forwarder|bridge)_nc_[a-z0-9_]+')
CMAKE_TARGET = re.compile(r'[A-Za-z0-9_.-]{1,64}')
A03_NC_TARGET = 'ct_forwarder_nc_norelease'           # A03 phase 1 only
# Build A (ct 2be3a19, pinned in the old-artifact pins) predates the
# /health "build" field: its /health format strings have no "build" key (the cut's ct-forwarder/ct-bridge end in
# ``"build":"%s"``). Its identity is its pinned sha256 alone. Keyed by those exact bytes, so no other binary may omit the field.
HEALTH_BUILD_ABSENT = {
    '75baf2994c0b898fc4fadd6cbe889b3cc189acc3ed9d0be9b0d03fa15ff513c4': 'ct-2be3a19/ct-forwarder',
    'c6e68edc2d7bc0cde3b95c449e476cf945e1869b2a6dd85392d951fcd6eca88a': 'ct-2be3a19/ct-bridge',
}


def health_build_expected(entry):
    """What ``/health.build`` of a slot binary answers: None for a pinned build without the field (HEALTH_BUILD_ABSENT, by
    sha256), else the artifact's ``source_sha`` (absent: None, which then never equals a reported build)."""
    entry = entry or {}
    if entry.get('sha256') in HEALTH_BUILD_ABSENT:
        return None
    return entry.get('source_sha')


# A dated exception to "negative builds never share a manifest with build B": the A03 kinds of the base set and
# of the cut (mk_manifests KINDS / CUT_KINDS, slot plan A03). The runner keyed it on 's16-a03'.
A03_KINDS = {'s16-a03', 's16-a03-embedded', 's17-a03', 's17-a03-embedded'}


def a03_phase1_declared(manifest):
    """True when ``manifest`` declares the A03 phase-1 swap and nothing more: an A03 kind, both forwarder
    slots on ``forwarder_b`` = ``ct_forwarder_nc_norelease``, build A (a real build) staged as ``forwarder`` for the
    ``replace_slot`` swap, both bridges on ``bridge`` and no ``bridge_b``."""
    if manifest.get('manifest_kind') not in A03_KINDS:
        return False
    art, slots = manifest.get('artifacts') or {}, manifest.get('slot_artifacts') or {}
    swap_to = art.get('forwarder') or {}
    return (slots.get('fwd0') == 'forwarder_b' and slots.get('fwd1') == 'forwarder_b'
            and (art.get('forwarder_b') or {}).get('target') == A03_NC_TARGET
            and bool(swap_to) and not NC_TARGET.fullmatch(str(swap_to.get('target') or ''))
            and art.get('bridge_b') is None and slots.get('bridge0') == 'bridge' and slots.get('bridge1') == 'bridge')


def _file(entry, what, keys=('path', 'sha256')):
    file = Path(entry['path'])
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise Inconclusive('missing/untrusted artifact path: ' + what)
    with file.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != entry[keys[1]]:
        raise Violation('artifact digest mismatch: ' + what)


def _lib(entry, what, changed=None):
    """A staged library: path + sha256, optional boolean exec flag, nothing else."""
    if not isinstance(entry, dict) or set(entry) - LIB_KEYS or not {'path', 'sha256'} <= set(entry):
        raise Violation(what + ': library key set is path, sha256, exec; got ' + str(sorted(entry) if isinstance(entry, dict) else entry))
    if 'exec' in entry and type(entry['exec']) is not bool:
        raise Violation(what + ': library exec must be a boolean')
    try:
        _file(entry, what)
    except Violation:
        if changed:
            raise Violation(changed) from None
        raise


def _source(entry, what):
    if not re.fullmatch(r'[0-9a-f]{40}', entry.get('source_sha') or ''):
        raise Inconclusive('missing artifact source commit: ' + what)



_UNITS = {'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}
_TIME = {'ns': 1, 'us': 1000, 'ms': 1000 ** 2, 's': 1000 ** 3}


def aeron_value(text):
    """A property value as the Aeron drivers read it: sizes k/m/g (binary), durations ns/us/ms/s (to ns), else the text."""
    value = text.strip().lower()
    match = re.fullmatch(r'(\d+)(ns|us|ms|s)', value)
    if match:
        return ('ns', int(match.group(1)) * _TIME[match.group(2)])
    match = re.fullmatch(r'(\d+)([kmg]?)', value)
    if match:
        return ('n', int(match.group(1)) * _UNITS.get(match.group(2), 1))
    return ('text', value)


def parse_properties(text, what):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise Violation(f'{what}: not a key=value line: {line[:80]}')
        key, value = (part.strip() for part in line.split('=', 1))
        if key in values:
            raise Violation(f'{what}: {key} is set twice')
        values[key] = value
    return values


def check_driver_properties(properties_text, overlay_text):
    """The pinned external driver properties equal the embedded overrides (a drift is a Violation), and the dev
    overlay sets only threading and idle keys, SHARED threading, never a pinned value."""
    props = parse_properties(properties_text, 'driver.properties')
    drift = sorted(k for k, v in ENGINE_DRIVER_PROPERTIES.items() if k not in props or aeron_value(props[k]) != aeron_value(v))
    if drift:
        raise Violation('driver.properties drifts from the embedded overrides: ' + ', '.join(
            f'{k} {props.get(k, "<missing>")} != {ENGINE_DRIVER_PROPERTIES[k]}' for k in drift))
    overlay = parse_properties(overlay_text, 'driver-dev.properties')
    extra = sorted(set(overlay) - DEV_OVERLAY_KEYS)
    if extra:
        raise Violation('driver-dev.properties may set only threading and idle keys; refused ' + ', '.join(extra))
    if overlay.get('aeron.threading.mode') != 'SHARED':
        raise Violation('driver-dev.properties must set aeron.threading.mode=SHARED (the member has one CPU)')
    return props, overlay


def _validate_driver_block(manifest, mode_key, libs_key, who):
    mode = manifest.get(mode_key, 'embedded')
    if mode not in DRIVER_MODES:
        raise Violation(f'{mode_key} must be embedded or external, got ' + str(mode))
    libs = manifest.get(libs_key)
    if mode == 'embedded':
        if libs is not None:
            raise Violation(f'{libs_key} without {mode_key} external: {who} stage no driver')
        return
    if not libs:
        raise Violation(f'{mode_key} external needs {libs_key} (aeronmd, its two .so, driver.properties, the dev overlay)')
    if set(libs) != ENGINE_LIBS:
        raise Violation(f'{libs_key} must be exactly ' + ', '.join(sorted(ENGINE_LIBS)) + '; got ' + ', '.join(sorted(libs)))
    for name, lib in libs.items():
        _lib(lib, f'{libs_key} ' + name, changed=f'{libs_key} changed: ' + name)
        if (name == 'aeronmd') != (lib.get('exec') is True):
            raise Violation(f'{libs_key} aeronmd must be exec and nothing else may be: ' + name)
    check_driver_properties(Path(libs['driver.properties']['path']).read_text(),
                            Path(libs['driver-dev.properties']['path']).read_text())


def validate_engine_driver(manifest):
    _validate_driver_block(manifest, 'engine_driver', 'engine_libs', 'the embedded engines')


def validate_projector_driver(manifest):
    """The money projector's driver mode, the same rules as the engines' (an external projector
    stages the pinned aeronmd set and attaches to it at AERON_DIR; an embedded one stages nothing and never sets AERON_DIR)."""
    _validate_driver_block(manifest, 'projector_driver', 'projector_libs', 'an embedded projector')


def _target(manifest, name):
    entry = manifest['artifacts'].get(name)
    return None if entry is None else entry.get('target')


def validate_build_b(manifest, path):
    """Build B rules by manifest kind (kinded manifests carry ``manifest_kind``; older manifests have none and keep the old rules)."""
    for name in OPTIONAL_BINARIES:
        entry = manifest['artifacts'].get(name)
        if entry is not None and 'target' in entry and not CMAKE_TARGET.fullmatch(str(entry['target'])):
            raise Violation(f'{name}: target must be a CMake target name')
    kind = manifest.get('manifest_kind')
    if kind is None:
        return
    if kind not in KINDS:
        raise Violation('unknown manifest kind ' + str(kind))
    if Path(path).name.split('--')[0].removesuffix('.json') != kind:
        raise Violation(f'manifest kind {kind} does not match the file name {Path(path).name}')
    staged = [n for n in ('forwarder_b', 'bridge_b') if manifest['artifacts'].get(n) is not None]
    for name in staged + [n for n in ('forwarder', 'bridge') if manifest['artifacts'].get(n) is not None]:
        if _target(manifest, name) is None:
            raise Violation(f'{name} needs a pinned CMake target (artifacts.{name}.target, set by mk_manifests.py)')
    for name in ('forwarder', 'bridge'):
        if manifest['artifacts'].get(name) is not None and NC_TARGET.fullmatch(_target(manifest, name)):
            raise Violation(f'build A {name} must be a real build, got {_target(manifest, name)}')
    rest = kind.split('-', 1)[1] if '-' in kind else ''
    if rest.startswith('a05'):
        for name in staged:
            if NC_TARGET.fullmatch(_target(manifest, name)):
                raise Violation(f'an A05 manifest stages the negative build {_target(manifest, name)} as {name}: build B is a '
                                'real ct build')
    elif rest.startswith('red'):         # red-a03/red-a04, red1/red2
        for name in staged:
            if not NC_TARGET.fullmatch(_target(manifest, name)):
                raise Violation(f'a RED manifest stages the real build {_target(manifest, name)} as {name}')
    elif rest.startswith('a03'):
        if staged != ['forwarder_b'] or _target(manifest, 'forwarder_b') != A03_NC_TARGET or manifest['artifacts'].get('forwarder') is None:
            raise Violation(f'an A03 manifest stages {A03_NC_TARGET} as forwarder_b and build A as forwarder, nothing else '
                            '(the A03 drain is the forwarder swap)')
    elif staged:
        raise Violation(f'manifest kind {kind} stages no build B: ' + ', '.join(staged))


def check_build_b(manifest, scenario_name):
    """5.2 at the scenario: core-drill-a05-* refuses an nc_ target as build B, core-red-* refuses a real build as ``*_b``."""
    for name in ('forwarder_b', 'bridge_b'):
        entry = manifest['artifacts'].get(name)
        if entry is None:
            continue
        target = entry.get('target')
        if scenario_name.startswith('core-drill-a05-'):
            if target is None:
                raise Violation(f'{name} needs a pinned CMake target for an A05 drill')
            if NC_TARGET.fullmatch(target):
                raise Violation(f'an A05 drill refuses the negative build {target} as {name}')
        elif scenario_name.startswith('core-red-') and target is not None and not NC_TARGET.fullmatch(target):
            raise Violation(f'a RED runs a negative build; refused the real build {target} as {name}')


def check_engine_driver_skip(manifest, path, value):
    """ENGINE_DRIVER_SKIP=1 (the harness environment; the wrapper of the two members then starts no aeronmd) only on the
    edk-cnctimeout control manifest. Returns the members whose driver is skipped (empty when unset)."""
    if value is None or value == '':
        return ()
    kind = manifest.get('manifest_kind')
    if kind not in EDK_CNCTIMEOUT_KINDS or Path(path).name.split('--')[0].removesuffix('.json') != kind:
        raise Violation(f'ENGINE_DRIVER_SKIP is refused outside {EDK_CNCTIMEOUT_KIND}.json; manifest {Path(path).name}')
    if manifest.get('engine_driver') != 'external':
        raise Violation('ENGINE_DRIVER_SKIP needs engine_driver external')
    if value != '1':
        raise Violation('ENGINE_DRIVER_SKIP=1 only (it skips ' + ' and '.join(ENGINE_DRIVER_SKIP_MEMBERS) + ')')
    return ENGINE_DRIVER_SKIP_MEMBERS


def validate_cpus(manifest, cpu_count):
    limits = manifest['limits']
    cpu_set = manifest['cpu_set']
    if not isinstance(cpu_set, list) or not cpu_set or len(set(cpu_set)) != len(cpu_set):
        raise Violation('cpu_set must be an explicit list of distinct CPUs')
    by_role = limits.get('cpu_set_by_role', {})
    for role, cpus in by_role.items():
        if role not in ROLES:
            raise Violation('cpu set for an unknown role: ' + role)
        if (not isinstance(cpus, list) or not cpus or len(set(cpus)) != len(cpus)
                or any(type(c) is not int or c < 0 or c >= cpu_count for c in cpus)):
            raise Violation('invalid cpu set for ' + role)
    missing = [r for r in ENGINES if r not in by_role]
    if missing:
        raise Violation('every engine member must be pinned to its own cpuset: ' + ', '.join(missing))
    used = set()
    for role in ENGINES:
        cpus = set(by_role[role])
        if cpus & used:
            raise Violation('engine cpusets must be pairwise disjoint: ' + role)
        if not cpus <= set(cpu_set):
            raise Violation('engine cpuset outside the fixture cpu_set: ' + role)
        used |= cpus
    probe = set(by_role.get('probe', []))
    if not probe or probe & set(cpu_set):
        raise Violation('probe CPUs must be explicit and separate from service CPUs')
    for role, quota in limits.get('cpu_quota_by_role', {}).items():
        cpus = by_role.get(role, cpu_set)
        if role not in ROLES or type(quota) not in (int, float) or not 0 < quota <= len(cpus):
            raise Violation('invalid bounded CPU quota for ' + str(role))


def validate_role_limits(limits):
    """Optional per-role overrides of shm_mb / memory_mb (an ME member needs 1.5 GiB of tmpfs)."""
    for key in ('shm_mb_by_role', 'memory_mb_by_role'):
        for role, value in (limits.get(key) or {}).items():
            if role not in ROLES:
                raise Violation(key + ' names an unknown role: ' + str(role))
            if integer(value) <= 0:
                raise Violation(key + ' must be positive and explicit: ' + role)


def validate_core_manifest(manifest, manifest_path, cpu_count=None, profiles=journal_decode.PROFILES,
                           require_me_enforced=False):
    cpu_count = os.cpu_count() if cpu_count is None else cpu_count
    try:
        if manifest['schema_version'] != 2 or manifest.get('topology') != 'core':
            raise Violation('core manifest must be schema_version 2, topology core')
        if not re.fullmatch(r'rc2-[0-9a-f]{12}', manifest['run_id']):
            raise Violation('unknown core fixture identity')
        missing = MANIFEST_KEYS - set(manifest)
        if missing:
            raise Inconclusive('incomplete core manifest: ' + ', '.join(sorted(missing)))
        unknown = set(manifest) - MANIFEST_KEYS - OPTIONAL_MANIFEST_KEYS
        if unknown:
            raise Violation('manifest keys are an allowlist; refused ' + ', '.join(sorted(unknown)))
        if manifest['timeouts'] != 'production':
            raise Violation('the core fixture runs production election/heartbeat/session timeouts only')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', manifest['image']):
            raise Violation('runtime image must be immutable')
        path = Path(manifest_path).absolute()
        root = Path(manifest['state_root'])
        if root != path.parent / 'fixtures' / manifest['run_id'] or root.resolve() != root:
            raise Violation('state path escapes the manifest-owned fixture directory')
        if manifest['failure_domain'] != 'single_host_process_loss':
            raise Violation('single-host containers cannot prove host HA')
        net = ipaddress.ip_network(manifest['network']['subnet'])
        private = [ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
        # Archive control ports (AE and ME journal) are reachable only inside this internal network.
        if (net.version != 4 or net.prefixlen != 24 or not any(net.subnet_of(n) for n in private)
                or manifest['network']['internal'] is not True):
            raise Violation('fixture needs its own internal RFC1918 /24 network: no archive port leaves it')
        nodes = manifest['nodes']
        legacy = LEGACY_ROLES & set(nodes)
        if legacy:
            raise Violation('legacy roles are absent from the core topology: ' + ', '.join(sorted(legacy)))
        if set(nodes) != ROLES:
            raise Violation('core topology roles are exactly ' + ', '.join(sorted(ROLES)) + '; got '
                            + ', '.join(sorted(set(nodes) ^ ROLES)))
        if len(set(nodes.values())) != len(nodes):
            raise Violation('two roles share an address')
        for value in nodes.values():
            address = ipaddress.ip_address(value)
            if address not in net or address in {net.network_address, net.broadcast_address, net.network_address + 1}:
                raise Violation('endpoint is outside the fixture or collides with its gateway')
        if manifest['ports'] != PORT_PROFILE:
            raise Violation('core port profile differs from the fixture contract')
        for field in ['shm_mb', 'memory_mb', 'disk_min_free_mb']:
            if integer(manifest['limits'][field]) <= 0:
                raise Violation('resource limits must be positive and explicit')
        validate_role_limits(manifest['limits'])
        validate_cpus(manifest, cpu_count)
        integer(manifest['seed'])
        artifacts = manifest['artifacts']
        unknown = set(artifacts) - set(REQUIRED_JARS) - set(OPTIONAL_BINARIES)
        if unknown:
            raise Violation('unknown artifacts: ' + ', '.join(sorted(unknown)))
        for role in REQUIRED_JARS:
            if artifacts.get(role) is None:
                raise Inconclusive('missing required artifact: ' + role)
            _source(artifacts[role], role); _file(artifacts[role], role)
        for role in OPTIONAL_BINARIES:
            if role not in artifacts:
                raise Violation('optional slot artifact must be declared explicitly (null when absent): ' + role)
            entry = artifacts[role]
            if entry is None:
                continue
            _source(entry, role); _file(entry, role)
            if entry.get('driver') == 'java_media_driver':
                raise Violation('driver java_media_driver is retired: external means the staged aeronmd')
            if entry.get('driver') not in DRIVER_MODES:
                raise Violation(role + ': driver must be embedded or external')
            for name, lib in (entry.get('libs') or {}).items():
                if '/' in name:
                    raise Violation(role + ': library names are flat file names')
                _lib(lib, role + ' library ' + name)
        slots = manifest['slot_artifacts']
        if set(slots) != set(SLOTS):
            raise Violation('slot_artifacts must name every slot role: ' + ', '.join(sorted(SLOTS)))
        for slot, name in slots.items():
            if name is not None and name not in SLOT_ARTIFACTS[slot]:
                raise Violation(f'slot {slot} cannot run artifact {name}')
        for key in PINNED_PROGRAMS + [k for k in OPTIONAL_PROGRAMS if k in manifest]:
            helper = manifest[key]
            for path_key, digest_key in [('path', 'sha256'), ('source_path', 'source_sha256')]:
                file = Path(helper[path_key])
                if not file.is_absolute() or file.is_symlink() or not file.is_file():
                    raise Inconclusive('missing probe input: ' + key + ' ' + path_key)
                if hashlib.sha256(file.read_bytes()).hexdigest() != helper[digest_key]:
                    raise Violation('probe input changed: ' + key + ' ' + path_key)
        for name, lib in (manifest.get('probe_libs') or {}).items():
            if '/' in name:
                raise Violation('probe_libs: library names are flat file names')
            _lib(lib, 'probe_libs ' + name, changed='probe input changed: probe_libs ' + name)
        drivers = [k for k in ('t1_me_driver', 't1_core_driver') if k in manifest]
        if drivers and not (manifest.get('probe_libs') or {}).get('aeronmd'):
            # The T1 drivers attach to the probe's own aeronmd; without it the probe would idle and the
            # drivers fail at me_genesis with an opaque Aeron error, after every container started
            raise Violation(f'{" and ".join(drivers)} pinned without probe_libs.aeronmd: the T1 drivers need the probe\'s '
                            'staged media driver')
        credentials = manifest['credentials']
        if credentials.get('ae') != AE_CREDENTIAL_ENV:
            retired = [retired_env_refusal(v) for v in (credentials.get('ae') or {}).values() if v in RETIRED_ENV]
            raise Violation('core credentials must use CORE_AUTH_KEYS / CORE_AUTH_CREDENTIAL'
                            + (': ' + '; '.join(retired) if retired else ''))
        me = credentials.get('me') or {}
        if me.get('mode') not in ME_AUTH_MODES:
            raise Violation('ME credential mode must be declared: enforced | not_enforced_by_artifact')
        if require_me_enforced and me['mode'] != 'enforced':
            raise Violation('ME credential mode must be enforced for drills: an authenticating ME refuses a credential-less session')
        for key in ['keys_env', 'credential_env']:
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,63}', me.get(key) or ''):
                raise Violation('ME credential environment names must be explicit')
            if me[key] in PROCESS_ENV or me[key] in IMAGE_ENV or me[key] in RETIRED_ENV or TIMEOUT_WORDS.search(me[key]):
                raise Violation('ME credential environment name collides with a fixture variable: ' + me[key])
        if me['keys_env'] == me['credential_env']:
            raise Violation('ME key table and credential need distinct environment names')
        validate_engine_driver(manifest)
        validate_projector_driver(manifest)
        validate_build_b(manifest, path)
        profile = manifest['me_journal_profile']
        if profile not in journal_decode.profiles_spec(profiles):
            raise Violation('unknown ME journal profile ' + str(profile))
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, (Violation, Inconclusive)):
            raise
        raise Inconclusive('incomplete core manifest: ' + str(error)) from error


def assert_production_timeouts(environment, allowed=PROCESS_ENV):
    """Fixture-side guard: a process receives only allowlisted names, and no value carries a timeout."""
    for key, value in environment.items():
        if key in RETIRED_ENV:
            raise Violation('refusing a retired environment name: ' + retired_env_refusal(key))
        if key not in allowed:
            raise Violation('environment names are an allowlist; refusing ' + key)
        exempt = key in DRIVER_TIMEOUT_EXEMPT and type(value) is str and value == DRIVER_TIMEOUT_EXEMPT[key]
        if (TIMEOUT_WORDS.search(key) and not exempt) or JVM_TIMEOUT.search(str(value)):
            raise Violation('refusing to pass a timeout setting to a fixture process: ' + key)



def check_image_config(config):
    """The same allowlist for the pinned image itself: its Env names are allowlisted and nothing in Env, Entrypoint or
    Cmd carries a JVM timeout override. Returns the env NAMES for the ownership record."""
    env = dict(entry.split('=', 1) for entry in config.get('Env') or [])
    unknown = set(env) - IMAGE_ENV
    if unknown:
        raise Violation('pinned image carries non-allowlisted environment ' + ', '.join(sorted(unknown)))
    for text in list(env.values()) + list(config.get('Entrypoint') or []) + list(config.get('Cmd') or []):
        if JVM_TIMEOUT.search(text):
            raise Violation('pinned image carries a timeout override: ' + text)
    return sorted(env)


GENESIS_DERIVATION = 'per-run: odd(sha256(run_id) mod 2^61 + life - 1), in [1, 2^62)'


def derive_genesis_id(run_id, life=1):
    """The ME/core genesisId of one run, derived from its run_id at run time (deterministic, odd,
    in [1, 2^62), distinct per life), so two runs of one kind (siblings that differ only in run_id) never repeat an id."""
    import hashlib
    if type(life) is not int or life < 1:
        raise Violation('a genesis life is a positive integer: ' + repr(life))
    base = int.from_bytes(hashlib.sha256(str(run_id).encode()).digest(), 'big') % (1 << 61)
    return hex(((base + life - 1) % (1 << 61)) * 2 + 1)


def child_manifest(manifest, parent, tag):
    """A child of ``manifest`` with a fresh run identity, written under ``parent`` as
    ``<kind>--<run_id>-<tag>.json`` when the manifest carries a kind (the name ``validate_build_b`` checks against
    ``manifest_kind``, as mk_manifests.py writes them), else ``<run_id>-<tag>-manifest.json`` as before. Returns (path, child)."""
    import uuid
    child = json.loads(json.dumps(manifest))
    child['run_id'] = 'rc2-' + uuid.uuid4().hex[:12]
    parent = Path(parent)
    child['state_root'] = str(parent / 'fixtures' / child['run_id'])
    if '--' in tag or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', tag):
        raise Violation('a child manifest tag is a short name without "--": ' + tag)
    kind = child.get('manifest_kind')
    path = parent / (f'{kind}--{child["run_id"]}-{tag}.json' if kind else f'{child["run_id"]}-{tag}-manifest.json')
    with path.open('x') as stream:
        json.dump(child, stream, indent=1); stream.write('\n')
    return path, child


def load(path):
    return json.loads(Path(path).read_text())
