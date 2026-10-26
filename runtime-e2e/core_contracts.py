# SPDX-License-Identifier: Apache-2.0
"""Manifest schema v2: the core topology (RC2 S14, harness 2.7; critic G10, G15, G31, D18, D20).

The legacy schema v1 (OMS order entry, PostgreSQL order truth) stays in contracts.py for the frozen
R02 scenarios. v2 is the OMS + ledger core: ME x3, AE x3, two forwarder slots, two bridge slots, the
money projector, a reserved shadow replica slot and the probe. Slots whose product does not exist
yet (C++ forwarder and bridge, the RCS shadow) declare ``null`` and are skipped, never faked.
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
AE_CREDENTIAL_ENV = {'keys_env': 'ASSETS_AUTH_KEYS', 'credential_env': 'AE_AUTH_CREDENTIAL'}
ME_AUTH_MODES = {'enforced', 'not_enforced_by_artifact'}
# D20: the drills are about elections, so the fixture keeps every production timeout. Everything is an
# allowlist: the manifest's top-level keys, the environment names a fixture process may receive, and
# the environment the pinned image itself carries. Anything else is refused, never filtered.
MANIFEST_KEYS = {'schema_version', 'topology', 'run_id', 'timeouts', 'image', 'state_root', 'failure_domain',
                 'network', 'nodes', 'ports', 'seed', 'cpu_set', 'limits', 'artifacts', 'slot_artifacts', 'core_probe',
                 'journal_probe', 'credentials', 'me_journal_profile', 'postgres_bin', 'postgres_port'}
OPTIONAL_MANIFEST_KEYS = {'netfilter_helper', 'host_loss_acceptance', 'profile_note', 'measurement_purpose',
                          'harness_commit', 'harness_dirty'}
# Names the fixture itself sets (core_fixture: ENGINE_COMMON, engine_env, projector, slot_env, probe_env).
PROCESS_ENV = {
    'CLUSTER_PORT_STRIDE', 'BASE_DIR', 'TRANSPORT_DRIVER_MODE', 'TRANSPORT_IDLE_MODE', 'TRANSPORT_TERM_LENGTH',
    'TRANSPORT_LOG_TERM_LENGTH', 'TRANSPORT_SNAPSHOT_TERM_LENGTH', 'MATCH_ENGINE_BOOK_CAPACITY', 'SNAPSHOT_LOG_BYTES',
    'SNAPSHOT_INTERVAL_MINUTES', 'CLUSTER_NODE', 'CLUSTER_ADDRESSES', 'CLUSTER_PORT_BASE', 'METRICS_PORT',
    'SETTLEMENT_JOURNAL_ENABLED', 'SETTLEMENT_JOURNAL_DIR', 'SETTLEMENT_JOURNAL_ARCHIVE_BIND', 'ASSETS_NODE_PORT',
    'ASSETS_AUTH_KEYS', 'AE_AUTH_CREDENTIAL',
    'PROJECTOR_POSTGRES_URL', 'PROJECTOR_POSTGRES_USER', 'PROJECTOR_POSTGRES_PASSWORD', 'PROJECTOR_AE_JOURNAL_ARCHIVES',
    'PROJECTOR_LOCAL_HOST', 'PROJECTOR_METRICS_PORT',
    'FWD_CORE_INGRESS', 'FWD_CORE_RESPONSE_CHANNEL', 'FWD_ME_INGRESS', 'FWD_ME_RESPONSE_CHANNEL', 'AERON_DIR',
    'FWD_RING_CAPACITY', 'FWD_TICK_CAP_MS', 'FWD_HEAD_PROBE_MS', 'FWD_KEEPALIVE_MS', 'FWD_HTTP_PORT',
    'FWD_TICKS_ENABLED', 'FWD_RELEASE_RELAY',
    'BRIDGE_ME_JOURNAL_ARCHIVES', 'BRIDGE_JOURNAL_CONTROL_STREAM', 'BRIDGE_JOURNAL_STREAM', 'BRIDGE_JOURNAL_CHANNEL',
    'BRIDGE_REPLAY_STREAM', 'BRIDGE_LOCAL_HOST', 'BRIDGE_AE_CLUSTER_ADDRESSES', 'BRIDGE_AE_PORT_BASE',
    'BRIDGE_AE_EGRESS_ENDPOINT', 'BRIDGE_INSTANCE_ID', 'BRIDGE_METRICS_PORT', 'BRIDGE_DRIVER_DIR', 'LD_LIBRARY_PATH',
    'CORE_AE_ADDRESSES', 'CORE_AE_PORT_BASE', 'CORE_LOCAL_HOST'}
IMAGE_ENV = {'PATH', 'JAVA_HOME', 'JAVA_VERSION', 'LANG', 'LANGUAGE', 'LC_ALL', 'HOME', 'TZ'}
TIMEOUT_WORDS = re.compile(r'TIMEOUT|HEARTBEAT|ELECTION|LIVENESS', re.IGNORECASE)
JVM_TIMEOUT = re.compile(r'-D\S*(timeout|heartbeat|election|liveness)', re.IGNORECASE)


def _file(entry, what, keys=('path', 'sha256')):
    file = Path(entry['path'])
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise Inconclusive('missing/untrusted artifact path: ' + what)
    with file.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != entry[keys[1]]:
        raise Violation('artifact digest mismatch: ' + what)


def _source(entry, what):
    if not re.fullmatch(r'[0-9a-f]{40}', entry.get('source_sha') or ''):
        raise Inconclusive('missing artifact source commit: ' + what)


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
        raise Violation('D20: every engine member must be pinned to its own cpuset: ' + ', '.join(missing))
    used = set()
    for role in ENGINES:
        cpus = set(by_role[role])
        if cpus & used:
            raise Violation('D20: engine cpusets must be pairwise disjoint: ' + role)
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


def validate_core_manifest(manifest, manifest_path, cpu_count=None, profiles=journal_decode.PROFILES):
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
            raise Violation('D20: manifest keys are an allowlist; refused ' + ', '.join(sorted(unknown)))
        if manifest['timeouts'] != 'production':
            raise Violation('D20: the core fixture runs production election/heartbeat/session timeouts only')
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
        # D18: archive control ports (AE and ME journal) are reachable only inside this internal network.
        if (net.version != 4 or net.prefixlen != 24 or not any(net.subnet_of(n) for n in private)
                or manifest['network']['internal'] is not True):
            raise Violation('fixture needs its own internal RFC1918 /24 network (D18: no archive port leaves it)')
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
            if entry.get('driver') not in {'embedded', 'java_media_driver'}:
                raise Violation(role + ': driver must be embedded or java_media_driver')
            for name, lib in (entry.get('libs') or {}).items():
                if '/' in name:
                    raise Violation(role + ': library names are flat file names')
                _file(lib, role + ' library ' + name)
        slots = manifest['slot_artifacts']
        if set(slots) != set(SLOTS):
            raise Violation('slot_artifacts must name every slot role: ' + ', '.join(sorted(SLOTS)))
        for slot, name in slots.items():
            if name is not None and name not in SLOT_ARTIFACTS[slot]:
                raise Violation(f'slot {slot} cannot run artifact {name}')
        for key in ['core_probe', 'journal_probe']:
            helper = manifest[key]
            for path_key, digest_key in [('path', 'sha256'), ('source_path', 'source_sha256')]:
                file = Path(helper[path_key])
                if not file.is_absolute() or file.is_symlink() or not file.is_file():
                    raise Inconclusive('missing probe input: ' + key + ' ' + path_key)
                if hashlib.sha256(file.read_bytes()).hexdigest() != helper[digest_key]:
                    raise Violation('probe input changed: ' + key + ' ' + path_key)
        credentials = manifest['credentials']
        if credentials.get('ae') != AE_CREDENTIAL_ENV:
            raise Violation('AE credentials must use ASSETS_AUTH_KEYS / AE_AUTH_CREDENTIAL (RC1 K6)')
        me = credentials.get('me') or {}
        if me.get('mode') not in ME_AUTH_MODES:
            raise Violation('ME credential mode must be declared: enforced | not_enforced_by_artifact')
        for key in ['keys_env', 'credential_env']:
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,63}', me.get(key) or ''):
                raise Violation('ME credential environment names must be explicit')
            if me[key] in PROCESS_ENV or me[key] in IMAGE_ENV or TIMEOUT_WORDS.search(me[key]):
                raise Violation('ME credential environment name collides with a fixture variable: ' + me[key])
        if me['keys_env'] == me['credential_env']:
            raise Violation('ME key table and credential need distinct environment names')
        profile = manifest['me_journal_profile']
        if profile not in journal_decode.profiles_spec(profiles):
            raise Violation('unknown ME journal profile ' + str(profile))
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, (Violation, Inconclusive)):
            raise
        raise Inconclusive('incomplete core manifest: ' + str(error)) from error


def assert_production_timeouts(environment, allowed=PROCESS_ENV):
    """Fixture-side guard (D20): a process receives only allowlisted names, and no value carries a timeout."""
    for key, value in environment.items():
        if key not in allowed:
            raise Violation('D20: environment names are an allowlist; refusing ' + key)
        if TIMEOUT_WORDS.search(key) or JVM_TIMEOUT.search(str(value)):
            raise Violation('D20: refusing to pass a timeout setting to a fixture process: ' + key)


def check_image_config(config):
    """D20 for the pinned image itself: its Env names are allowlisted and nothing in Env, Entrypoint or
    Cmd carries a JVM timeout override. Returns the env NAMES for the ownership record."""
    env = dict(entry.split('=', 1) for entry in config.get('Env') or [])
    unknown = set(env) - IMAGE_ENV
    if unknown:
        raise Violation('D20: pinned image carries non-allowlisted environment ' + ', '.join(sorted(unknown)))
    for text in list(env.values()) + list(config.get('Entrypoint') or []) + list(config.get('Cmd') or []):
        if JVM_TIMEOUT.search(text):
            raise Violation('D20: pinned image carries a timeout override: ' + text)
    return sorted(env)


def load(path):
    return json.loads(Path(path).read_text())
