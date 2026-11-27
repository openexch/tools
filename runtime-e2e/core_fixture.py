# SPDX-License-Identifier: Apache-2.0
"""Fixture v2: the OMS + ledger core topology.

Same ownership, evidence and teardown rules as the legacy Fixture (it is reused, not copied): every
Docker object carries the run label and an unpredictable token, nothing is reset, failed state is
kept. What changes: the role set (no OMS, no market gateway, no legacy bridge), per-run session keys
for AE and ME with secrets redacted from every retained log, the core probe and journal probe,
optional slots for the C++ forwarder and bridge that start from a pinned binary or are skipped and
said so, the ``shadow0`` slot for the shadow replica (the core jar as ``CORE_ROLE=replica`` on the replica kinds, reserved
on every other manifest), cpuset-pinned engines and production timeouts.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import copy
import shutil
import subprocess
import time
import uuid
import zipfile

from contracts import FP, Inconclusive, Violation
import core_contracts
from core_contracts import (ENGINES, PROBE_ENV, PROCESS_ENV, SLOTS, assert_production_timeouts, check_image_config,
                            validate_core_manifest)
from credentials import KeyRing, redact
from fixture import JAVA, LABEL, Fixture
import journal_decode

ENGINE_COMMON = {'CLUSTER_PORT_STRIDE': '100', 'BASE_DIR': '/data/state', 'TRANSPORT_DRIVER_MODE': 'embedded',
                 'TRANSPORT_IDLE_MODE': 'backoff', 'TRANSPORT_TERM_LENGTH': '1m', 'TRANSPORT_LOG_TERM_LENGTH': '1m',
                 'TRANSPORT_SNAPSHOT_TERM_LENGTH': '1m', 'MATCH_ENGINE_BOOK_CAPACITY': '4096',
                 'SNAPSHOT_LOG_BYTES': '1073741824', 'SNAPSHOT_INTERVAL_MINUTES': '5'}
# The staged aeronmd deletes its dir on start and shutdown so that a restart of a killed
# container (the tmpfs /dev/shm survives a kill) never attaches the new process to the dead driver's cnc.dat.
DRIVER_ENV = {'AERON_DIR_DELETE_ON_START': '1', 'AERON_DIR_DELETE_ON_SHUTDOWN': '1'}
EMBEDDED_DIRS = {'fwd': '/dev/shm/fwd-embedded', 'bridge': '/dev/shm/bridge-embedded'}
PROBE_AERON_DIR = '/dev/shm/probe-aeron'
DRIVER_WAIT_TENTHS = 300                      # 30 s for the staged aeronmd to publish its cnc.dat
TAP_REGISTER_BOUND_S = 30                     # review F5: the tap's 'registered' note, observed before ME genesis
AE_RESTART_MIN_AFTER_KILL_S = 12.5            # measured: a restart earlier hits "active mark file detected" and hangs
KILL_HEAL_BOUND_S = 120
GENESIS_PHASES = ['genesis_snapshot_ns', 'tap_started_ns', 'me_genesis_ns', 'bridges_ready_ns', 'core_bound_ns',
                  'first_deposit_ns', 'funded_ns', 'forwarders_ready_ns']
# A second core life runs on an ME that regenesis('me') already re-genesised, so it has no me_genesis phase
LIFE2_CORE_PHASES = [p for p in GENESIS_PHASES if p != 'me_genesis_ns']
GENESIS_ORDER = [('snapshot_genesis', 'genesis_snapshot_ns'), ('start_tap_witness', 'tap_started_ns'),
                 ('me_genesis', 'me_genesis_ns'), ('arm_money_journal', 'money_journal_ns'),
                 ('start_projector', 'projector_ns'), ('start_bridges', 'bridges_ready_ns'),
                 ('core_genesis', 'core_bound_ns'), ('configure_risk', 'risk_ns'),
                 ('fund', 'funded_ns'), ('verify_funded', 'verified_ns'), ('start_forwarders', 'forwarders_ready_ns')]
LIFE2_CORE_ORDER = [step for step in GENESIS_ORDER if step[0] != 'me_genesis']
# stop(): the polite-stop bound per role (docker stop -t). Forwarder: exit 0, contract <= 1 s (RUN:465-472);
# bridge: exit 0 within 10 s (RUN:1768-1770); engines: 15 s then kill is the escalation bound only; on jars with the
# polite-stop fix the code and time are judged by the drills' engine_polite_stop line (143 within ENGINE_SHUTDOWN_TIMEOUT_S + slack).
STOP_BOUND_S = {'forwarder': 3, 'bridge': 10, 'engine': 15, 'projector': 10, 'replica': 15, 'projection': 10, 'marketdata': 10}
FORWARDER_STOP_CONTRACT_S = 1.0
SESSION_WINDOW_S = 10.0          # the core's session timeout a killed forwarder's session outlives it by
READY_AFTER_KILL_S = 5.0         # The ready_after_kill bound, a setting (measured 1.12 s in DR-A05)
REPLACE_READY_BOUND_S = 60       # stops a hung replacement wait; not a line
GENESIS_CAPTURE_SETTLE_S = 15         # a follower appends the committed CoreConfig frames within this after the genesis
REGENESIS_HEAL_BOUND_S = 900     # a stopped or fenced role stays a fault target across both regenesis scopes and the halt phase
ENGINE_LIBS_DIR = '/artifacts/engine_libs'
PROJECTOR_LIBS_DIR = '/artifacts/projector_libs'
ENGINE_DRIVER_PIDFILE = '/data/aeronmd.pid'
DEFAULT_RISK = {'version': 1, 'min_qty': 1, 'max_qty': 10**6 * FP, 'collar_bps': 5000, 'per_sec': 1000, 'max_open': 5000,
                'slippage_bps': 100}
PORT_OFFSETS = {'archive': 1, 'ingress': 2, 'member': 3, 'log': 4, 'transfer': 5}
# The core's archive segment length on the replica and full drill kinds (members and the replica), a core setting
# (ARCHIVE_SEGMENT_LENGTH) since the core stopped hard-coding 64 MiB: the core never read fixture.JAVA's
# -Daeron.archive.segment.file.length (it sets the length explicitly), so the env setting is what makes a 1m fixture log
# purge in whole 1 MiB segments. archive_listing reads the length a recording actually got from its catalog descriptor,
# never from this constant.
ARCHIVE_SEGMENT_LENGTH_SETTING = '1m'
ARCHIVE_SEGMENT_LENGTH = int(ARCHIVE_SEGMENT_LENGTH_SETTING[:-1]) * 1024 * 1024
# The replica's first /ready: a genesis start replays the log from 0 and is VERIFIED from the start; a setting
SHADOW_START_READY_BOUND_S = 120
EXIT_MEANING = {0: 'ANSWERED', 3: 'UNKNOWN', 4: 'REFUSED', 5: 'NOT_REFUSED', 64: 'USAGE'}


def parse_prometheus(text):
    """Prometheus text -> {'name{labels}': value}; malformed lines are refused, not skipped."""
    values = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\s+(\S+)(?:\s+\d+)?', line.strip())
        if not match:
            raise Inconclusive('unparseable metric line: ' + line[:120])
        values[match.group(1)] = float(match.group(2))
    return values


STUB_TOKEN = re.compile(r'([a-z_]+)=("[^"]*"|\S+)')


def parse_stub_line(line):
    """One ct_session_stub output line (``[docker timestamp] [ts] event=<name> k=v ...``) as a dict, or None. The docker
    timestamp, when present, is kept as ``ts``."""
    if 'event=' not in line:
        return None
    head, _, rest = line.partition('event=')
    row = {'event': rest.split()[0] if rest.split() else ''}
    for key, value in STUB_TOKEN.findall(rest[len(row['event']):]):
        row[key] = value[1:-1] if value.startswith('"') else value
    stamp = head.strip().split(' ', 1)[0]
    if re.fullmatch(r'\d{4}-\d\d-\d\dT[0-9:.]+Z', stamp):
        row['ts'] = stamp
    return row


def check_genesis_order(phases, expected=GENESIS_PHASES):
    """The empty snapshot and the tap come first; no deposit may precede either. ``expected`` is the phase
    list of the life being checked (LIFE2_CORE_PHASES for a core re-genesis on an already re-genesised ME)."""
    for name in expected:
        if name not in phases:
            raise Violation('genesis phase missing: ' + name)
    if phases['first_deposit_ns'] < phases['genesis_snapshot_ns'] or phases['first_deposit_ns'] < phases['tap_started_ns']:
        raise Violation('genesis snapshot after money moved')
    for earlier, later in zip(expected, expected[1:]):
        if phases[earlier] > phases[later]:
            raise Violation(f'genesis phase out of order: {later} before {earlier}')


T1_ROW = re.compile(r'\.tickSize\(([0-9_]+)L?\)\.minPrice\(([0-9_]+)L?\)\.maxPrice\(([0-9_]+)L?\)\.lotSize\(([0-9_]+)L?\)')


def t1_market_rows(source):
    """tick, min, max, lot of the market rows the ItCoreDriver genesis encodes (one literal row for every market)."""
    rows = {tuple(int(v.replace('_', '')) for v in hit) for hit in T1_ROW.findall(source)}
    if len(rows) != 1:
        raise Violation(f'ItCoreDriver: expected one literal market rows encoding, found {sorted(rows)}')
    tick, low, high, lot = rows.pop()
    return {'tick': tick, 'min': low, 'max': high, 'lot': lot}


def projector_health_view(body, members, nodes):
    """oe-projector's /health (gateway README "History projector": ``projector.role``, ``.cursor``, ``.halt``, ``.follow``
    with its source index into the configured archives, endpoint, archive id, recording and counts) as the flat keys the
    projection drills read from a slot (the stand-in's names), the body itself under ``raw``. ``members`` are the core
    members the slot lists as its sources, in that order."""
    pj = body.get('projector') if isinstance(body.get('projector'), dict) else {}
    follow = pj.get('follow') if isinstance(pj.get('follow'), dict) else {}
    counts = follow.get('counts') if isinstance(follow.get('counts'), dict) else {}
    cursor = pj.get('cursor') if isinstance(pj.get('cursor'), dict) else {}
    halt = pj.get('halt') if isinstance(pj.get('halt'), dict) else {}
    index = follow.get('source')
    member = members[index] if isinstance(index, int) and 0 <= index < len(members) else None
    endpoint = follow.get('endpoint')
    if endpoint and member is None:
        host = str(endpoint).rsplit(':', 1)[0]
        member = next((m for m in members if nodes.get(m) == host), None)
    return {'role': pj.get('role'), 'source': {'member': member, 'index': index, 'endpoint': endpoint},
            'archive_id': follow.get('archiveId'), 'source_switches': counts.get('switches'),
            'recordings_walked': {'recording_id': follow.get('recordingId'), 'chain_index': follow.get('chainIndex'),
                                  'phase': follow.get('phase')},
            'applied_seq': cursor.get('appliedSeq'), 'head_seq': follow.get('headSeq'), 'halt': halt.get('reason'),
            'halt_detail': halt.get('detail'), 'beats': follow.get('beats'), 'lag_ms': follow.get('lagMs'),
            'lag_events': follow.get('lagEvents'), 'replays_open': follow.get('replaysOpen'),
            'session_open': follow.get('sessionOpen'), 'behind': counts.get('behind'),
            'leader_avoided': counts.get('leaderAvoided'), 'replays_started': counts.get('replaysStarted'),
            'replay_stops': counts.get('replayStops'), 'stop_requests_answered': counts.get('stopRequestsAnswered'),
            'records_applied': counts.get('recordsApplied'), 'mtu_refusals': counts.get('mtuRefusals'),
            'sources_state': follow.get('sources'), 'epoch': cursor.get('epoch'), 'probe_unanswered': None, 'polls': None,
            'last_pg_error': (pj.get('pg') or {}).get('lastError') if isinstance(pj.get('pg'), dict) else None,
            'build': body.get('build'), 'version': body.get('version'), 'binary': True, 'raw': body}


def role_kind(name):
    """forwarder | bridge | engine | projector, or None for a role the fixture never stops politely."""
    if name in ENGINES:
        return 'engine'
    if name in ('fwd0', 'fwd1'):
        return 'forwarder'
    if name in ('bridge0', 'bridge1'):
        return 'bridge'
    if name == 'shadow0':
        return 'replica'
    if name in core_contracts.PROJECTION_ROLES:
        return 'projection'
    if name in core_contracts.MARKETDATA_ROLES:
        return 'marketdata'
    return 'projector' if name == 'projector' else None


def partition_arguments(manifest, source, target, kind, action):
    """iptables arguments for a (src role, dst role, port kind) UDP drop, applied in the source's namespace.

    Engines are addressed per member (``ae1``) or as a whole cluster (``ae``). The rule sits on OUTPUT in
    the source container, so only that client's packets to that port are lost (forwarder -> ME,
    bridge -> AE, bridge -> ME journal archive partitions), never another process's.
    """
    if action not in {'add', 'delete'}:
        raise Violation('unsupported partition operation')
    if source not in core_contracts.ROLES or source == 'probe':
        raise Violation('partition source must be an owned fixture service role')
    members = [target + str(i) for i in range(3)] if target in {'me', 'ae'} else [target]
    if any(m not in ENGINES for m in members) or source in members:
        raise Violation('partition target must be another engine member or cluster')
    rules = []
    for member in members:
        engine, index = member[:2], int(member[2:])
        base = manifest['ports'][engine + '_base'] + index * manifest['ports']['stride']
        if kind == 'journal_archive':
            if engine != 'me':
                raise Violation('only the ME carries a settlement journal archive')
            port = base + 10
        elif kind == 'money_journal_archive':
            if engine != 'ae':
                raise Violation('only the AE carries the money journal archive')
            port = base + PORT_OFFSETS['archive']
        elif kind in PORT_OFFSETS:
            port = base + PORT_OFFSETS[kind]
        else:
            raise Violation('unknown port kind ' + str(kind))
        rules.append(['-w', '2', '-A' if action == 'add' else '-D', 'OUTPUT', '-p', 'udp', '-d',
                      manifest['nodes'][member], '--dport', str(port), '-j', 'DROP'])
    return rules


CATALOG_HEADER_LENGTH = 32          # Aeron's CatalogHeader block (version, length, nextRecordingId, alignment)
DESCRIPTOR_HEADER_LENGTH = 32       # RecordingDescriptorHeader (length, state, checksum)
RECORDING_VALID = 1                 # RecordingState.VALID
SHADOW_STREAM_ID = 4301             # cluster-kit ShadowAlias.STREAM_ID: the only stream wipe_shadows may delete


def catalog_descriptors(archive_dir):
    """recording id -> {'state', 'start', 'stop', 'segment_length', 'term_length', 'stream'} read from an Aeron archive's
    ``archive.catalog`` (host side, little-endian, Aeron 1.53 layout: a 32-byte header whose alignment pads every entry,
    then per entry a 32-byte descriptor header and the RecordingDescriptor body). A missing or unreadable catalog is
    an empty map; the caller says what it could not read."""
    import struct
    path = Path(archive_dir) / 'archive.catalog'
    try:
        data = path.read_bytes()
    except OSError:
        return {}
    if len(data) < CATALOG_HEADER_LENGTH:
        return {}
    alignment = struct.unpack_from('<i', data, 16)[0]
    offset = CATALOG_HEADER_LENGTH if alignment else 1024
    alignment = alignment or 1024
    out = {}
    while offset + DESCRIPTOR_HEADER_LENGTH + 80 <= len(data):
        length, state = struct.unpack_from('<ii', data, offset)
        if length <= 0:
            break
        body = offset + DESCRIPTOR_HEADER_LENGTH
        rid = struct.unpack_from('<q', data, body + 16)[0]
        start, stop = struct.unpack_from('<qq', data, body + 40)
        segment, term, _mtu, _session, stream = struct.unpack_from('<iiiii', data, body + 60)
        out[rid] = {'state': state, 'start': start, 'stop': stop, 'segment_length': segment, 'term_length': term,
                    'stream': stream}
        offset += (length + DESCRIPTOR_HEADER_LENGTH + alignment - 1) // alignment * alignment
    return out


def delete_shadow_segment(path, descriptor, keep=()):
    """Unlink one shadow segment file and return its size. The guard under wipe_shadows: a test helper must never delete
    money-journal (or any other non-shadow) data, so a descriptor whose stream is not SHADOW_STREAM_ID, or a recording
    the member's recording.log names, is refused whatever the caller selected."""
    rid = int(Path(path).stem.split('-')[0])
    if descriptor is None or descriptor.get('stream') != SHADOW_STREAM_ID or rid in keep:
        raise Violation(f'refusing to delete {Path(path).name}: stream '
                        f'{None if descriptor is None else descriptor.get("stream")} is not the shadow stream '
                        f'{SHADOW_STREAM_ID}' + (' (named by recording.log)' if rid in keep else ''))
    size = Path(path).stat().st_size
    Path(path).unlink()
    return size


def archive_listing(state_root, member):
    """The log recording of one member read from its bind-mounted state (host side, like release_cut.genesis_reader):
    the newest TERM recording of ``cluster/recording.log``, its segment length from the archive catalog's descriptor,
    and the base positions of its ``<id>-<base>.rec`` segment files. ``log_start_segment`` > 0 proves the log no longer
    starts at 0 (a purge removed whole segments); 0 proves nothing either way. ``contiguous`` is false when a segment is
    missing between the first and the last, or when the descriptor (and so the segment length) cannot be read."""
    import release_cut
    base = Path(state_root) / 'state' / member / 'state'
    log = base / 'cluster' / 'recording.log'
    if not log.is_file():
        return {'member': member, 'error': 'no recording.log', 'log_recording': None, 'segments': [],
                'log_start_segment': None, 'contiguous': False}
    terms = [e for e in release_cut.recording_log(log) if e['type'] == 'TERM' and e['valid']]
    if not terms:
        return {'member': member, 'error': 'no TERM entry', 'log_recording': None, 'segments': [],
                'log_start_segment': None, 'contiguous': False}
    rid = terms[-1]['recording_id']
    bases = sorted(int(p.stem.split('-')[1]) for p in (base / 'archive').glob(f'{rid}-*.rec'))
    descriptor = catalog_descriptors(base / 'archive').get(rid)
    segment = descriptor['segment_length'] if descriptor else None
    out = {'member': member, 'log_recording': rid, 'segments': bases, 'log_start_segment': bases[0] if bases else None,
           'segment_length': segment,
           'contiguous': bool(bases) and bool(segment) and all(b - a == segment for a, b in zip(bases, bases[1:]))}
    if not descriptor:
        out['error'] = f'recording {rid} not in archive.catalog: segment length unknown'
    return out


class CoreFixture(Fixture):
    # time seams: the fault helpers wait on real time, the unit tests on a fake clock
    clock = staticmethod(time.time)
    gateway_slots = False            # a manifest without the gateway roles (set in __init__)
    projection_slots = False         # a manifest without the projection roles (set in __init__)
    marketdata_slots = False         # a manifest without the market-data role (set in __init__)
    sleep = staticmethod(time.sleep)

    def __init__(self, manifest_path, attach=False, keyring=None, drill=False):
        """``drill=True`` (the core-topology drills) refuses an ME whose artifact does not enforce credentials; core-boot keeps both."""
        self.manifest_path = Path(manifest_path).absolute()
        self.m = json.loads(self.manifest_path.read_text())
        validate_core_manifest(self.m, self.manifest_path, require_me_enforced=drill)
        # The edk-cnctimeout control's switch, refused on every other manifest before the box is touched
        self.engine_driver_skip = core_contracts.check_engine_driver_skip(self.m, self.manifest_path,
                                                                          os.environ.get('ENGINE_DRIVER_SKIP'))
        self.root = Path(self.m['state_root'])
        self.run_id = self.m['run_id']
        self.gateway = str(ipaddress.ip_network(self.m['network']['subnet']).network_address + 1)
        self.pg = Path(self.m['postgres_bin'])
        self.pg_port = self.m['postgres_port']
        if type(self.pg_port) is not int or not 1024 < self.pg_port < 65536:
            raise Violation('invalid fixture postgres port')
        # The REPLICA key only when this manifest runs the replica (an older core refuses a table naming the class)
        self.gateway_slots = core_contracts.gateway_manifest(self.m)
        self.projection_slots = core_contracts.projection_manifest(self.m)
        self.marketdata_slots = core_contracts.marketdata_manifest(self.m)
        self.keys = keyring or KeyRing(replica=self.m['slot_artifacts'].get('shadow0') == 'shadow', gateway=self.gateway_slots,
                                       projection=self.projection_slots, marketdata=self.marketdata_slots)
        self.secret_values = self.keys.secrets()
        self.slots = {}
        if attach:
            self.registry = json.loads((self.root / 'owner.json').read_text())
            if self.registry['run_id'] != self.run_id or self.registry['manifest_sha256'] != hashlib.sha256(self.manifest_path.read_bytes()).hexdigest():
                raise Violation('fixture ownership/manifest mismatch')
            self.token = self.registry['token']
        else:
            if self.root.exists():
                raise Violation('fresh fixture required; existing state is never reset')
            self.root.parent.mkdir(parents=True, exist_ok=True)
            if shutil.disk_usage(self.root.parent).free < self.m['limits']['disk_min_free_mb'] * 1024**2:
                raise Inconclusive('insufficient free disk for fixture')
            if not set(self.m['cpu_set']) | set(sum(self.m['limits']['cpu_set_by_role'].values(), [])) <= os.sched_getaffinity(0):
                raise Inconclusive('fixture CPU set is unavailable')
            self.root.mkdir()
            self.token = uuid.uuid4().hex
            self.registry = {'run_id': self.run_id, 'token': self.token, 'topology': 'core',
                             'manifest_sha256': hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
                             'containers': {}, 'network_id': None, 'pg_started': False, 'command_seq': 0,
                             'credentials': self.keys.evidence()}
            self.save()
        (self.root / 'logs').mkdir(exist_ok=True)

    # ---------------------------------------------------------------- evidence hygiene

    def command(self, argv, *, input=None, timeout=60, check=True, env=None, accepted=(0,)):
        """As Fixture.command, with every session secret redacted from the retained argv and output.

        ``accepted`` names exit codes that are evidence, not failure (a probe reporting REFUSED or
        UNKNOWN); the scenario judges them and the runner does not count them as child failures.
        """
        sequence = self.next_command_seq()
        started = time.monotonic_ns()
        try:
            r = subprocess.run([str(arg) for arg in argv], input=input, text=True,
                               capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as error:
            def decode(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            r = subprocess.CompletedProcess(argv, 124, decode(error.stdout), decode(error.stderr))
        output = self.root / 'logs' / f'command-{sequence:05d}.log'
        output.write_text(redact(r.stdout + r.stderr, self.secret_values))
        with (self.root / 'commands.jsonl').open('a') as log:
            log.write(json.dumps({'argv': [redact(str(a), self.secret_values) for a in argv], 'exit_code': r.returncode,
                                  'elapsed_ns': time.monotonic_ns() - started, 'output': str(output),
                                  'accepted_exit_codes': sorted(accepted),
                                  'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}) + '\n')
        if check and r.returncode:
            raise Inconclusive(f'child exit {r.returncode}: {[redact(str(a), self.secret_values) for a in argv[:3]]}; evidence {output}')
        return r

    # ---------------------------------------------------------------- staging

    def _stage(self, source, target, digest, what, mode):
        shutil.copyfile(source, target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise Violation(what)
        target.chmod(mode)

    def stage_artifacts(self):
        dest = self.root / 'artifacts'; dest.mkdir()
        for role in core_contracts.REQUIRED_JARS:
            artifact = self.m['artifacts'][role]
            self._stage(artifact['path'], dest / (role + '.jar'), artifact['sha256'], 'artifact changed while staging: ' + role, 0o644)
        for role in (core_contracts.OPTIONAL_BINARIES + (core_contracts.GATEWAY_BINARIES if self.gateway_slots else [])
                     + (core_contracts.PROJECTION_BINARIES if self.projection_slots else [])
                     + (core_contracts.MARKETDATA_BINARIES if self.marketdata_slots else [])):
            artifact = self.m['artifacts'][role]
            if artifact is None:
                continue
            target = dest / role; target.mkdir()
            what = 'slot artifact changed while staging: ' + role
            self._stage(artifact['path'], target / 'bin', artifact['sha256'], what, 0o755)
            for name, lib in (artifact.get('libs') or {}).items():
                # Only a lib with exec: true (aeronmd) gets the exec bit; the shared objects do not
                self._stage(lib['path'], target / name, lib['sha256'], what, 0o755 if lib.get('exec') else 0o644)
        # The engine containers' staged aeronmd and its pinned properties; the projector's, the same set
        for key in ('engine_libs', 'projector_libs'):
            libs = self.m.get(key) or {}
            if libs:
                (dest / key).mkdir()
                for name, lib in libs.items():
                    self._stage(lib['path'], dest / key / name, lib['sha256'], f'{key} changed while staging: ' + name,
                                0o755 if lib.get('exec') else 0o644)
        probe_libs = self.m.get('probe_libs') or {}
        if probe_libs:
            (dest / 'probe').mkdir()
            for name, lib in probe_libs.items():
                self._stage(lib['path'], dest / 'probe' / name, lib['sha256'], 'probe changed while staging: probe_libs ' + name,
                            0o755 if lib.get('exec') else 0o644)
        for key, filename in [('core_probe', 'core-probe.jar'), ('journal_probe', 'journal-probe.jar'),
                              ('t1_me_driver', 't1-me-driver.jar'), ('t1_core_driver', 't1-core-driver.jar')]:
            if key not in self.m:
                continue
            self._stage(self.m[key]['path'], dest / filename, self.m[key]['sha256'], 'probe changed while staging: ' + key, 0o644)

    def start_database(self):
        """History projection only: the money projector's database. PostgreSQL is off the money path."""
        data = self.root / 'postgres'
        self.command([self.pg / 'initdb', '-D', data, '-A', 'trust', '-U', 'runtime_fixture', '--no-locale', '--encoding=UTF8'])
        with (data / 'postgresql.conf').open('a') as config:
            config.write(f"\nlisten_addresses='{self.gateway}'\nport={self.pg_port}\nunix_socket_directories=''\n"
                         "shared_buffers='64MB'\nmax_connections=40\n")
        (data / 'pg_hba.conf').write_text('local all all trust\nhost all all ' + self.m['network']['subnet'] + ' trust\n')
        self.command([self.pg / 'pg_ctl', '-D', data, '-l', self.root / 'logs/postgres.log', '-w', 'start'])
        self.registry['pg_started'] = True
        self.registry['pg_pid'] = int((data / 'postmaster.pid').read_text().splitlines()[0]); self.save()
        self.create_roles()
        self.create_money_database()
        if self.gateway_slots:
            self.create_gateway_database()
        if self.projection_slots:
            self.create_projection_databases()
        if self.marketdata_slots:
            self.create_marketdata_database()

    FIXTURE_DATABASES = {'postgres', 'r01_money', 'r01_gateway', 'r01_history_b', core_contracts.MARKETDATA_DATABASE}

    def psql(self, database, sql, role=None):
        """The core fixture's databases only. The harness connects as the bootstrap superuser; ``role`` (one of the role
        plan's login roles) runs a step as that role instead (a writer creating its relations, so it owns them)."""
        if database not in self.FIXTURE_DATABASES:
            raise Violation('unknown fixture database')
        user = role or core_contracts.FIXTURE_SUPERUSER
        if role is not None and role not in core_contracts.LOGIN_ROLES:
            raise Violation('psql as a role outside the role plan: ' + str(role))
        return self.command([self.pg / 'psql', '-h', self.gateway, '-p', self.pg_port, '-U', user,
                             '-d', database, '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql]).stdout.strip()

    # Databases whose default privileges a drill sets only after the slots started (the ownership row's control: a
    # relation created before the default privileges were set), else empty
    deferred_default_privileges = frozenset()

    def create_roles(self):
        """The role plan's roles (core_contracts.LOGIN_ROLES and the reader group), each a login role with no superuser,
        createdb, createrole, replication or bypassrls right; idempotent."""
        sql = [f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{group}') THEN CREATE ROLE {group} NOLOGIN; "
               f"END IF; END $$" for group in (core_contracts.HISTORY_READER_GROUP, core_contracts.MONEY_READER_GROUP,
                                               core_contracts.HISTORY_PRUNER_GROUP)]
        for role in sorted(core_contracts.LOGIN_ROLES):
            sql.append(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} "
                       f"LOGIN; END IF; END $$")
            sql.append(f'ALTER ROLE {role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        sql.append(f'GRANT {core_contracts.HISTORY_READER_GROUP} TO {core_contracts.GATEWAY_LOGIN}')
        # the schemas' age deletes are called by the retention role through the pruner group
        sql.append(f'GRANT {core_contracts.HISTORY_PRUNER_GROUP} TO {core_contracts.RETENTION_ROLE}')
        for statement in sql:
            self.psql('postgres', statement)
        self.registry['db_roles'] = {'superuser': core_contracts.FIXTURE_SUPERUSER, 'logins': dict(core_contracts.LOGIN_ROLES),
                                     'reader_group': core_contracts.HISTORY_READER_GROUP,
                                     'money_reader_group': core_contracts.MONEY_READER_GROUP,
                                     'reader_members': [core_contracts.GATEWAY_LOGIN]}
        self.save()

    def create_database(self, database):
        """CREATE DATABASE with the role plan's owner, then its grants (grant_database)."""
        plan = core_contracts.DATABASE_ROLE_PLAN[database]
        self.psql('postgres', f'CREATE DATABASE {database} OWNER {plan["owner"]}')
        self.grant_database(database, defaults=database not in self.deferred_default_privileges)

    def grant_database(self, database, defaults=True):
        """The console's grants on one database: CONNECT, no CREATE on schema public for PUBLIC, USAGE and CREATE for the
        writers, USAGE for the readers and the retention role, and (``defaults``) each writer's default privileges:
        DELETE and TRUNCATE to the retention role, SELECT to the writer's default readers. Default privileges act only on
        relations created later, so this runs before any writer starts."""
        plan = core_contracts.DATABASE_ROLE_PLAN[database]
        retention = core_contracts.RETENTION_ROLE
        usage = list(plan['readers']) + ([retention] if plan['retention'] else [])
        sql = [f'GRANT CONNECT ON DATABASE {database} TO {", ".join(plan["connect"])}',
               'REVOKE CREATE ON SCHEMA public FROM PUBLIC',
               f'GRANT USAGE, CREATE ON SCHEMA public TO {", ".join(plan["writers"])}']
        if usage:
            sql.append(f'GRANT USAGE ON SCHEMA public TO {", ".join(usage)}')
        for statement in sql:
            self.psql(database, statement)
        if defaults:
            self.set_default_privileges(database)

    def set_default_privileges(self, database):
        plan = core_contracts.DATABASE_ROLE_PLAN[database]
        for writer in plan['writers']:
            if plan['retention']:
                rights = 'TRUNCATE' if plan.get('retention_truncate_only') else 'DELETE, TRUNCATE'
                self.psql(database, f'ALTER DEFAULT PRIVILEGES FOR ROLE {writer} GRANT {rights} ON TABLES TO '
                                    f'{core_contracts.RETENTION_ROLE}')
            readers = plan['default_select'].get(writer)
            if readers:
                self.psql(database, f'ALTER DEFAULT PRIVILEGES FOR ROLE {writer} GRANT SELECT ON TABLES TO {", ".join(readers)}')
        self.registry.setdefault('default_privileges', {})[database] = time.time_ns(); self.save()

    def grant_retention_select(self, database):
        """The retention role's grants that name relations, once each exists: SELECT on the relations the plan lets it
        read, and TRUNCATE alone (whatever it held revoked first) on the plan's ``retention_truncate_only`` relations."""
        plan = core_contracts.DATABASE_ROLE_PLAN[database]
        for relation in plan['retention_select']:
            self.psql(database, f"DO $$ BEGIN IF to_regclass('public.{relation}') IS NOT NULL THEN EXECUTE "
                                f"'GRANT SELECT ON public.{relation} TO {core_contracts.RETENTION_ROLE}'; END IF; END $$")
        for relation in plan.get('retention_truncate_only') or []:
            self.psql(database, f"DO $$ BEGIN IF to_regclass('public.{relation}') IS NOT NULL THEN EXECUTE "
                                f"'REVOKE ALL ON public.{relation} FROM {core_contracts.RETENTION_ROLE}'; EXECUTE "
                                f"'GRANT TRUNCATE ON public.{relation} TO {core_contracts.RETENTION_ROLE}'; END IF; END $$")

    def create_gateway_database(self):
        """The gateway's users store, empty: oe-gateway applies its own migration (db/migration, under an advisory lock,
        its sha256 recorded) and oe-stream only verifies it. History relations are not seeded: no drill of this
        harness reads history (the history read contract is the projection's, a later slice)."""
        self.create_database('r01_gateway')
        self.registry['gateway_database'] = {'name': 'r01_gateway', 'migration': 'applied by oe-gateway', 'history': None,
                                             'owner': core_contracts.DATABASE_ROLE_PLAN['r01_gateway']['owner']}
        self.save()

    # The database a gateway slot reads history from, when a drill names another than the gateways' own before the
    # slot's next start (the byte-equal drill's D: gw0 on the second projection database)
    gateway_history_database = None

    def projector_binary(self):
        """True when the projection slots run the projector binary (a kind of core_contracts.PROJECTOR_BINARY_KINDS)."""
        return self.projection_slots and self.m.get('manifest_kind') in core_contracts.PROJECTOR_BINARY_KINDS

    def gateway_pg_url(self, slot=None):
        """The gateways' database URL. Where the projector binary writes it, the gateways log in as their own login role,
        a member of the schema's reader group (SELECT on the four read relations, nothing else of the projection); where a
        stand-in writes it (rig kinds), as the bootstrap superuser the stand-in writes as."""
        database = (self.gateway_history_database or {}).get(slot, 'r01_gateway')
        if database not in self.FIXTURE_DATABASES - {'postgres', 'r01_money'}:
            raise Violation('a gateway reads the gateways\' or a projection database: ' + str(database))
        user = core_contracts.GATEWAY_LOGIN if self.projector_binary() else core_contracts.FIXTURE_SUPERUSER
        return f'postgresql://{user}@{self.gateway}:{self.pg_port}/{database}'

    def create_projection_databases(self):
        """The projection databases: pj0 writes the gateways' database (created above, empty of history); pj1 a second,
        empty one. The projection creates its own schema in each (the stand-in under an advisory lock, as the projector
        binary will)."""
        self.create_database('r01_history_b')
        self.registry['projection_databases'] = dict(core_contracts.PROJECTION_DATABASES)
        if self.projector_binary():
            # The reader group the projection schema grants to (create_roles, before any projector applies the schema,
            # which then finds it) and the gateways' login role in it; the projector's login role owns every relation
            self.registry['history_reader'] = {'login': core_contracts.GATEWAY_LOGIN,
                                               'member_of': core_contracts.HISTORY_READER_GROUP}
        self.save()

    MARKETDATA_PASSWORD_FILE = '/data/pg-password'

    def create_marketdata_database(self):
        """The market history database and its writer login role (fixed names, core_contracts), empty: oe-marketdata applies
        its own schema and owns every relation. The role's password is a run secret (redacted) in md0's own state dir;
        the fixture's pg_hba trusts the fixture network, so the password is carried, not checked."""
        db, role = core_contracts.MARKETDATA_DATABASE, core_contracts.MARKETDATA_WRITER
        password = uuid.uuid4().hex + uuid.uuid4().hex
        self.psql('postgres', f"ALTER ROLE {role} PASSWORD '{password}'")
        self.create_database(db)
        state = self.root / 'state' / 'md0'
        state.mkdir(parents=True, exist_ok=True)
        path = state / 'pg-password'
        path.write_text(password + '\n')
        path.chmod(0o600)
        self.marketdata_secrets = {password}
        self.secret_values = self.keys.secrets() | self.marketdata_secrets
        self.registry['marketdata_database'] = {'name': db, 'writer': role, 'schema': 'applied by oe-marketdata'}
        self.registry.setdefault('prepared_state', {})['md0'] = {'pg_password_file': True}
        self.save()

    # The order history databases (row "history database lost"): the gateways' database, which pj0 writes and the gateways
    # read, and pj1's. Taking one down refuses every new connection to it and ends every open one, the same failure a
    # stopped database server shows its clients; the money database and the market history database stay up.
    ORDER_HISTORY_DATABASES = ('r01_gateway', 'r01_history_b')

    def history_databases_down(self, down):
        """Take the order history databases down (``down`` True) or bring them back; returns the witness (recorded)."""
        names = ', '.join(f"'{d}'" for d in self.ORDER_HISTORY_DATABASES)
        for database in self.ORDER_HISTORY_DATABASES:
            self.psql('postgres', f'ALTER DATABASE {database} ALLOW_CONNECTIONS {"false" if down else "true"}')
        ended = 0
        if down:
            ended = int(self.psql('postgres', f'SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity '
                                              f'WHERE datname IN ({names})') or 0)
        state = self.psql('postgres', f"SELECT string_agg(datname || '=' || datallowconn, ',' ORDER BY datname) "
                                      f'FROM pg_database WHERE datname IN ({names})')
        return self.record_fault({'kind': 'history_databases_down' if down else 'history_databases_up',
                                  'databases': list(self.ORDER_HISTORY_DATABASES), 'backends_ended': ended,
                                  'allow_connections': state, 'at_ns': time.time_ns()})

    def marketdata_database_down(self, down):
        """Take the market history database down (``down`` True: every new connection refused and every open one ended,
        what a stopped database server shows its clients) or bring it back; returns the witness (recorded). The money
        database and the order history databases stay up."""
        db = core_contracts.MARKETDATA_DATABASE
        self.psql('postgres', f'ALTER DATABASE {db} ALLOW_CONNECTIONS {"false" if down else "true"}')
        ended = 0
        if down:
            ended = int(self.psql('postgres', f"SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                                              f"WHERE datname = '{db}'") or 0)
        state = self.psql('postgres', f"SELECT datallowconn FROM pg_database WHERE datname = '{db}'")
        return self.record_fault({'kind': 'marketdata_database_down' if down else 'marketdata_database_up', 'database': db,
                                  'backends_ended': ended, 'allow_connections': state, 'at_ns': time.time_ns()})

    def recreate_projection_database(self, database):
        """Drop and create one projection database, empty (a projection from genesis into an empty database). The
        projection that writes it is stopped first by the drill; the gateways' database is never recreated (it holds the
        gateways' users store)."""
        if database not in set(core_contracts.PROJECTION_DATABASES.values()) - {'r01_gateway'}:
            raise Violation('only a second projection database is recreated: ' + str(database))
        self.psql('postgres', f'DROP DATABASE {database} WITH (FORCE)')
        self.create_database(database)
        return self.record_fault({'kind': 'recreate_projection_database', 'database': database})

    def projection_pg_url(self, database):
        """A projection's database URL: the projector binary logs in as its own login role; a stand-in (rig kinds) as
        the bootstrap superuser."""
        if database not in set(core_contracts.PROJECTION_DATABASES.values()):
            raise Violation('unknown projection database ' + str(database))
        user = core_contracts.HISTORY_PROJECTOR_LOGIN if self.projector_binary() else core_contracts.FIXTURE_SUPERUSER
        return f'postgresql://{user}@{self.gateway}:{self.pg_port}/{database}'

    def create_money_database(self):
        """The run's money database and the projector jar's packaged migrations (start_database, and reset_projection),
        applied as the money projector's login role, so it owns the money tables; the retention role is then left with
        TRUNCATE alone on the two history tables (the reset; its age delete is the schema's own function)."""
        self.create_database('r01_money')
        with zipfile.ZipFile(self.m['artifacts']['projector']['path']) as jar:
            schemas = sorted(n for n in jar.namelist() if n.startswith('db/migration/V') and n.endswith('.sql'))
            if not schemas: raise Inconclusive('missing packaged projector schema')
            for name in schemas:
                self.psql('r01_money', jar.read(name).decode(), role=core_contracts.MONEY_PROJECTOR_LOGIN)
        # As the console after each money migration run: the writer's default privileges gave the retention role a right
        # on every new relation; it keeps TRUNCATE on the money history tables only (a lookup table, the retention mark
        # or a view is not history)
        keep = core_contracts.TABLE_OWNERS['r01_money']['retention_tables']
        self.psql('r01_money', "DO $$ DECLARE r record; BEGIN FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n "
                               "ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm') "
                               "AND pg_get_userbyid(c.relowner) = current_user AND c.relname <> ALL (ARRAY["
                               + ', '.join(f"'{t}'" for t in keep) + "]) LOOP EXECUTE format('REVOKE ALL ON public.%I FROM "
                               f"%I', r.relname, '{core_contracts.RETENTION_ROLE}'); END LOOP; END $$",
                  role=core_contracts.MONEY_PROJECTOR_LOGIN)
        self.grant_retention_select('r01_money')

    # ---------------------------------------------------------------- processes

    def spawn(self, name, command, environment=None, *, join=None):
        """Create and start one fixture container. A gateway slot's driver sidecar (``<slot>-driver``) holds the slot's
        address and a shareable IPC namespace; ``join`` (the sidecar's container id) starts the slot binary in the
        sidecar's network and IPC namespaces, so the two share the slot's address and the Aeron directory and nothing
        else: each has its own pid namespace, filesystem, limits and lifetime."""
        sidecar = self.sidecar_slot(name)
        if (name not in self.m['nodes'] and sidecar is None) or name in self.registry['containers']:
            raise Violation('unknown or duplicate fixture process')
        assert_production_timeouts(environment or {}, self.allowed_env(), self.timeout_exempt())
        if any(core_contracts.JVM_TIMEOUT.search(str(a)) for a in command):
            raise Violation('refusing a JVM timeout override for ' + name)
        # A seeded member (seed_state) or a slot replaced with keep_state starts on the dir already in place
        prepared = (name in (self.registry.get('seeded') or {}) or name in (self.registry.get('kept_state') or {})
                    or name in (self.registry.get('prepared_state') or {}))
        bound = (self.registry.get('bound_state') or {}).get(name)     # A member bound to another fixture's root
        state = self.root / 'state' / name
        if bound:
            state = Path(bound)
        else:
            state.mkdir(parents=True, exist_ok=prepared)
        limits = self.m['limits']
        role = sidecar or name           # a sidecar runs on its slot's CPUs, memory and shm settings
        memory_mb = (limits.get('memory_mb_by_role') or {}).get(name, (limits.get('memory_mb_by_role') or {}).get(role, limits['memory_mb']))
        shm_mb = (limits.get('shm_mb_by_role') or {}).get(role, limits['shm_mb'])
        cpus = limits['cpu_set_by_role'].get(role, self.m['cpu_set'])
        if join is not None:
            namespaces = ['--network', 'container:' + join, '--ipc', 'container:' + join]
        else:
            namespaces = ['--network', self.registry['network_id'], '--ip', self.m['nodes'][role]]
            namespaces += ['--ipc', 'shareable', '--shm-size', str(shm_mb) + 'm'] if sidecar else ['--shm-size', str(shm_mb) + 'm']
        args = ['docker', 'create', '--name', self.run_id + '-' + name, *namespaces,
                '--label', LABEL + '=' + self.run_id, '--label', LABEL + '.token=' + self.token,
                '--user', f'{os.getuid()}:{os.getgid()}', '--workdir', '/data', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
                '--memory', str(memory_mb) + 'm', '--memory-swap', str(memory_mb) + 'm',
                '--cpuset-cpus', ','.join(map(str, cpus)),
                '--cpus', str(limits.get('cpu_quota_by_role', {}).get(role, 1)),
                '--tmpfs', '/tmp:rw,nosuid,size=128m',
                '--log-opt', 'max-size=32m', '--log-opt', 'max-file=3',
                '--mount', f'type=bind,src={state},dst=/data',
                '--mount', f'type=bind,src={self.root / "artifacts"},dst=/artifacts,readonly']
        for key, value in sorted((environment or {}).items()): args += ['--env', key + '=' + str(value)]
        args += ['--entrypoint', command[0], self.m['image'], *command[1:]]
        resource_id = self.command(args).stdout.strip()
        self.registry['containers'][name] = resource_id; self.save()
        self.inspect('container', resource_id)
        self.command(['docker', 'start', resource_id])
        return resource_id

    def timeout_exempt(self):
        """The timeout names a process may receive, at their exact values: the driver pair, plus the members' rejoin wait
        when a peer-loss drill recorded one (member_rejoin_wait_env)."""
        return {**core_contracts.DRIVER_TIMEOUT_EXEMPT, **(getattr(self, 'member_rejoin_wait_env', None) or {})}

    def allowed_env(self):
        me = self.m['credentials']['me']
        return PROCESS_ENV | {me['keys_env'], me['credential_env']}

    def check_image(self):
        config = json.loads(self.command(['docker', 'image', 'inspect', '--format', '{{json .Config}}',
                                          self.m['image']]).stdout)
        self.registry['image_env_names'] = check_image_config(config); self.save()

    def collect_logs(self):
        for name, cid in self.registry['containers'].items():
            self.inspect('container', cid)
            logs = self.command(['docker', 'logs', '--timestamps', cid], check=False)
            (self.root / 'logs' / (name + '.log')).write_text(redact(logs.stdout + logs.stderr, self.secret_values))

    def redact_probe_state(self):
        """tap.out/tap.err and every other retained probe file pass the same redaction as command logs."""
        directory = self.root / 'state' / 'probe'
        if not directory.is_dir():
            return
        for path in sorted(directory.rglob('*')):
            if path.is_file() and not path.is_symlink():
                text = path.read_bytes().decode('utf-8', errors='replace')
                cleaned = redact(text, self.secret_values)
                if cleaned != text:
                    path.write_text(cleaned)

    def close(self):
        try:
            self.redact_probe_state()
        finally:
            super().close()

    def execute(self, name, argv, *, input=None, timeout=30, environment=None, check=True, accepted=(0,)):
        # the pinned T1 drivers' names (PROBE_ENV) are allowed on the probe container only
        assert_production_timeouts(environment or {}, self.allowed_env() | {'ME_AUTH_CREDENTIAL'}
                                   | (PROBE_ENV if name == 'probe' else set()))
        resource_id = self.registry['containers'][name]
        self.inspect('container', resource_id)
        command = ['docker', 'exec', '-i']
        for key, value in sorted((environment or {}).items()): command += ['--env', key + '=' + str(value)]
        return self.command([*command, resource_id, *argv], input=input, timeout=timeout, check=check, accepted=accepted)

    def engine_env(self, engine, index):
        addresses = ','.join(self.m['nodes'][engine + str(i)] for i in range(3))
        env = {**ENGINE_COMMON, 'CLUSTER_NODE': str(index), 'CLUSTER_ADDRESSES': addresses,
               'CLUSTER_PORT_BASE': str(self.m['ports'][engine + '_base']),
               'CLUSTER_PORT_STRIDE': str(self.m['ports']['stride'])}
        if engine == 'me':
            env.update(METRICS_PORT=str(core_contracts.engine_http_port(self.m['ports'], f'me{index}')), SETTLEMENT_JOURNAL_ENABLED='true',
                       SETTLEMENT_JOURNAL_DIR='/data/journal', SETTLEMENT_JOURNAL_ARCHIVE_BIND='0.0.0.0')
            env['MATCH_ENGINE_FROM_CONFIG'] = 'true'    # RUN:158: the replicated EngineConfig decides, not an env knob
            env[self.m['credentials']['me']['keys_env']] = self.keys.table('me')
        else:
            env['CORE_NODE_PORT'] = str(core_contracts.engine_http_port(self.m['ports'], f'ae{index}'))
            env['CORE_AUTH_KEYS'] = self.keys.table('ae')
            if self.projector_binary():
                # the member's replay gauge counts the history projector's replays (its reader budget reads it)
                env['CORE_ARCHIVE_REPLAY_PROBE_STREAM'] = core_contracts.HISTORY_PROJECTOR_JOURNAL['HISTORY_PROJECTOR_REPLAY_STREAM']
            env.update(self.member_shadow_env(index))
        if self.engine_driver() == 'external':
            # TC:84-91 / ATC:37-42 external mode attaches to the wrapper's aeronmd at AERON_DIR (TC:155, ATC:70)
            env.update(TRANSPORT_DRIVER_MODE='external', AERON_DIR=f'/dev/shm/aeron-{engine}{index}')
        return env

    def member_shadow_env(self, index):
        """The AE member's shadow block on a replica kind (core_contracts.REPLICA_KINDS): SNAPSHOT_MODE=shadow, pull sources
        = the replica's archive then the two peers' (spelled as CLUSTER_ADDRESSES spells them; the member's own endpoint is
        refused at boot), the producer buffer, the witness alarm, a 1-minute cadence, the kind's own member settings and,
        on a peer-loss drill only, the rejoin watchdog wait it recorded (member_rejoin_wait_env). A
        full-mode kind keeps SNAPSHOT_MODE unset and takes the cadence only. No TRANSPORT_LOG_RCV_WINDOW: the member derives
        its window from the term and logs it at boot."""
        kind = self.m.get('manifest_kind')
        # 1 MiB archive segments on the replica and full drill kinds only: their drills need a log that purges (logStart
        # > 0); the older kinds were measured on the core's 64 MiB default and keep it until they are re-measured
        segment = {'ARCHIVE_SEGMENT_LENGTH': ARCHIVE_SEGMENT_LENGTH_SETTING}
        if kind in core_contracts.FULL_KINDS:
            return {**core_contracts.DRILL_CADENCE_ENV, **segment}
        if kind not in core_contracts.REPLICA_KINDS:
            return {}
        sources = [self.archive_endpoint('shadow0')] + [self.archive_endpoint(f'ae{j}') for j in range(3) if j != index]
        return {**core_contracts.MEMBER_SHADOW_ENV, **core_contracts.DRILL_CADENCE_ENV, **segment,
                'SHADOW_PULL_SOURCES': ','.join(sources), **core_contracts.REPLICA_KINDS[kind]['members'],
                **(getattr(self, 'member_rejoin_wait_env', None) or {})}

    def archive_endpoint(self, role):
        """``host:port`` of an AE member's or the replica's archive control channel (port offset 1)."""
        ports = self.m['ports']
        slot = core_contracts.REPLICA_SLOT if role == 'shadow0' else int(role[2:])
        if role != 'shadow0' and not (role.startswith('ae') and role in ENGINES):
            raise Violation('an archive endpoint of an AE member or the replica only: ' + role)
        return f'{self.m["nodes"][role]}:{ports["ae_base"] + slot * ports["stride"] + PORT_OFFSETS["archive"]}'

    def replica_env(self):
        """The replica's environment (core README "Replica"): the cluster it follows, its slot and address, FOLLOWER
        backup source, its metrics port, the three members' archives as pull sources, its REPLICA key, the fixture term,
        and the kind's own replica settings. External mode attaches to its wrapper's aeronmd."""
        nodes, ports = self.m['nodes'], self.m['ports']
        env = {**core_contracts.REPLICA_ENV, 'BASE_DIR': ENGINE_COMMON['BASE_DIR'],
               'CLUSTER_ADDRESSES': ','.join(nodes[f'ae{i}'] for i in range(3)), 'CLUSTER_PORT_BASE': str(ports['ae_base']),
               'CLUSTER_PORT_STRIDE': str(ports['stride']), 'CLUSTER_REPLICA_ADDRESS': nodes['shadow0'],
               'CORE_NODE_PORT': str(core_contracts.engine_http_port(ports, 'shadow0')),
               'SHADOW_PULL_SOURCES': ','.join(self.archive_endpoint(f'ae{i}') for i in range(3)),
               'TRANSPORT_LOG_TERM_LENGTH': ENGINE_COMMON['TRANSPORT_LOG_TERM_LENGTH'],
               'ARCHIVE_SEGMENT_LENGTH': ARCHIVE_SEGMENT_LENGTH_SETTING,
               'TRANSPORT_IDLE_MODE': ENGINE_COMMON['TRANSPORT_IDLE_MODE'], 'TRANSPORT_DRIVER_MODE': 'embedded',
               'CORE_AUTH_CREDENTIAL': self.keys.credential('shadow0', 'ae')}
        env.update(core_contracts.REPLICA_KINDS.get(self.m.get('manifest_kind'), {}).get('replica', {}))
        if self.engine_driver() == 'external':
            env.update(TRANSPORT_DRIVER_MODE='external', AERON_DIR='/dev/shm/aeron-shadow0')
        return env

    def replica_command(self):
        """The engines' launch shape, never the C++ slot wrapper: ``java -jar`` of the staged core jar embedded, the
        engines' aeronmd wrapper (engine_libs) external."""
        jar = JAVA + ['-jar', '/artifacts/shadow/bin']
        if self.engine_driver() != 'external':
            return jar
        return self._driver_wrapper('shadow0', ENGINE_LIBS_DIR, jar)

    def engine_driver(self):
        """``embedded`` (dev default) or ``external`` (the staged aeronmd in the engine container, C13)."""
        return self.m.get('engine_driver', 'embedded')

    def projector_driver(self):
        """``embedded`` (the default; the projector's own Java driver) or ``external`` (the staged
        aeronmd in the projector container, attached through PROJECTOR_DRIVER_MODE=external and AERON_DIR)."""
        return self.m.get('projector_driver', 'embedded')

    def _driver_wrapper(self, role, libs_dir, jar):
        """The external-driver wrapper of the engines (CF engine_command): a fresh driver dir, the staged aeronmd on the pinned
        driver.properties plus the dev overlay in the background with its pid in /data, a 30 s wait for its cnc.dat with the
        driver alive, then ``exec java``."""
        d = '/dev/shm/aeron-' + role
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        alive = f'"$(cat {ENGINE_DRIVER_PIDFILE})"'
        script = (f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} AERON_PRINT_CONFIGURATION=1 LD_LIBRARY_PATH={libs_dir} '
                  f'{libs_dir}/aeronmd {libs_dir}/driver.properties {libs_dir}/driver-dev.properties & '
                  f'echo $! > {ENGINE_DRIVER_PIDFILE}; i=0; '
                  f'while {{ [ ! -f {d}/cnc.dat ] || ! kill -0 {alive} 2>/dev/null; }} && [ $i -lt {DRIVER_WAIT_TENTHS} ]; '
                  f'do sleep 0.1; i=$((i+1)); done; '
                  f'[ -f {d}/cnc.dat ] && kill -0 {alive} 2>/dev/null || {{ echo "aeronmd did not come up in 30 s" >&2; exit 1; }}; '
                  f'exec {shlex.join(jar)}')
        return ['sh', '-c', script]

    def projector_command(self):
        jar = JAVA + ['-jar', '/artifacts/projector.jar']
        if self.projector_driver() != 'external':
            return jar
        return self._driver_wrapper('projector', PROJECTOR_LIBS_DIR, jar)

    def engine_command(self, engine, index):
        """Embedded engines run ``java -jar`` as before; external engines run through the wrapper shape (CF:347-356):
        a fresh driver dir, the staged aeronmd on the pinned driver.properties plus the dev overlay in the background with its
        pid in /data (exec_kill), a 30 s wait for its cnc.dat with the driver alive, then ``exec java`` (the engine's own
        awaitExternalDriver is the second wait, TC:266-283, ATC:117-131). A member named by ENGINE_DRIVER_SKIP (control
        edk-cnctimeout only) starts java with no driver at all."""
        role = engine + str(index)
        props = [f'-D{k}={v}' for k, v in sorted((self.m.get('core_jvm_properties') or {}).items())] if engine == 'ae' else []
        jar = JAVA + props + ['-jar', f'/artifacts/{engine}.jar']
        if self.engine_driver() != 'external':
            return jar
        d = '/dev/shm/aeron-' + role
        if role in getattr(self, 'engine_driver_skip', ()):
            return ['sh', '-c', f'rm -rf {d}; mkdir -p {d}; exec {shlex.join(jar)}']
        return self._driver_wrapper(role, ENGINE_LIBS_DIR, jar)

    def engine_driver_pidfile(self, role):
        """The pid file the engine wrapper writes, so exec_kill can kill an engine's staged aeronmd."""
        if role == 'projector':
            if self.projector_driver() != 'external':
                raise Violation(f'projector runs no staged driver (projector_driver {self.projector_driver()})')
            return ENGINE_DRIVER_PIDFILE
        if role not in ENGINES or self.engine_driver() != 'external':
            raise Violation(f'{role} runs no staged driver (engine_driver {self.engine_driver()})')
        return ENGINE_DRIVER_PIDFILE

    def probe_env(self, principal):
        env = {'CORE_ADDRESSES': ','.join(self.m['nodes'][f'ae{i}'] for i in range(3)),
               'CORE_PORT_BASE': str(self.m['ports']['ae_base']), 'CLUSTER_PORT_STRIDE': str(self.m['ports']['stride']),
               'CORE_LOCAL_HOST': self.m['nodes']['probe']}
        if principal is not None:
            env['CORE_AUTH_CREDENTIAL'] = self.keys.credential(principal, 'ae')
        return env

    def t1_env(self):
        """Environment of the pinned T1 drivers (PROBE_ENV): the probe principals' credentials, 5 ME markets."""
        cred = self.keys.credential
        return {'T1_ADMIN_KEY': cred('probe-admin', 'ae'), 'T1_TOOL_KEY': cred('probe-tool', 'ae'),
                'T1_GATEWAY_KEY': cred('probe-gateway', 'ae'), 'T1_ME_ADMIN_KEY': cred('probe-admin', 'me'),
                'T1_ME_MARKETS': '5', 'T1_LOCAL_HOST': self.m['nodes']['probe']}

    def projector_env(self):
        return {'PROJECTOR_POSTGRES_URL': f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_money',
                'PROJECTOR_POSTGRES_USER': core_contracts.MONEY_PROJECTOR_LOGIN, 'PROJECTOR_POSTGRES_PASSWORD': 'synthetic-fixture-only',
                'PROJECTOR_CORE_JOURNAL_ARCHIVES': ','.join(self.m['nodes'][f'ae{i}'] + ':' + str(19301 + 100 * i) for i in range(3)),
                'PROJECTOR_LOCAL_HOST': self.m['nodes']['projector'], 'PROJECTOR_METRICS_PORT': str(self.m['ports']['projector_http']),
                **self.projector_driver_env()}

    def projector_driver_env(self):
        """No key in the manifest = the base env unchanged; embedded never sets AERON_DIR (ProjectorDriver refuses
        it); external names the staged driver's dir."""
        if 'projector_driver' not in self.m:
            return {}
        if self.projector_driver() == 'external':
            return {'PROJECTOR_DRIVER_MODE': 'external', 'AERON_DIR': '/dev/shm/aeron-projector'}
        return {'PROJECTOR_DRIVER_MODE': 'embedded'}

    def probe_command(self):
        """The probe idles; with pinned probe_libs it also runs the aeronmd the T1 drivers attach to."""
        if not (self.m.get('probe_libs') or {}).get('aeronmd'):
            return ['sleep', 'infinity']
        d = PROBE_AERON_DIR
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        script = (f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/probe /artifacts/probe/aeronmd & '
                  f'echo $! > /data/aeronmd.pid; i=0; while [ ! -f {d}/cnc.dat ] && [ $i -lt {DRIVER_WAIT_TENTHS} ]; do sleep 0.1; i=$((i+1)); done; '
                  f'[ -f {d}/cnc.dat ] || {{ echo "probe aeronmd did not come up" >&2; exit 1; }}; exec sleep infinity')
        return ['sh', '-c', script]

    def genesis_id(self, life=1):
        """The ME/core genesis identity, odd and distinct per life. Derived from the run_id
        at run time (core_contracts.derive_genesis_id), not from the kind's constant seed, so activation step 7 sees a distinct id per
        genesis run; the rule is recorded with the genesis (genesis_derivation)."""
        return core_contracts.derive_genesis_id(self.run_id, life)

    def genesis_derivation(self):
        return {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': self.run_id}

    def life(self, scope='core'):
        """The newest life whose ``scope`` (me | core) genesis has started; 1 before any genesis record."""
        lives = self.registry.get('lives') or {}
        started = [int(n) for n, record in lives.items() if scope in record]
        return max(started) if started else 1

    def core(self, verb, principal, timeout=60, **kv):
        """One CoreProbe verb in the probe container; returns (meaning, json-or-None)."""
        argv = JAVA + ['-cp', '/artifacts/core-probe.jar:/artifacts/ae.jar', 'CoreProbe', verb] + [f'{k}={v}' for k, v in kv.items()]
        r = self.execute('probe', argv, environment=self.probe_env(principal), timeout=timeout, check=False,
                         accepted=(0, 3, 4, 5))
        meaning = EXIT_MEANING.get(r.returncode, 'CRASHED')
        lines = [l for l in r.stdout.splitlines() if l.startswith('{')]
        reply = json.loads(lines[-1]) if lines else None
        with (self.root / 'core-requests.jsonl').open('a') as log:
            log.write(json.dumps({'verb': verb, 'principal': principal, 'args': kv, 'exit': r.returncode,
                                  'meaning': meaning, 'reply': reply, 'at_ns': time.time_ns()}) + '\n')
        if meaning in {'USAGE', 'CRASHED'}:
            raise Inconclusive(f'core probe {verb} exited {r.returncode}')
        return meaning, reply

    def journal_dump(self, member):
        index = int(member[2:])
        argv = JAVA + ['-cp', '/artifacts/journal-probe.jar:/artifacts/me.jar', 'JournalProbe', 'dump',
                       f'archive={self.m["nodes"][member]}:{self.m["ports"]["me_base"] + index * self.m["ports"]["stride"] + 10}',
                       f'local={self.m["nodes"]["probe"]}', 'control_stream=4010', 'stream=4001',
                       f'replay_port={self.m["ports"]["journal_replay"]}', f'source={member}']
        r = self.execute('probe', argv, timeout=120)
        return [l for l in r.stdout.splitlines() if l.startswith('{')]

    def me_open_legs(self):
        ingress = ','.join(f'{i}={self.m["nodes"][f"me{i}"]}:{self.m["ports"]["me_base"] + i * self.m["ports"]["stride"] + 2}'
                           for i in range(3))
        env = {}
        if self.m['credentials']['me']['mode'] == 'enforced':
            env['ME_AUTH_CREDENTIAL'] = self.keys.credential('probe-admin', 'me')
        argv = JAVA + ['-cp', '/artifacts/journal-probe.jar:/artifacts/me.jar', 'JournalProbe', 'open-legs',
                       f'ingress={ingress}', f'local={self.m["nodes"]["probe"]}']
        r = self.execute('probe', argv, environment=env, timeout=90)
        return json.loads([l for l in r.stdout.splitlines() if l.startswith('{')][-1])['legs']

    def me_open_legs_unauthenticated(self):
        """core-boot control: an authenticating ME refuses a session that presents no credential."""
        ingress = ','.join(f'{i}={self.m["nodes"][f"me{i}"]}:{self.m["ports"]["me_base"] + i * self.m["ports"]["stride"] + 2}'
                           for i in range(3))
        argv = JAVA + ['-cp', '/artifacts/journal-probe.jar:/artifacts/me.jar', 'JournalProbe', 'open-legs',
                       f'ingress={ingress}', f'local={self.m["nodes"]["probe"]}']
        return self.execute('probe', argv, timeout=90, check=False, accepted=(0, 1))

    def tap_paths(self, life=1):
        """One tap per life, ``tap-life<n>.jsonl/.out/.err/.sessions.jsonl`` in the probe's /data (host: state/probe), and
        its stop file ``tap-life<n>.stop`` (the tap ends early once it exists, ``stop_tap``)."""
        stem = f'tap-life{int(life)}'
        host = self.root / 'state' / 'probe'
        return {k: host / (stem + suffix) for k, suffix in
                (('rows', '.jsonl'), ('out', '.out'), ('err', '.err'), ('sessions', '.sessions.jsonl'), ('stop', '.stop'))}

    def start_tap(self, duration_ms, life=1):
        """Independent dispatch/order/admission witness (TOOL session), in the background, on per-life files."""
        cid = self.registry['containers']['probe']; self.inspect('container', cid)
        command = ['docker', 'exec', '-d']
        environment = self.probe_env('probe-tool')
        assert_production_timeouts(environment, self.allowed_env())
        for key, value in sorted(environment.items()): command += ['--env', f'{key}={value}']
        paths = self.tap_paths(life)
        if paths['stop'].exists():
            raise Violation(f'the tap stop file {paths["stop"]} exists before the tap started')
        data = {k: '/data/' + v.name for k, v in paths.items()}
        argv = JAVA + ['-cp', '/artifacts/core-probe.jar:/artifacts/ae.jar', 'CoreProbe', 'tap', f'out={data["rows"]}',
                       f'sessions={data["sessions"]}', f'duration_ms={int(duration_ms)}', f'stop={data["stop"]}']
        self.command([*command, cid, 'sh', '-c', shlex.join(argv) + f' > {data["out"]} 2> {data["err"]}'])
        return self.tap_paths(life)['rows']

    def stop_tap(self, life=None):
        """Ask the current life's tap to end now (it polls its stop file every 200 ms and then prints its summary);
        ``duration_ms`` stays its worst case. Returns the stop time (ns)."""
        path = self.tap_paths(life or self.life('core'))['stop']
        path.write_text(str(time.time_ns()) + '\n')
        return time.time_ns()

    def start_story(self, kv, name='story'):
        """One ``CoreProbe story`` JVM in the background on the GATEWAY principal. Returns the host paths of its
        request log, markers, stdout and exit file (the probe's /data is the host's state/probe)."""
        cid = self.registry['containers']['probe']; self.inspect('container', cid)
        environment = self.probe_env('probe-gateway')
        assert_production_timeouts(environment, self.allowed_env())
        command = ['docker', 'exec', '-d']
        for key, value in sorted(environment.items()): command += ['--env', f'{key}={value}']
        args = dict(kv, out=f'/data/{name}.jsonl', markers=f'/data/{name}-markers.jsonl')
        argv = JAVA + ['-cp', '/artifacts/core-probe.jar:/artifacts/ae.jar', 'CoreProbe', 'story'] + [f'{k}={v}' for k, v in args.items()]
        self.command([*command, cid, 'sh', '-c', shlex.join(argv) + f' > /data/{name}.out 2> /data/{name}.err; echo $? > /data/{name}.exit'])
        host = self.root / 'state' / 'probe'
        paths = {k: host / f'{name}{suffix}' for k, suffix in
                 [('log', '.jsonl'), ('markers', '-markers.jsonl'), ('out', '.out'), ('err', '.err'), ('exit', '.exit')]}
        self.registry.setdefault('stories', {})[name] = {'args': {k: str(v) for k, v in args.items()},
                                                        'started_ns': time.time_ns(), **{k: str(v) for k, v in paths.items()}}
        self.save()
        return paths

    def start_lag_sampler(self, hz, term_bytes, name='lag'):
        """``lag_sampler.py`` once, detached in the probe container for a drill's duration (never a process per sample):
        staged into the probe's /data from this harness (pinned with it), polling the members' and the replica's
        ``/metrics`` over the fixture network; it stops on ``/data/<name>/stop`` and writes ``lag.tsv`` and ``summary.json``
        there. Returns the host paths (the probe's /data is ``state/probe``)."""
        host = self.root / 'state' / 'probe'
        source = Path(__file__).with_name('lag_sampler.py')
        shutil.copyfile(source, host / 'lag_sampler.py')
        out = host / name
        out.mkdir()
        nodes, ports = self.m['nodes'], self.m['ports']
        members = ','.join(f'http://{nodes[f"ae{i}"]}:{core_contracts.engine_http_port(ports, f"ae{i}")}/metrics' for i in range(3))
        replica = f'http://{nodes["shadow0"]}:{core_contracts.engine_http_port(ports, "shadow0")}/metrics'
        argv = ['python3', '-I', '/data/lag_sampler.py', '--members', members, '--replica', replica, '--out', f'/data/{name}',
                '--hz', str(hz), '--term-bytes', str(term_bytes), '--stop-file', f'/data/{name}/stop']
        cid = self.registry['containers']['probe']; self.inspect('container', cid)
        self.command(['docker', 'exec', '-d', cid, 'sh', '-c', shlex.join(argv) + f' > /data/{name}/sampler.out 2>&1'])
        paths = {'dir': out, 'tsv': out / 'lag.tsv', 'summary': out / 'summary.json', 'stop': out / 'stop',
                 'sampler_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'started_ns': time.time_ns()}
        self.registry.setdefault('samplers', {})[name] = {k: str(v) for k, v in paths.items()}
        self.save()
        return paths

    def stop_lag_sampler(self, paths, bound_s=15):
        """Ask the sampler to stop and read its summary (an absent summary within the bound is INCONCLUSIVE)."""
        paths['stop'].write_text('stop\n')
        deadline = time.monotonic() + bound_s
        while time.monotonic() < deadline:
            if paths['summary'].is_file():
                return json.loads(paths['summary'].read_text())
            self.sleep(0.2)
        raise Inconclusive(f'the lag sampler wrote no summary within {bound_s} s of its stop file ({paths["dir"]})')

    def funding_plan(self, script, users, seed):
        """The deposit table of ``CoreProbe story script=funding`` (no cluster), one owner of the amounts."""
        meaning, reply = self.core('story', None, script='funding', seed=seed, users=','.join(map(str, users)),
                                   out='/data/funding-plan.jsonl', **{'for': script})
        if meaning != 'ANSWERED':
            raise Inconclusive('story funding plan: ' + meaning)
        rows = [json.loads(l)['row'] for l in (self.root / 'state' / 'probe' / 'funding-plan.jsonl').read_text().splitlines() if l]
        return [{'request': r['request'], 'user': r['user'], 'asset': r['asset'], 'amount': r['amount']} for r in rows]

    def read_tap_summary(self, life=None):
        """CoreProbe tap's exit lines: ``TAP first= last= rows= gaps=`` and the JSON summary, plus its
        session-transition sidecar. Inconclusive while the tap JVM has not printed them (it is still running or died).
        ``life`` defaults to the current core life."""
        out = self.tap_paths(life or self.life('core'))['out']
        lines = out.read_text().splitlines() if out.exists() else []
        line = next((l for l in lines if l.startswith('TAP first=')), None)
        summary = None
        for l in lines:
            try:
                parsed = json.loads(l) if l.startswith('{') else None
            except ValueError:
                parsed = None
            if parsed and parsed.get('verb') == 'tap':
                summary = parsed
        if line is None or summary is None:
            raise Inconclusive('the tap printed no TAP density line: it is still running or died')
        sessions = Path(self.root / 'state' / 'probe' / Path(summary['sessions_file']).name)
        transitions = [json.loads(l) for l in sessions.read_text().splitlines() if l.strip()] if sessions.exists() else []
        return {'line': line, 'summary': summary, 'transitions': transitions}

    def leader(self, engine):
        """The member reporting cluster role 2 (leader), or None. A member that does not answer is not the leader."""
        metric = 'core_cluster_role' if engine == 'ae' else 'match_cluster_role'
        leaders = []
        for i in range(3):
            try:
                if self.metrics(f'{engine}{i}', core_contracts.engine_http_port(self.m['ports'], f'{engine}{i}')).get(metric) == 2.0:
                    leaders.append(f'{engine}{i}')
            except Inconclusive:
                continue
        return leaders[0] if len(leaders) == 1 else None

    def ready_body(self, role):
        port, path = self.ready_target(role)
        response = self.http(role, port, path)
        return response.get('status'), response.get('body', '')

    def metrics(self, role, port):
        response = self.http(role, port, '/metrics')
        if response['status'] != 200:
            raise Inconclusive(f'{role} metrics unavailable: {response.get("status")}')
        return parse_prometheus(response['body'])

    def start(self, plan=None, before_engines=None):
        """Boot the topology. ``plan=None`` is the bare boot (empty core, slots up; core-boot). A ``plan`` runs the
        genesis phases and leaves a funded, OPEN core with bridges and forwarders ready."""
        self.check_image(); self.stage_artifacts(); self.start_network(); self.start_database()
        self.spawn('probe', self.probe_command())
        if before_engines is not None:          # The X-R precheck, with the projection database up
            before_engines()
        boot = {'started_ns': time.time_ns(), 'phases': {}}
        self.registry['boot'] = boot
        for engine in ('ae', 'me'):
            for i in range(3):
                self.spawn(engine + str(i), self.engine_command(engine, i), self.engine_env(engine, i))
        for engine in ('ae', 'me'):
            for i in range(3): self.wait_http(engine + str(i), core_contracts.engine_http_port(self.m['ports'], engine + str(i)), '/ready')
        if self.engine_driver() == 'external':
            # Every external engine's driver is registered, so restart() demands a NEW driver
            for role in ENGINES:
                if role not in getattr(self, 'engine_driver_skip', ()):
                    self.registry.setdefault('driver_identity', {})[role] = self.driver_identity(role)
            self.save()
        boot['phases']['engines_ready_ns'] = time.time_ns()
        if plan is None:
            self.arm_money_journal(None); self.start_projector(None)
            cut = core_contracts.cut_derived(self.m.get('manifest_kind'))
            for slot in sorted(SLOTS):
                if cut and slot == 'fwd0':
                    # The cut forwarder waits for the ME epoch (not ready on a bare ME), so the
                    # cut's core-boot binds the epoch (the ME genesis, behaviour 2) before the forwarder slots
                    self.registry['lives'] = {'1': {'me': {'genesis_id': self.genesis_id(1)}}}
                    self.me_genesis({})
                    boot['phases']['me_genesis_ns'] = time.time_ns()
                self.slots[slot] = self.start_slot(slot)
        else:
            self.genesis(plan)
        if self.gateway_slots:
            if plan is None:
                # A bare boot has no CoreConfig: a gateway never reads ready on it (config_loaded), so none is started
                for slot in sorted(core_contracts.GATEWAY_SLOTS):
                    self.slots[slot] = {'state': 'NOT_STARTED', 'reason': 'bare boot: no CoreConfig, a gateway is never ready'}
            else:
                self.core_behavior_step()
                self.start_gateway_slots()
                boot['phases']['gateway_slots_ns'] = time.time_ns()
                if self.projection_slots and not getattr(self, 'projection_deferred', False):
                    self.start_projection_slots()
                    boot['phases']['projection_slots_ns'] = time.time_ns()
                if self.marketdata_slots and not getattr(self, 'marketdata_deferred', False):
                    self.start_marketdata_slots()
                    boot['phases']['marketdata_slots_ns'] = time.time_ns()
        boot['phases']['complete_ns'] = time.time_ns()
        self.registry['slots'] = self.slots; self.registry['boot'] = boot
        self.registry['startup_complete'] = True; self.save()

    # ---------------------------------------------------------------- genesis

    def genesis(self, plan):
        """Phases 2..11, in this order, with a timestamp per phase. ``plan``: {users, funding: [{user, asset,
        amount}], risk: {...}, markets: [1..5], ledger_capacity, tap_ms}."""
        phases = self.registry['boot']['phases']
        gid = self.genesis_id(1)
        self.registry['lives'] = {'1': {'me': {'genesis_id': gid}, 'core': {'genesis_id': gid}}}
        self.run_genesis_steps(plan, GENESIS_ORDER, phases)
        self.registry['genesis'] = {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000), 'life': 1,
                                    'derivation': self.genesis_derivation()}
        self.save()
        check_genesis_order(phases)
        self.audit_genesis()

    def audit_genesis(self, life=1):
        """Right after every s17 genesis the audit is taken into ``audit.json`` of the state
        root (``audit-life<n>.json`` for a later core life); runner.py turns it and the run's evidence into
        the activation record of that life. Never fatal: the record judges it."""
        if not core_contracts.cut_derived(self.m.get('manifest_kind')):
            return None
        import release_cut
        path = self.root / ('audit.json' if life == 1 else f'audit-life{life}.json')
        try:
            return release_cut.audit_fixture(self, path)
        except Exception as error:
            path.write_text(json.dumps({'status': 'ERROR', 'error': str(error)[:500], 'findings':
                                        [str(error)[:300]], 'stopped': [], 'members_up': {}}) + '\n')
            return None

    def evidence_marks(self):
        """The row counts of the two evidence logs the activation record reads; a regenesis records them
        where its life begins, so each life's record reads its own rows only."""
        def rows(name):
            path = self.root / name
            return sum(1 for line in path.read_text().splitlines() if line.strip()) if path.is_file() else 0
        return {'commands': rows('commands.jsonl'), 'core_requests': rows('core-requests.jsonl')}

    def capture_core_genesis(self, life, settle_s=0):
        """The core's recorded genesisId of ``life`` (release_cut.genesis_reader over the AE log recordings), kept in the state
        root with its sha256; the activation record reads this capture, not the end-of-run logs. s17 kinds (the ones that
        issue activation records); an error is recorded as the capture, so the record cannot read OK.

        Taken twice. Right after the core genesis (``settle_s`` > 0): the CoreConfig frames sit at the head of every
        member's log, and a later log purge (snapshot reclaim, the shadow floor) removes the segment that holds them, so a
        reader at the end of the run finds them on some members only ("members differ"). A follower that has not appended
        them yet is waited for up to ``settle_s`` (only while the members differ). And before regenesis('core') wipes the
        AE: that one keeps an earlier capture of the life that observed the genesisId (the logs may be purged by then)."""
        if not core_contracts.cut_derived(self.m.get('manifest_kind')):
            return None
        import release_cut
        record = self.registry.setdefault('lives', {}).setdefault(str(life), {})
        earlier = record.get('core_genesis_reader')
        if earlier and Path(earlier['path']).is_file():
            try:
                if json.loads(Path(earlier['path']).read_text()).get('status') == 'observed':
                    return earlier
            except ValueError:
                pass
        deadline = time.monotonic() + settle_s
        while True:
            try:
                reader = release_cut.genesis_reader(self.root, release_cut.load_money_schema(self.m['artifacts']['ae']['path']))
            except Exception as error:
                reader = {'status': 'not observable', 'genesis_id': None, 'error': str(error)[:300], 'members': {}}
            if reader.get('status') != 'members differ' or time.monotonic() >= deadline:
                break
            self.sleep(0.5)
        path = self.root / f'core-genesis-life{life}.json'
        path.write_text(json.dumps(reader, indent=1) + '\n')
        entry = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        record['core_genesis_reader'] = entry
        self.save()
        return entry

    def run_genesis_steps(self, plan, order, phases):
        for step, phase in order:
            if step == 'fund':
                phases['first_deposit_ns'] = time.time_ns()
            getattr(self, step)(plan)
            phases[phase] = time.time_ns()
            self.save()
            if step == 'core_genesis':          # before any snapshot can let a log purge take the CoreConfig frames
                self.capture_core_genesis(self.life('core'), settle_s=GENESIS_CAPTURE_SETTLE_S)

    def _ok(self, verb, principal, **kv):
        meaning, reply = self.core(verb, principal, **kv)
        if meaning != 'ANSWERED':
            raise Inconclusive(f'{verb}: core probe {meaning}: {json.dumps(reply)}')
        return reply

    def snapshot_genesis(self, plan):
        """Step 2: the empty-genesis snapshot, before any config, gate change or deposit (check_barrier needs it empty)."""
        money, orders = self._ok('money-dump', 'probe-admin'), self._ok('order-dump', 'probe-admin')['orders']
        if money['balances'] or money['holds'] or money['lastAppliedTradeId'] != 0 or orders:
            raise Violation('core is not an empty financial and order genesis')
        self.registry['genesis_snapshot'] = {'verified': True, 'balances': [], 'holds': [], 'live_orders': [],
                                             'last_applied_trade_id': 0}
        self.save()

    def start_tap_witness(self, plan):
        """Step 3: the tap registers before any gate change, so it sees [SUSPENDED, GENESIS] and the ADMIN OPEN."""
        duration = int(plan.get('tap_ms', 1_800_000))
        life = self.life('core')
        started_ns = time.time_ns()
        path = self.start_tap(duration, life=life)
        sessions = self.tap_paths(life)['sessions']
        # registry['tap'] is the current life's tap; every life's record stays under lives[n]
        self.registry['tap'] = {'path': str(path), 'started_ns': started_ns, 'duration_ms': duration, 'life': life,
                                'sessions': str(sessions)}
        self.registry.setdefault('lives', {}).setdefault(str(life), {})['tap'] = self.registry['tap']
        self.save()
        note = self.wait_tap_registered(path, started_ns, sessions=sessions)
        self.registry['tap'].update(registered_at_ms=note['at_ms'], registered_leader=note.get('leader'))
        self.save()

    def wait_tap_registered(self, path, started_ns, bound_s=TAP_REGISTER_BOUND_S, sessions=None):
        """The tap's own 'registered' transition (its sessions sidecar) is observed before any
        gate change; a fixed sleep was not evidence (a late registration loses [SUSPENDED, GENESIS] and O12 would FAIL on
        a host cause). Not seen within the bound: INCONCLUSIVE, never a guess."""
        sessions = Path(sessions) if sessions is not None else path.with_name(path.name + '.sessions.jsonl')
        deadline = time.monotonic() + bound_s
        while True:
            if sessions.exists():
                for line in sessions.read_text().splitlines():
                    try:
                        note = json.loads(line) if line.strip() else {}
                    except ValueError:
                        continue
                    if note.get('event') == 'registered' and int(note.get('at_ms') or 0) * 1_000_000 >= started_ns - 1_000_000_000:
                        return note
            if time.monotonic() > deadline:
                err = path.with_suffix('.err')
                tail = err.read_text()[-300:] if err.exists() else ''
                raise Inconclusive(f'the tap did not register within {bound_s} s: {tail}')
            self.sleep(0.2)

    def tap_gate(self, market=0, life=None):
        """The last admission row the tap recorded for ``market`` (0 = GLOBAL), or None: the observed gate state. ``life``
        names another life's tap; the default is the current one."""
        record = self.registry['tap'] if life is None else self.registry['lives'][str(life)]['tap']
        tap = Path(record['path'])
        rows = []
        if tap.exists():
            for line in tap.read_text().splitlines():
                try:
                    entry = json.loads(line) if line.strip() else {}
                except ValueError:
                    continue      # a row the tap is still writing
                if entry.get('tap') == 'admission' and entry['row'].get('market') == market:
                    rows.append(entry['row'])
        return rows[-1] if rows else None

    def _driver(self, key, main, *args, timeout=150, check=True, accepted=(0,)):
        if key not in self.m:
            raise Inconclusive(f'manifest has no {key}: the genesis drivers are pinned through build_core_probes.py --ct-dir')
        jar = '/artifacts/' + key.replace('_', '-') + '.jar'
        base = '/artifacts/me.jar' if main == 'ItMeDriver' else '/artifacts/ae.jar'
        argv = JAVA + ['-cp', f'{jar}:{base}', main, *map(str, args)]
        return self.execute('probe', argv, environment=self.t1_env(), timeout=timeout, check=check, accepted=accepted)

    def _ingress(self, engine):
        nodes, ports = self.m['nodes'], self.m['ports']
        return ','.join(f'{i}={nodes[f"{engine}{i}"]}:{ports[engine + "_base"] + i * ports["stride"] + 2}' for i in range(3))

    def me_genesis(self, plan):
        """Step 4: EngineConfig FRESH through ItMeDriver; markets 2..5 exist at the ME."""
        self._driver('t1_me_driver', 'ItMeDriver', 'genesis', PROBE_AERON_DIR, self._ingress('me'),
                     self.genesis_id(self.life('me')), plan.get('ledger_capacity', 100_000))

    def arm_money_journal(self, plan):
        meaning, reply = self.core('money-journal', 'probe-admin', state='on')
        if meaning != 'ANSWERED':
            raise Inconclusive('money journal could not be armed through the core probe: ' + meaning)

    def start_projector(self, plan):
        if 'projector' in self.registry['containers']:      # A second life restarts the same container, never spawns
            self.restart('projector')
            return
        self.spawn('projector', self.projector_command(), self.projector_env())
        self.wait_http('projector', self.m['ports']['projector_http'], '/health')

    def start_or_restart_slot(self, slot):
        """start_slot on the first life; restart() of the same container on a later one (regenesis)."""
        if slot not in self.registry['containers']:
            return self.start_slot(slot)
        witness = self.restart(slot)
        row = self.slot_row(slot, self.slot_artifact(slot), register_driver=False)
        row['restart'] = {k: witness.get(k) for k in ('started_at', 'exit_code')}
        return row

    def start_bridges(self, plan):
        """Step 6. The core's GLOBAL gate binds only through a bridge's FRESH 68, so no bridge is no genesis."""
        for slot in ('bridge0', 'bridge1'):
            self.slots[slot] = self.start_or_restart_slot(slot)
        if not any(self.slots[s]['state'] == 'STARTED' for s in ('bridge0', 'bridge1')):
            raise Inconclusive('the core genesis binds the ME epoch through a bridge; both bridge slots are empty')

    def core_genesis(self, plan):
        """Step 7: CoreConfig 1 -> 2 -> 3, OPEN GLOBAL retried until the bridge binds the epoch. users = 0: no
        fire-and-forget deposits (T1C:269-281); the oracle-grade funding is step 9."""
        self._driver('t1_core_driver', 'ItCoreDriver', 'genesis', PROBE_AERON_DIR, self._ingress('ae'),
                     self.genesis_id(self.life('core')), plan.get('ledger_capacity', 100_000), 0, 'via-bridge')

    def t1_market(self):
        """The market rows of the pinned ItCoreDriver genesis, read from its source (an earlier constant had maxPrice
        10^18, the driver sends 1_000_000_000_000_000L = 10^15: the tables differed, so the driver's re-run met STALE at
        CoreConfig 1, CoreConfigStateMachine.java:94-98 at eb559a7)."""
        return t1_market_rows(Path(self.m['t1_core_driver']['source_path']).read_text())

    def core_config(self, version, genesis_id=None):
        """One CoreConfig through ``CoreProbe core-config`` on the ADMIN principal, with the values the
        genesis driver sends (configVersion = behaviorVersion = version, the genesisId, its market rows), so a later driver run
        meets an equal record (DUPLICATE). Returns [version, AdminAck result name]."""
        gid = genesis_id or self.genesis_id(self.life('core'))
        meaning, reply = self.core('core-config', 'probe-admin', version=version, behavior=version, genesis=gid, **self.t1_market())
        acks = [r for r in (reply or {}).get('replies') or [] if r.get('t') == 'AdminAck']
        if not acks:
            raise Inconclusive(f'CoreConfig {version}: no AdminAck ({meaning})')
        return [version, acks[-1]['result']]

    def core_genesis_partial(self, plan, stop_after, genesis_id=None):
        """X-A2: the core genesis stopped after CoreConfig ``stop_after`` (1 or 2): the driver switch ``-Dt1.maxv=k`` as a
        harness option (the driver's three frames leave within 70 ms, so an outside kill cannot stop it)."""
        if stop_after not in (1, 2):
            raise Violation('a partial genesis stops after CoreConfig 1 or 2, got ' + repr(stop_after))
        results = [self.core_config(v, genesis_id) for v in range(1, stop_after + 1)]
        row = {'stop_after': stop_after, 'genesis_id': genesis_id or self.genesis_id(self.life('core')), 'results': results}
        self.registry['partial_genesis'] = row; self.save()
        return row

    def core_genesis_finish(self, plan, genesis_id=None):
        """X-A2 recovery: CoreConfig 3 only, measured."""
        row = {'genesis_id': genesis_id or self.genesis_id(self.life('core')), 'results': [self.core_config(3, genesis_id)]}
        self.registry['finish_genesis'] = row; self.save()
        return row

    def configure_risk(self, plan):
        """Step 8: an explicit RiskConfig per market, recorded as sample.risk."""
        risk = dict(DEFAULT_RISK, **(plan.get('risk') or {}))
        for market in plan.get('markets', range(1, 6)):
            self._ok('risk', 'probe-admin', market=market, **risk)
        self.registry['risk'] = {str(m): risk for m in plan.get('markets', range(1, 6))}; self.save()

    def fund(self, plan):
        """Step 9: ACKed deposits on the TOOL principal, each recorded with its gate state (CO:18-28). A plan that names
        ``funding_for`` takes the story's own deposit table (``CoreProbe story script=funding``)."""
        rows = []
        funding = plan.get('funding') or []
        if plan.get('funding_for'):
            funding = self.funding_plan(plan['funding_for'], plan['users'], plan.get('seed', self.m['seed'] & 0xFFFFFFFF))
        for n, row in enumerate(funding, start=1):
            rh, rl = row.get('request', [2, n])
            # review F4: the gate state is the tap's last GLOBAL admission row at deposit time, an observation, not a constant
            gate = self.tap_gate(0)
            meaning, reply = self.core('deposit', 'probe-tool', user=row['user'], asset=row['asset'], amount=row['amount'],
                                       rh=rh, rl=rl)
            if meaning != 'ANSWERED':
                raise Inconclusive(f'funding deposit {n} was {meaning}: {json.dumps(reply)}')
            rows.append({'request': [rh, rl], 'kind': 'deposit', 'user': row['user'], 'asset': row['asset'],
                         'amount': row['amount'], 'outcome': 'ACK', 'gate': gate['state'] if gate else None,
                         'gate_witness': {'source': 'tap', 'row': gate}, 'reply': reply})
        self.registry['funding'] = rows; self.save()

    def fund_rows(self, rows):
        """drill-time funding on the TOOL principal (A04's halt-time deposits and withdrawals), appended to
        registry['funding'] with the tap's GLOBAL gate row at send time, exactly as fund() records them, so M9 judges them.
        The outcome is recorded as answered (ACK, REJECT, UNKNOWN), never raised: the oracle judges it."""
        out = []
        for row in rows:
            kind = row.get('kind')
            if kind not in ('deposit', 'withdraw'):
                raise Violation('fund_rows moves money by deposit or withdraw only, got ' + str(kind))
            seq = self.registry['fund_rows_seq'] = self.registry.get('fund_rows_seq', 0) + 1
            rh, rl = row.get('request', [3, seq])      # fund() uses [2, n]; drill-time rows never collide with genesis rows
            gate = self.tap_gate(0)
            meaning, reply = self.core(kind, 'probe-tool', user=row['user'], asset=row['asset'], amount=row['amount'], rh=rh, rl=rl)
            entry = {'request': [rh, rl], 'kind': kind, 'user': row['user'], 'asset': row['asset'], 'amount': row['amount'],
                     'outcome': {'ANSWERED': 'ACK', 'REFUSED': 'REJECT'}.get(meaning, 'UNKNOWN'),
                     'gate': gate['state'] if gate else None, 'gate_witness': {'source': 'tap', 'row': gate}, 'reply': reply,
                     'phase': 'drill', 'life': self.life('core'), 'at_ns': time.time_ns()}
            self.registry.setdefault('funding', []).append(entry); self.save()
            out.append(entry)
        return out

    def verify_funded(self, plan):
        """Step 10: the money-dump shows exactly the deposits, the gate is OPEN, and every ME member journaled one
        engine_config record and nothing else (the clean-genesis witness)."""
        money = self._ok('money-dump', 'probe-admin')
        if money['journalEnabled'] is not True:
            raise Violation('money journal not armed at genesis')
        want = {}
        for row in self.registry.get('funding', []):
            want[(row['user'], row['asset'])] = want.get((row['user'], row['asset']), 0) + row['amount']
        have = {(b['user'], b['asset']): b['available'] + b['locked'] for b in money['balances']}
        if have != want or money['holds']:
            raise Violation(f'money-dump differs from the genesis deposits: {have} != {want}')
        global_gate = self.tap_gate(0)
        if global_gate is None or global_gate['state'] != 'OPEN':
            raise Violation(f'GLOBAL gate is not OPEN after genesis: {global_gate}')
        profile = journal_decode.load_profile(self.m['me_journal_profile'])
        # A member a scenario stopped (a registered fault target, not Running) is skipped
        # and named; any other stopped member is still dumped (and fails loudly), and two members are the minimum witness
        members, skipped = self.members_up('me')
        if len(members) < 2:
            raise Inconclusive(f'verify_funded needs at least two ME members; up {members}, stopped {skipped}')
        self.registry['verify_funded'] = {'members': members, 'skipped': skipped}; self.save()
        for member in members:
            events = journal_decode.decode_dump(self.journal_dump(member), profile, require_end=True)
            if [e['type'] for e in events] != ['engine_config']:
                raise Violation(f'{member} journal is not a clean genesis: {[e["type"] for e in events]}')

    def members_up(self, engine):
        """(members to read, members skipped) of an engine. Skipped: a registered fault target whose
        container is not Running (X-A1's killed leader, X-A4's late members); every other member is read."""
        targets = self.registry.get('fault_targets') or {}
        members, skipped = [], []
        for i in range(3):
            role = f'{engine}{i}'
            cid = self.registry['containers'].get(role)
            down = cid is None or not self.inspect('container', cid)['State']['Running']
            (skipped if down and role in targets else members).append(role)
        return members, skipped

    def start_forwarders(self, plan):
        for slot in ('fwd0', 'fwd1'):
            self.slots[slot] = self.start_or_restart_slot(slot)
        for slot in ('shadow0',):
            self.slots[slot] = self.start_slot(slot)

    def bind_member_states(self, state_dir, members=ENGINES):
        """The members' /data are the dirs of
        ``state_dir`` (another fixture's state, wiped by the precheck's list), linked as ``state/<member>`` so every reader of
        this fixture's state root sees them. Each dir must exist and be empty; a member already started is refused."""
        for member in members:
            target = Path(state_dir) / member
            if member in self.registry['containers']:
                raise Violation(f'bind_member_states refuses {member}: already started')
            if not target.is_dir():
                raise Violation(f'bind_member_states: {target} does not exist')
            if any(target.iterdir()):
                raise Violation(f'bind_member_states: {target} is not empty (the forward order runs on wiped roots)')
            link = self.root / 'state' / member
            link.parent.mkdir(parents=True, exist_ok=True)
            if link.exists() or link.is_symlink():
                raise Violation(f'bind_member_states: {link} exists')
            link.symlink_to(target.resolve(), target_is_directory=True)
            self.registry.setdefault('bound_state', {})[member] = str(target.resolve())
        self.save()
        return dict(self.registry['bound_state'])

    # ---------------------------------------------------------------- seeds

    def seed_state(self, role, src, recorded_sha256, witness=None, parts=None):
        """Copy a member's state dir from a stopped earlier run into ``state/<role>`` before the member starts. Refused: a
        member already started, a missing source, a source whose tree hash (sha256 over sorted relative paths and file sha256)
        differs from the recorded one. ``parts`` copies only those subtrees (X-7: the ME journal archive). The hash and the
        non-vacuity ``witness`` go in the fault witness."""
        from legacy_tag import tree_hash
        if role not in ENGINES:
            raise Violation('seed_state seeds an engine member only: ' + role)
        if role in self.registry['containers']:
            raise Violation(f'seed_state refuses {role}: the member was already started (a seed goes in before the start)')
        src = Path(src)
        if not src.is_dir():
            raise Inconclusive(f'seed source missing: {src}')
        tree = tree_hash(src)
        if tree['sha256'] != recorded_sha256:
            raise Inconclusive(f'seed tree hash differs from the recorded one: {src} {tree["sha256"]} != {recorded_sha256}')
        dest = self.root / 'state' / role
        if dest.exists():
            raise Violation('seed_state needs a fresh member state dir: ' + str(dest))
        if parts:
            dest.mkdir(parents=True)
            for part in parts:
                if (src / part).exists():
                    shutil.copytree(src / part, dest / part, symlinks=True)
        else:
            shutil.copytree(src, dest, symlinks=True)
            if tree_hash(dest)['sha256'] != tree['sha256']:
                raise Inconclusive(f'seed copy of {role} differs from its source')
        row = {'source': str(src), 'tree': tree, 'parts': list(parts) if parts else None, 'witness': witness}
        self.registry.setdefault('seeded', {})[role] = row; self.save()
        return self.record_fault({'kind': 'seed_state', 'target': role, **row})

    # ---------------------------------------------------------------- slots

    def slot_artifact(self, slot):
        """The artifact a slot runs: the manifest's, or the one replace_slot swapped in (witnessed)."""
        return ((getattr(self, 'registry', None) or {}).get('slot_override') or {}).get(slot, self.m['slot_artifacts'][slot])

    def slot_binary(self, slot):
        """(artifact name, driver mode) of the binary pinned for a slot; Inconclusive when the slot is empty."""
        name = self.slot_artifact(slot)
        artifact = self.m['artifacts'].get(name) if name else None
        if artifact is None:
            raise Inconclusive(f'slot {slot} has no pinned binary')
        return name, artifact['driver']

    def slot_env(self, slot):
        nodes, ports = self.m['nodes'], self.m['ports']
        ae_ingress = ','.join(f'{i}={nodes[f"ae{i}"]}:{ports["ae_base"] + i * ports["stride"] + 2}' for i in range(3))
        me_ingress = ','.join(f'{i}={nodes[f"me{i}"]}:{ports["me_base"] + i * ports["stride"] + 2}' for i in range(3))
        _, mode = self.slot_binary(slot)
        instance = str(self.keys.keys[(slot, 'ae')][0])
        if slot.startswith('fwd'):
            me = self.m['credentials']['me']
            if me['credential_env'] != 'ME_AUTH_CREDENTIAL':
                raise Violation('ct-forwarder reads its ME credential from ME_AUTH_CREDENTIAL (FC:161); the manifest names '
                                + me['credential_env'])
            env = {'FWD_CORE_INGRESS': ae_ingress, 'FWD_CORE_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:0',
                   'CORE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'), 'FWD_ME_INGRESS': me_ingress,
                   'FWD_ME_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:0',
                   'ME_AUTH_CREDENTIAL': self.keys.credential(slot, 'me'),
                   'FWD_INGRESS_CHANNEL': 'aeron:udp?term-length=4m|mtu=8192', 'FWD_DRIVER_MODE': mode,
                   'FWD_DRIVER_TIMEOUT_MS': '5000', 'FWD_INSTANCE_ID': instance,
                   'FWD_HTTP_BIND': f'{nodes[slot]}:{ports["forwarder_http"]}'}
            if mode == 'external':
                env['AERON_DIR'] = '/dev/shm/aeron-' + slot
            else:
                env['FWD_DRIVER_DIR'] = EMBEDDED_DIRS['fwd']
            return env
        env = {'BRIDGE_ME_JOURNAL_ARCHIVES': ','.join(f'{nodes[f"me{i}"]}:{ports["me_base"] + i * ports["stride"] + 10}' for i in range(3)),
               'BRIDGE_JOURNAL_CONTROL_STREAM': '4010', 'BRIDGE_JOURNAL_STREAM': '4001',
               'BRIDGE_JOURNAL_CHANNEL': 'aeron:ipc', 'BRIDGE_REPLAY_STREAM': '4012',
               'BRIDGE_JOURNAL_MTU': '1408',     # the ME journal archive's MTU (RUN:354; the 2026-09 incident's lesson)
               'BRIDGE_LOCAL_HOST': nodes[slot], 'BRIDGE_DRIVER_MODE': mode, 'BRIDGE_DRIVER_TIMEOUT_MS': '5000',
               'BRIDGE_CORE_CLUSTER_ADDRESSES': ','.join(nodes[f'ae{i}'] for i in range(3)),
               'BRIDGE_CORE_PORT_BASE': str(ports['ae_base']), 'CLUSTER_PORT_STRIDE': str(ports['stride']),
               'BRIDGE_CORE_EGRESS_ENDPOINT': nodes[slot] + ':19394', 'CORE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'),
               'BRIDGE_INSTANCE_ID': instance, 'BRIDGE_HTTP_BIND': f'{nodes[slot]}:{ports["bridge_http"]}'}
        if mode == 'external':
            env['AERON_DIR'] = '/dev/shm/aeron-' + slot
        else:
            env['BRIDGE_DRIVER_DIR'] = EMBEDDED_DIRS['bridge']
        return env

    def slot_process_env(self, slot):
        name, _ = self.slot_binary(slot)
        return {**self.slot_env(slot), 'LD_LIBRARY_PATH': f'/artifacts/{name}'}

    def slot_command(self, slot):
        """The wrapper both modes run through (container is --read-only; both binaries need the driver dir to EXIST)."""
        name, mode = self.slot_binary(slot)
        binary = f'/artifacts/{name}/bin'
        if mode == 'embedded':
            return ['sh', '-c', f'mkdir -p {EMBEDDED_DIRS["fwd" if slot.startswith("fwd") else "bridge"]}; exec {binary}']
        d = '/dev/shm/aeron-' + slot
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        alive = '"$(cat /data/aeronmd.pid)"'
        script = (f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/{name} /artifacts/{name}/aeronmd & '
                  f'echo $! > /data/aeronmd.pid; i=0; '
                  f'while {{ [ ! -f {d}/cnc.dat ] || ! kill -0 {alive} 2>/dev/null; }} && [ $i -lt {DRIVER_WAIT_TENTHS} ]; '
                  f'do sleep 0.1; i=$((i+1)); done; '
                  f'[ -f {d}/cnc.dat ] && kill -0 {alive} 2>/dev/null || {{ echo "aeronmd did not come up in 30 s" >&2; exit 1; }}; '
                  f'exec {binary}')
        return ['sh', '-c', script]

    readiness_override = {}

    def ready_target(self, role):
        """(port, path) whose 200 means the role is back. A Running container is not a heal. ``readiness_override``
        is set only by the RED-1 drill (the nc forwarders may answer /ready 503 STALLED; liveness is /health)."""
        ports = self.m['ports']
        if role in self.readiness_override:
            return (ports['forwarder_http'] if role.startswith('fwd') else ports['bridge_http']), self.readiness_override[role]
        if role.startswith('fwd'):
            return ports['forwarder_http'], '/ready'
        if role.startswith('bridge'):
            return ports['bridge_http'], '/ready'
        if role == 'projector':
            return ports['projector_http'], '/health'
        if role in ENGINES:
            return core_contracts.engine_http_port(ports, role), '/ready'
        if role == 'shadow0' and self.slot_artifact('shadow0') == 'shadow':
            return core_contracts.engine_http_port(ports, 'shadow0'), '/ready'
        if role in core_contracts.GATEWAY_SLOTS and self.slot_artifact(role):
            return self.gateway_ready_target(role)
        if role in core_contracts.PROJECTION_SLOTS and self.slot_artifact(role):
            # /health, not /ready: a standby copy is never ready, and a writer is ready only after its first probe
            return self.m['ports']['projector_admin'], '/health'
        if role in core_contracts.MARKETDATA_SLOTS and self.slot_artifact(role):
            # /ready/session (the ME session): /ready also needs a book snapshot of every expected market, which a market
            # with no order yet may never get
            return self.m['ports']['md_admin'], '/ready/session'
        raise Violation('no readiness target for ' + role)

    def start_slot(self, slot):
        artifact_name = self.slot_artifact(slot)
        if slot == 'shadow0':
            if artifact_name is None:
                return {'state': 'RESERVED', 'reason': 'reserved for the shadow replica role (this manifest runs none)'}
            if artifact_name != 'shadow' or self.m['artifacts'].get('shadow') is None:
                raise Inconclusive(f'shadow0 runs the shadow artifact only, got {artifact_name}')
            self.spawn(slot, self.replica_command(), self.replica_env())
            port, path = self.ready_target(slot)
            self.wait_http(slot, port, path, timeout=SHADOW_START_READY_BOUND_S)
            return self.slot_row(slot, artifact_name)
        artifact = self.m['artifacts'][artifact_name] if artifact_name else None
        if artifact is None:
            return {'state': 'SKIPPED_ABSENT', 'artifact': artifact_name,
                    'reason': 'no pinned binary for this slot yet (C++ ' + ('forwarder' if slot.startswith('fwd')
                                                                           else 'bridge') + ')'}
        self.spawn(slot, self.slot_command(slot), self.slot_process_env(slot))
        port, path = self.ready_target(slot)
        self.wait_http(slot, port, path)
        return self.slot_row(slot, artifact_name)

    def slot_row(self, slot, artifact_name, register_driver=True):
        artifact = self.m['artifacts'][artifact_name]
        port, path = self.ready_target(slot)
        row = {'state': 'STARTED', 'artifact': artifact_name, 'sha256': artifact['sha256'], 'source_sha': artifact['source_sha'],
               'driver': artifact['driver'], 'readiness': path}
        try:    # /health is the witness only (coreConnected, halted, meEpoch ...); readiness was /ready
            row['health'] = json.loads(self.http(slot, port, '/health')['body'])
        except (ValueError, KeyError, TypeError):
            row['health'] = None
        if artifact['driver'] == 'external' and register_driver:
            self.registry.setdefault('driver_identity', {})[slot] = self.driver_identity(slot)
            self.save()
        return row

    def driver_identity(self, role):
        """cnc.dat mtime (ns) of the role's staged aeronmd plus the container's StartedAt. Inside a container the aeronmd
        pid is always 9 and the inode always 6, so neither can tell two drivers apart. A slot with a driver sidecar: the
        sidecar's container and StartedAt (its pid 1 is the driver, so the same StartedAt while running is the same
        driver process)."""
        if self.driver_sidecar(role):
            d = self.slot_driver(role)
            return {'sidecar': d['container'], 'started_at': d['started_at'], 'cnc_mtime': d.get('cnc_mtime')}
        out = self.execute(role, ['stat', '-c', '%.9Y', f'/dev/shm/aeron-{role}/cnc.dat'], timeout=15)
        started = self.inspect('container', self.registry['containers'][role])['State']['StartedAt']
        return {'cnc_mtime': out.stdout.strip(), 'started_at': started}

    # ---------------------------------------------------------------- gateway and stream slots

    # The gateway slots' channels name term-length and mtu (the binaries refuse a channel without them); the fixture's
    # 4 MiB term and 8192 MTU, the forwarders' values. Settings of the fixture, not limits of the binaries.
    GATEWAY_CHANNEL_PARAMS = 'term-length=4m|mtu=8192'
    GATEWAY_AUTH_MODES = 'api-key'
    # The response endpoint's port of a gateway or stream slot (each slot has its own address): a fixed port, so a drill
    # can name the core's egress to one slot on the network (the slow-consumer drill thins it). A setting of the fixture.
    GATEWAY_RESPONSE_PORT = 20480
    # The session stub's channel mask (the stream's: acks, orders, balances, control) and its status cadence
    STUB_CHANNELS = 'acks,orders,balances,control'
    STUB_STATUS_INTERVAL_MS = 1000
    STUB_COMMAND_FILE = '/data/stub.cmd'
    STUB_READY_BOUND_S = 60
    # The gateway's treasury lane (deposit and withdraw), on in every gateway kind: the gateway's own switch and its
    # TREASURY credential (whose key every core member holds in CORE_AUTH_KEYS, the core's way of admitting a TREASURY
    # session; the principal rides the replicated SessionOpen). The faucet caps are settings of the gateway: asset 0, and
    # GATEWAY_FUZZ_UNKNOWN_ASSET, an asset id the core's config does not list, capped so that the gateway's asset check
    # is the only rule between a deposit of an unknown asset and the core (the fuzz sends it).
    GATEWAY_FUZZ_UNKNOWN_ASSET = 999
    GATEWAY_FAUCET_CAPS = {0: '1', GATEWAY_FUZZ_UNKNOWN_ASSET: '1'}

    def faucet_caps(self):
        """The gateways' faucet caps: GATEWAY_FAUCET_CAPS, or the caps a drill names before the gateways start (a drill that
        funds its users through the treasury lane), recorded in the registry."""
        caps = getattr(self, 'gateway_faucet_caps', None)
        if not caps:
            return dict(self.GATEWAY_FAUCET_CAPS)
        if self.registry.get('gateway_faucet_caps') != {str(k): v for k, v in caps.items()}:
            self.registry['gateway_faucet_caps'] = {str(k): v for k, v in caps.items()}
            self.save()
        return dict(caps)

    def core_behavior_step(self):
        """A gateway kind runs the core at its kind's behaviour version (default 4: a create's requestId lookup runs before
        the gate, so a stored acceptance is answered again under a closed gate). The genesis ladder ends at 3; the step to 4
        is one more CoreConfig with the same tables, taken with the gate open (CoreConfigStateMachine: no precondition).
        Recorded with the core's answer; a kind that names 3 stays there (the control of the stored-acceptance rule)."""
        spec = core_contracts.GATEWAY_KINDS.get(self.m.get('manifest_kind')) or {}
        target = spec.get('behavior', core_contracts.GATEWAY_CORE_BEHAVIOR)
        steps = [self.core_config(v) for v in range(4, target + 1)]
        bad = [r for r in steps if r[1] != 'ACCEPTED']
        self.registry['core_behavior'] = {'target': target, 'steps': steps}
        self.save()
        if bad:
            raise Inconclusive(f'core behaviour step refused: {bad}')
        return steps

    def gateway_users(self):
        """The users whose API keys the gateway and stream slots load (GATEWAY_API_KEYS_FILE): the drill's, set before
        start (``self.gateway_user_ids``), else none."""
        return sorted(getattr(self, 'gateway_user_ids', None) or [])

    def gateway_slot_env(self, slot):
        """The environment of a gateway or stream slot (gateway README "Run"; everything else on the binary's defaults)."""
        nodes, ports = self.m['nodes'], self.m['ports']
        name = self.slot_artifact(slot)
        artifact = self.m['artifacts'][name]
        ingress = ','.join(f'{i}={nodes[f"ae{i}"]}:{ports["ae_base"] + i * ports["stride"] + 2}' for i in range(3))
        cred = self.keys.credential(slot, 'ae')
        instance = str(self.keys.keys[(slot, 'ae')][0])
        if name == 'gateway_stub':
            return {'SHIM_HTTP_BIND': f'{nodes[slot]}:{ports["shim_http"]}', 'SHIM_API_KEYS_FILE': '/data/api-keys',
                    'SHIM_MODE': artifact['mode'], 'SHIM_CORE_PROBE': '/artifacts/core-probe.jar:/artifacts/ae.jar',
                    **self.probe_env(None), 'CORE_LOCAL_HOST': nodes[slot], 'CORE_AUTH_CREDENTIAL': cred}
        if name == 'session_stub':
            return {'CORE_AUTH_CREDENTIAL': cred}
        prefix = 'GATEWAY' if core_contracts.GATEWAY_SLOTS[slot] == 'gateway' else 'STREAM'
        env = {f'{prefix}_DRIVER_MODE': artifact['driver'], f'{prefix}_CORE_INGRESS': ingress,
               f'{prefix}_CORE_INGRESS_CHANNEL': 'aeron:udp?' + self.GATEWAY_CHANNEL_PARAMS,
               f'{prefix}_CORE_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:{self.GATEWAY_RESPONSE_PORT}|'
                                                   + self.GATEWAY_CHANNEL_PARAMS,
               'CORE_AUTH_CREDENTIAL': cred, f'{prefix}_INSTANCE_ID': instance,
               f'{prefix}_AUTH_MODES': self.GATEWAY_AUTH_MODES, 'GATEWAY_API_KEYS_FILE': '/data/api-keys'}
        if artifact['driver'] == 'external':
            env['AERON_DIR'] = '/dev/shm/aeron-' + slot
        else:
            env[f'{prefix}_DRIVER_DIR'] = '/dev/shm'
        if prefix == 'GATEWAY':
            env.update(GATEWAY_HTTP_BIND=f'{nodes[slot]}:{ports["gateway_http"]}',
                       GATEWAY_ADMIN_BIND=f'{nodes[slot]}:{ports["gateway_admin"]}', GATEWAY_PG_URL=self.gateway_pg_url(slot),
                       GATEWAY_ALLOW_TREASURY_LANE='1', GATEWAY_TREASURY_CREDENTIAL=self.keys.credential(slot + '-treasury', 'ae'),
                       GATEWAY_FAUCET_MAX_AMOUNT=','.join(f'{a}:{v}' for a, v in sorted(self.faucet_caps().items())))
            # a drill's gateway history settings (history-freshness: the stale bound and its probe cadence), recorded
            # by the drill; only those two names, through the same guard as every other name
            overrides = {k: str(v) for k, v in ((getattr(self, 'gateway_env_overrides', None) or {}).get(slot) or {}).items()}
            for key in overrides:
                if key not in ('GATEWAY_HISTORY_STALE_MS', 'GATEWAY_HISTORY_PROBE_MS'):
                    raise Violation(f'{slot}: a drill may set only the gateway history stale bound and probe cadence; refusing {key}')
            env.update(overrides)
        else:
            # The engine status feed polls each node's own endpoint over the network (never a shared disk)
            env.update(STREAM_WS_BIND=f'{nodes[slot]}:{ports["stream_ws"]}', STREAM_ADMIN_BIND=f'{nodes[slot]}:{ports["stream_admin"]}',
                       STREAM_CORE_NODE_ENDPOINTS=','.join(f'{i}@{nodes[f"ae{i}"]}:{core_contracts.engine_http_port(ports, f"ae{i}")}' for i in range(3)),
                       STREAM_ME_NODE_ENDPOINTS=','.join(f'{i}@{nodes[f"me{i}"]}:{core_contracts.engine_http_port(ports, f"me{i}")}' for i in range(3)))
        return env

    def stub_arguments(self, slot):
        """ct_session_stub's command line (StubOptions.h): one GATEWAY session, the stream's channel mask, status lines."""
        nodes, ports = self.m['nodes'], self.m['ports']
        artifact = self.m['artifacts'][self.slot_artifact(slot)]
        ingress = ','.join(f'{i}={nodes[f"ae{i}"]}:{ports["ae_base"] + i * ports["stride"] + 2}' for i in range(3))
        args = ['--driver-mode', artifact['driver'], '--instance-id', str(self.keys.keys[(slot, 'ae')][0]),
                '--ingress-endpoints', ingress, '--ingress-channel', 'aeron:udp?' + self.GATEWAY_CHANNEL_PARAMS,
                '--response-channel', f'aeron:udp?endpoint={nodes[slot]}:0|' + self.GATEWAY_CHANNEL_PARAMS,
                '--channels', self.STUB_CHANNELS, '--status-interval-ms', str(self.STUB_STATUS_INTERVAL_MS)]
        if artifact['driver'] == 'external':
            args += ['--aeron-dir', '/dev/shm/aeron-' + slot]
        else:
            args += ['--driver-dir', '/dev/shm']
        return args

    def gateway_slot_command(self, slot):
        """oe-gateway / oe-stream exec'd directly (embedded) or behind the staged aeronmd (external, the slot wrapper's
        shape); the shim under python3; the session stub reading its script from /data/stub.cmd (the fixture appends a
        line to steer it: throttle, status, quit)."""
        name = self.slot_artifact(slot)
        artifact = self.m['artifacts'][name]
        binary = f'/artifacts/{name}/bin'
        if name == 'gateway_stub':
            return ['python3', '-I', binary]
        if name == 'session_stub':
            run = (f'touch {self.STUB_COMMAND_FILE}; tail -n +1 -f {self.STUB_COMMAND_FILE} | '
                   f'{binary} {shlex.join(self.stub_arguments(slot))}')
        else:
            run = f'exec {binary}'
        if artifact['driver'] != 'external':
            return ['sh', '-c', run]
        d = '/dev/shm/aeron-' + slot
        if self.driver_sidecar(slot):
            # The driver runs in the slot's sidecar (gateway_driver_command); the binary waits for its cnc.dat in the
            # shared Aeron directory, then execs as pid 1 of its own container
            return ['sh', '-c', f'i=0; while [ ! -f {d}/cnc.dat ] && [ $i -lt {DRIVER_WAIT_TENTHS} ]; do sleep 0.1; i=$((i+1)); done; '
                                f'[ -f {d}/cnc.dat ] || {{ echo "no driver cnc.dat at {d} in 30 s" >&2; exit 1; }}; ' + run]
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        alive = '"$(cat /data/aeronmd.pid)"'
        script = (f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/{name} /artifacts/{name}/aeronmd & '
                  f'echo $! > /data/aeronmd.pid; i=0; '
                  f'while {{ [ ! -f {d}/cnc.dat ] || ! kill -0 {alive} 2>/dev/null; }} && [ $i -lt {DRIVER_WAIT_TENTHS} ]; '
                  f'do sleep 0.1; i=$((i+1)); done; '
                  f'[ -f {d}/cnc.dat ] && kill -0 {alive} 2>/dev/null || {{ echo "aeronmd did not come up in 30 s" >&2; exit 1; }}; '
                  + run)
        return ['sh', '-c', script]

    # ------------------------------------------------ the external driver of a gateway or stream slot: its own container
    # In external mode oe-gateway and oe-stream attach to an aeronmd that has its own lifetime, as production runs aeronmd
    # as its own service on the host: the driver is pid 1 of the slot's sidecar container ``<slot>-driver``, which holds
    # the slot's address (the driver does the slot's UDP) and a shareable IPC namespace (its /dev/shm holds the Aeron
    # directory). The binary's container joins those two namespaces and nothing else, so a kill, a SIGSTOP or a restart
    # of the binary leaves the driver running, and the restarted binary attaches to the same driver. The session stub
    # (a dry-run tool) keeps its driver in its own container.
    DRIVER_SIDECAR = '-driver'
    SIDECAR_BINARIES = ('gateway', 'gateway_nc', 'stream')

    def sidecar_slot(self, name):
        """The slot whose driver sidecar ``name`` is, or None."""
        if not name.endswith(self.DRIVER_SIDECAR):
            return None
        slot = name[:-len(self.DRIVER_SIDECAR)]
        return slot if slot in core_contracts.GATEWAY_SLOTS and self.driver_sidecar(slot) else None

    def driver_sidecar(self, slot):
        """True when ``slot`` runs a product binary on an external driver (the driver in its sidecar)."""
        if slot not in core_contracts.GATEWAY_SLOTS or not self.gateway_slots:
            return False
        name = self.slot_artifact(slot)
        return name in self.SIDECAR_BINARIES and self.m['artifacts'][name]['driver'] == 'external'

    def gateway_driver_command(self, slot):
        """The sidecar's aeronmd (the slot artifact's staged driver) as pid 1, on a fresh dir (DRIVER_ENV)."""
        name = self.slot_artifact(slot)
        d = '/dev/shm/aeron-' + slot
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        return ['sh', '-c', f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/{name} '
                            f'exec /artifacts/{name}/aeronmd']

    def start_slot_driver(self, slot):
        """Start the slot's sidecar and wait for its cnc.dat; returns the sidecar's container id."""
        name = slot + self.DRIVER_SIDECAR
        cid = self.spawn(name, self.gateway_driver_command(slot))
        deadline = time.monotonic() + DRIVER_WAIT_TENTHS / 10
        while True:
            if not self.inspect('container', cid)['State']['Running']:
                raise Inconclusive(f'{name}: aeronmd exited before its cnc.dat')
            if self.execute(name, ['test', '-f', f'/dev/shm/aeron-{slot}/cnc.dat'], timeout=15, check=False).returncode == 0:
                return cid
            if time.monotonic() >= deadline:
                raise Inconclusive(f'{name}: no cnc.dat within {DRIVER_WAIT_TENTHS / 10} s')
            self.sleep(0.1)

    def slot_driver(self, slot):
        """The sidecar driver of ``slot`` as observed now: container id, StartedAt, Running, restarts, the state letter
        of its pid 1, that process's name (aeronmd) and its cnc.dat's inode and mtime (informational)."""
        name = slot + self.DRIVER_SIDECAR
        cid = self.registry['containers'][name]
        row = self.inspect('container', cid)
        state = row['State']
        out = {'container': cid[:12], 'started_at': state['StartedAt'], 'running': state['Running'],
               'restart_count': row.get('RestartCount', 0)}
        if state['Running']:
            probe = self.execute(name, ['sh', '-c', 'read -r a b c r < /proc/1/stat; echo "$c"; cat /proc/1/comm; '
                                                    f'stat -c "%i %.9Y" /dev/shm/aeron-{slot}/cnc.dat'],
                                 timeout=15, check=False)
            lines = (probe.stdout or '').split('\n')
            out['state'] = lines[0].strip() or None
            out['comm'] = (lines[1] if len(lines) > 1 else '').strip() or None
            inode, _, mtime = (lines[2] if len(lines) > 2 else '').strip().partition(' ')
            out['cnc_inode'], out['cnc_mtime'] = inode or None, mtime or None
        return out

    def gateway_ready_target(self, role):
        """(port, path): oe-gateway and oe-stream /ready on the admin bind, the shim's /ready; the session stub has no
        listener and reads ready on its own ``event=registration state=REGISTERED`` line (port None)."""
        ports = self.m['ports']
        name = self.slot_artifact(role)
        if name == 'session_stub':
            return None, 'log:registered'
        if name == 'gateway_stub':
            return ports['shim_http'], '/ready'
        return (ports['gateway_admin'], '/ready') if core_contracts.GATEWAY_SLOTS[role] == 'gateway' else (ports['stream_admin'], '/ready')

    def wait_role_ready(self, name, port, path, timeout=90, since=None):
        """wait_http, or for the session stub its registration line in the container log after ``since``."""
        if port is not None:
            return self.wait_http(name, port, path, timeout=timeout)
        deadline = time.monotonic() + timeout
        cid = self.registry['containers'][name]
        while time.monotonic() < deadline:
            args = ['docker', 'logs'] + (['--since', since] if since else []) + [cid]
            out = self.command(args, check=False)
            if 'event=registration state=REGISTERED' in (out.stdout or '') + (out.stderr or ''):
                return {'status': 200, 'body': 'registered'}
            if not self.inspect('container', cid)['State']['Running']:
                raise Inconclusive(f'fixture process {name} exited before its session registered')
            self.sleep(0.5)
        raise Inconclusive(f'{name}: no registration within {timeout} s')

    def prepare_gateway_state(self, slot):
        """The slot's /data before its first start: the API keys file of the drill's users (secrets: redacted from every
        retained file). Written by the fixture into the slot's own state dir; no role reads another's."""
        state = self.root / 'state' / slot
        state.mkdir(parents=True, exist_ok=True)
        users = self.gateway_users()
        text = self.keys.api_keys_file(users) if users else ''
        path = state / 'api-keys'
        path.write_text(text)
        path.chmod(0o600)
        self.secret_values = self.keys.secrets() | getattr(self, 'marketdata_secrets', set())
        self.registry.setdefault('prepared_state', {})[slot] = {'api_key_users': users}
        self.save()

    def start_gateway_slots(self, slots=None):
        """Start the gateway and stream slots after the core genesis (a gateway reads ready only on a loaded config);
        a declared slot whose artifact is null is SKIPPED_ABSENT, never faked."""
        for slot in slots or sorted(core_contracts.GATEWAY_SLOTS):
            name = self.slot_artifact(slot)
            if name is None:
                self.slots[slot] = {'state': 'SKIPPED_ABSENT', 'reason': 'this manifest stages nothing in ' + slot}
                continue
            self.prepare_gateway_state(slot)
            join = self.start_slot_driver(slot) if self.driver_sidecar(slot) else None
            self.spawn(slot, self.gateway_slot_command(slot), self.gateway_slot_env(slot), join=join)
            port, path = self.ready_target(slot)
            self.wait_role_ready(slot, port, path, timeout=self.STUB_READY_BOUND_S if port is None else 90)
            self.slots[slot] = self.gateway_slot_row(slot, name)
        self.registry['slots'] = self.slots
        self.save()
        return {s: self.slots.get(s) for s in sorted(core_contracts.GATEWAY_SLOTS)}

    def gateway_slot_row(self, slot, name):
        artifact = self.m['artifacts'][name]
        port, path = self.ready_target(slot)
        row = {'state': 'STARTED', 'artifact': name, 'sha256': artifact['sha256'], 'source_sha': artifact['source_sha'],
               'driver': artifact['driver'], 'target': artifact['target'], 'readiness': path}
        if artifact.get('defines'):
            row['defines'] = list(artifact['defines'])
        if port is not None and name in ('gateway', 'gateway_nc', 'stream'):
            try:
                row['health'] = json.loads(self.http(slot, self.m['ports']['gateway_admin' if slot.startswith('gw') else 'stream_admin'],
                                                     '/health')['body'])
            except (ValueError, KeyError, TypeError):
                row['health'] = None
        if artifact['driver'] == 'external' and name != 'gateway_stub':
            self.registry.setdefault('driver_identity', {})[slot] = self.driver_identity(slot)
            self.save()
        return row

    def stub_command(self, slot, line):
        """Append one script line to the session stub's command file (StubCommands.h: throttle, status, reconnect, quit)."""
        if self.slot_artifact(slot) != 'session_stub':
            raise Violation(f'{slot} runs no session stub')
        if '\n' in line or not re.fullmatch(r'[a-z]+( [a-z0-9]+){0,2}', line):
            raise Violation('a stub command is one short script line: ' + repr(line))
        with (self.root / 'state' / slot / 'stub.cmd').open('a') as f:
            f.write(line + '\n')
        self.record_fault({'kind': 'stub_command', 'target': slot, 'line': line})

    def stub_events(self, slot, since=None):
        """The session stub's ``event=...`` lines as dicts (key=value tokens; quoted values kept whole), in order."""
        cid = self.registry['containers'][slot]
        out = self.command(['docker', 'logs', '--timestamps'] + (['--since', since] if since else []) + [cid], check=False)
        return [e for e in (parse_stub_line(l) for l in ((out.stdout or '') + (out.stderr or '')).splitlines()) if e]

    # ---------------------------------------------------------------- projection slots

    # The database each projection slot writes: core_contracts.PROJECTION_DATABASES unless a drill names another before
    # the slot's first start (the freshness drill's standby copy writes pj0's database)
    projection_targets = None

    def projection_database(self, slot):
        return (self.projection_targets or {}).get(slot, core_contracts.PROJECTION_DATABASES[slot])

    # The core members a projection slot lists as its sources, in that order (default: all three), when a drill names
    # them before the slot's next start (the byte-equal drill reads B and C from members other than A's)
    projection_sources = None
    PROJECTOR_KEY_FILE = '/data/cluster-key'
    PROJECTOR_RESPONSE_PORT = 20490

    def projection_members(self, slot):
        members = list((self.projection_sources or {}).get(slot) or [f'ae{i}' for i in range(3)])
        if not members or any(m not in ENGINES or not m.startswith('ae') for m in members) or len(set(members)) != len(members):
            raise Violation(f'{slot}: projection sources are distinct core members, got {members}')
        return members

    def history_projector_env(self, slot):
        """oe-projector's environment (gateway README "History projector"): the required settings only. Its sources are
        the listed members' archives with their node endpoints (role and replay budget), its cluster session the core
        members on its own GATEWAY key (a key file in its /data), its database the slot's projection database. Leases,
        probes, back-offs and timeouts stay at the binary's defaults."""
        nodes, ports = self.m['nodes'], self.m['ports']
        artifact = self.m['artifacts'][self.slot_artifact(slot)]
        members = self.projection_members(slot)
        params = self.GATEWAY_CHANNEL_PARAMS
        env = {'HISTORY_PROJECTOR_DRIVER_MODE': artifact['driver'],
               'HISTORY_PROJECTOR_INSTANCE_ID': str(self.keys.keys[(slot, 'ae')][0]),
               'HISTORY_PROJECTOR_ADMIN_BIND': f'{nodes[slot]}:{ports["projector_admin"]}',
               'HISTORY_PROJECTOR_JOURNAL_ARCHIVES': ','.join(self.archive_endpoint(m) for m in members),
               'HISTORY_PROJECTOR_JOURNAL_NODE_ENDPOINTS': ','.join(f'{nodes[m]}:{core_contracts.engine_http_port(ports, m)}' for m in members),
               'HISTORY_PROJECTOR_LOCAL_HOST': nodes[slot],
               'HISTORY_PROJECTOR_CLUSTER_MEMBERS': ','.join(f'{i}={nodes[f"ae{i}"]}:{ports["ae_base"] + i * ports["stride"] + 2}'
                                                             for i in range(3)),
               'HISTORY_PROJECTOR_CLUSTER_KEY_FILE': self.PROJECTOR_KEY_FILE,
               'HISTORY_PROJECTOR_CORE_INGRESS_CHANNEL': 'aeron:udp?' + params,
               'HISTORY_PROJECTOR_CORE_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:{self.PROJECTOR_RESPONSE_PORT}|{params}',
               'HISTORY_PROJECTOR_PG_URL': self.projection_pg_url(self.projection_database(slot)),
               **core_contracts.HISTORY_PROJECTOR_JOURNAL}
        # a drill's own projector settings for one slot (recorded by the drill; never a lease, probe or timeout)
        env.update({k: str(v) for k, v in ((getattr(self, 'projector_env_overrides', None) or {}).get(slot) or {}).items()})
        if artifact['driver'] == 'external':
            env['AERON_DIR'] = '/dev/shm/aeron-' + slot
        else:
            env['HISTORY_PROJECTOR_DRIVER_DIR'] = '/dev/shm'
        return env

    def projector_slot_command(self, slot):
        """oe-projector exec'd as the container's pid 1: directly (embedded), or behind the staged aeronmd in the same
        container (external, the C++ slots' wrapper), so a kill of the slot is a kill of its driver too."""
        name = self.slot_artifact(slot)
        binary = f'/artifacts/{name}/bin'
        if self.m['artifacts'][name]['driver'] != 'external':
            return ['sh', '-c', f'exec {binary}']
        d = '/dev/shm/aeron-' + slot
        # a drill may give the slot's staged aeronmd its client liveness pair (projection_aeronmd_env): through the
        # timeout guard at the exact exempt values only, and recorded in the fixture's registry
        extra = dict(getattr(self, 'projection_aeronmd_env', None) or {})
        driver_env = dict(DRIVER_ENV, **extra)
        core_contracts.assert_production_timeouts(
            driver_env, core_contracts.PROCESS_ENV | set(core_contracts.PROJECTION_DRIVER_LIVENESS_EXEMPT),
            core_contracts.PROJECTION_DRIVER_LIVENESS_EXEMPT)
        if extra:
            self.registry.setdefault('projection_aeronmd_env', {})[slot] = extra
            self.save()
        env = ' '.join(f'{k}={v}' for k, v in sorted(driver_env.items()))
        alive = '"$(cat /data/aeronmd.pid)"'
        return ['sh', '-c', f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/{name} /artifacts/{name}/aeronmd & '
                            f'echo $! > /data/aeronmd.pid; i=0; '
                            f'while {{ [ ! -f {d}/cnc.dat ] || ! kill -0 {alive} 2>/dev/null; }} && [ $i -lt {DRIVER_WAIT_TENTHS} ]; '
                            f'do sleep 0.1; i=$((i+1)); done; '
                            f'[ -f {d}/cnc.dat ] && kill -0 {alive} 2>/dev/null || {{ echo "aeronmd did not come up in 30 s" >&2; exit 1; }}; '
                            f'exec {binary}']

    def prepare_projection_state(self, slot):
        """The projector slot's /data before its first start: its cluster key file (keyId:GATEWAY:secret, a secret:
        redacted from every retained log; the file stays in the slot's own state dir, which no other role mounts)."""
        state = self.root / 'state' / slot
        state.mkdir(parents=True, exist_ok=True)
        path = state / 'cluster-key'
        path.write_text(self.keys.credential(slot, 'ae') + '\n')
        path.chmod(0o600)
        self.secret_values = self.keys.secrets() | getattr(self, 'marketdata_secrets', set())
        self.registry.setdefault('prepared_state', {})[slot] = {'cluster_key': True}
        self.save()

    def projection_slot_env(self, slot):
        """The stand-in's environment: its listener, its database, its own GATEWAY key, the members' metrics endpoints
        (read over the network to name the leader it follows). The stand-in's settings stay at its defaults unless the
        fixture's PROJECTION_STUB_SETTINGS names one. The projector binary's: history_projector_env."""
        nodes, ports = self.m['nodes'], self.m['ports']
        name = self.slot_artifact(slot)
        if name in ('history_projector', 'history_projector_nc'):
            return self.history_projector_env(slot)
        if name != 'projector_stub':
            raise Inconclusive(f'{slot}: no projection artifact {name}')
        artifact = self.m['artifacts'][name]
        env = {'STUB_ADMIN_BIND': f'{nodes[slot]}:{ports["projector_admin"]}',
               'STUB_PG_URL': self.projection_pg_url(self.projection_database(slot)), 'STUB_INSTANCE': slot,
               'STUB_MODE': artifact['mode'], 'STUB_CORE_PROBE': '/artifacts/core-probe.jar:/artifacts/ae.jar',
               'STUB_MEMBER_METRICS': ','.join(f'ae{i}@{nodes[f"ae{i}"]}:{core_contracts.engine_http_port(ports, f"ae{i}")}' for i in range(3)),
               **self.probe_env(None), 'CORE_LOCAL_HOST': nodes[slot], 'CORE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae')}
        env.update({k: str(v) for k, v in (getattr(self, 'projection_stub_settings', None) or {}).items()})
        return env

    def start_projection_slots(self, slots=None):
        """Start the projection slots after the gateway slots (a declared slot whose artifact is null is SKIPPED_ABSENT).
        Waits for the slot's /health, not its readiness: a standby copy is never ready."""
        for slot in slots or sorted(core_contracts.PROJECTION_SLOTS):
            name = self.slot_artifact(slot)
            if name is None:
                self.slots[slot] = {'state': 'SKIPPED_ABSENT', 'reason': 'this manifest stages nothing in ' + slot}
                continue
            if name == 'projector_stub':
                self.spawn(slot, ['python3', '-I', f'/artifacts/{name}/bin'], self.projection_slot_env(slot))
            else:
                if slot not in (self.registry.get('prepared_state') or {}):
                    self.prepare_projection_state(slot)
                self.spawn(slot, self.projector_slot_command(slot), self.projection_slot_env(slot))
            port, path = self.ready_target(slot)
            self.wait_http(slot, port, path, timeout=60)
            artifact = self.m['artifacts'][name]
            self.slots[slot] = {'state': 'STARTED', 'artifact': name, 'sha256': artifact['sha256'],
                                'source_sha': artifact['source_sha'], 'driver': artifact['driver'], 'target': artifact['target'],
                                'mode': artifact.get('mode'), 'database': self.projection_database(slot), 'readiness': path}
            if artifact.get('defines'):
                self.slots[slot]['defines'] = list(artifact['defines'])
            if name != 'projector_stub':
                self.slots[slot]['sources'] = self.projection_members(slot)
                self.slots[slot]['build'] = (self.projection_health(slot) or {}).get('build')
        self.registry['slots'] = self.slots
        self.save()
        return {s: self.slots.get(s) for s in (slots or sorted(core_contracts.PROJECTION_SLOTS))}

    def projection_health(self, slot):
        """The slot's own /health as JSON, or {'error': ...} when it does not answer. The projector binary's /health is
        read into the stand-in's flat keys (projector_health_view), its own body kept under ``raw``."""
        response = self.http(slot, self.m['ports']['projector_admin'], '/health')
        try:
            body = json.loads(response.get('body') or 'null') if response.get('status') == 200 else None
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return {'error': response}
        if self.slot_artifact(slot) in ('history_projector', 'history_projector_nc'):
            return projector_health_view(body, self.projection_members(slot), self.m['nodes'])
        return body

    # ---------------------------------------------------------------- the market-data slot

    MARKETDATA_EGRESS_PORT = 20500

    # A market-data drill may order the ME journal archives (member indexes, failover order: the first is followed first)
    # and give the commit-pause test build its two settings; both recorded by the drill
    marketdata_archive_order = None
    marketdata_env_overrides = None

    def marketdata_env(self, slot):
        """oe-marketdata's environment (gateway marketdata/MarketDataSettings.h): the required settings only. Its ME
        session on its own GATEWAY key of the ME table, the ME journal's archives as the bridge reads them (in member order,
        or in the order a drill set), the market history database under its writer role; every bound, size and timeout
        stays at the binary's default. A drill's overrides are the commit-pause test build's settings only."""
        nodes, ports = self.m['nodes'], self.m['ports']
        order = list(self.marketdata_archive_order or range(3))
        if sorted(order) != [0, 1, 2]:
            raise Violation(f'marketdata_archive_order names each ME member once: {order}')
        overrides = dict(self.marketdata_env_overrides or {})
        if set(overrides) - core_contracts.MARKETDATA_TEST_ENV:
            raise Violation('a drill overrides only ' + ', '.join(sorted(core_contracts.MARKETDATA_TEST_ENV)))
        artifact = self.m['artifacts'][self.slot_artifact(slot)]
        me = self.m['credentials']['me']
        env = {'MD_DRIVER_MODE': artifact['driver'], 'MD_INSTANCE_ID': str(self.keys.keys[(slot, 'me')][0]),
               'MD_ME_CLUSTER_ADDRESSES': ','.join(nodes[f'me{i}'] for i in range(3)),
               'MD_ME_PORT_BASE': str(ports['me_base']), 'CLUSTER_PORT_STRIDE': str(ports['stride']),
               'MD_ME_EGRESS_ENDPOINT': f'{nodes[slot]}:{self.MARKETDATA_EGRESS_PORT}',
               me['credential_env']: self.keys.credential(slot, 'me'),
               'MD_ME_JOURNAL_ARCHIVES': ','.join(f'{nodes[f"me{i}"]}:{ports["me_base"] + i * ports["stride"] + 10}'
                                                  for i in order),
               'MD_LOCAL_HOST': nodes[slot], 'MD_PUBLIC_BIND': f'{nodes[slot]}:{ports["md_public"]}',
               'MD_ADMIN_BIND': f'{nodes[slot]}:{ports["md_admin"]}',
               'MD_PG_URL': f'postgresql://{self.gateway}:{self.pg_port}/{core_contracts.MARKETDATA_DATABASE}',
               'MD_PG_USER': core_contracts.MARKETDATA_WRITER, 'MD_PG_PASSWORD_FILE': self.MARKETDATA_PASSWORD_FILE,
               'MD_CORS_ORIGINS': 'none', 'MD_EXPECTED_MARKETS': core_contracts.MARKETDATA_EXPECTED_MARKETS,
               **core_contracts.MARKETDATA_JOURNAL}
        if artifact['driver'] == 'external':
            env['AERON_DIR'] = '/dev/shm/aeron-' + slot
        else:
            env['MD_DRIVER_DIR'] = '/dev/shm'
        env.update({k: str(v) for k, v in overrides.items()})
        return env

    def marketdata_command(self, slot):
        """oe-marketdata as the container's pid 1: directly (embedded), or behind the staged aeronmd in the same container
        (external, the projector slots' wrapper)."""
        name = self.slot_artifact(slot)
        binary = f'/artifacts/{name}/bin'
        if self.m['artifacts'][name]['driver'] != 'external':
            return ['sh', '-c', f'exec {binary}']
        d = '/dev/shm/aeron-' + slot
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        alive = '"$(cat /data/aeronmd.pid)"'
        return ['sh', '-c', f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/{name} /artifacts/{name}/aeronmd & '
                            f'echo $! > /data/aeronmd.pid; i=0; '
                            f'while {{ [ ! -f {d}/cnc.dat ] || ! kill -0 {alive} 2>/dev/null; }} && [ $i -lt {DRIVER_WAIT_TENTHS} ]; '
                            f'do sleep 0.1; i=$((i+1)); done; '
                            f'[ -f {d}/cnc.dat ] && kill -0 {alive} 2>/dev/null || {{ echo "aeronmd did not come up in 30 s" >&2; exit 1; }}; '
                            f'exec {binary}']

    MARKETDATA_READY_BOUND_S = 90

    def start_marketdata_slots(self, slots=None):
        """Start the market-data slot after the gateway and projection slots (its ME session needs the ME's config; a
        declared slot whose artifact is null is SKIPPED_ABSENT). Waits for /ready/session, the ME session."""
        for slot in slots or sorted(core_contracts.MARKETDATA_SLOTS):
            name = self.slot_artifact(slot)
            if name is None:
                self.slots[slot] = {'state': 'SKIPPED_ABSENT', 'reason': 'this manifest stages nothing in ' + slot}
                continue
            self.spawn(slot, self.marketdata_command(slot), self.marketdata_env(slot))
            port, path = self.ready_target(slot)
            self.wait_http(slot, port, path, timeout=self.MARKETDATA_READY_BOUND_S)
            artifact = self.m['artifacts'][name]
            health = self.marketdata_health(slot)
            self.slots[slot] = {'state': 'STARTED', 'artifact': name, 'sha256': artifact['sha256'],
                                'source_sha': artifact['source_sha'], 'driver': artifact['driver'], 'target': artifact['target'],
                                'readiness': path, 'build': (health or {}).get('build')}
        self.registry['slots'] = self.slots
        self.save()
        return {s: self.slots.get(s) for s in (slots or sorted(core_contracts.MARKETDATA_SLOTS))}

    def marketdata_health(self, slot='md0'):
        """md0's own /health as JSON, or None when it does not answer."""
        response = self.http(slot, self.m['ports']['md_admin'], '/health')
        try:
            body = json.loads(response.get('body') or 'null')
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    def respawn_slot(self, name):
        """Start a stopped gateway or projection slot again in a NEW container from the same artifact, on the environment
        the fixture computes now (a drill changed the slot's database or sources before): the old container's log is kept
        as ``logs/<name>.gen<n>.log``, its state dir stays in place (keys and api-keys file), a gateway slot on a sidecar
        driver rejoins that same driver. Returns the witness; the fault row closes on the slot's readiness."""
        if name not in core_contracts.PROJECTION_SLOTS and name not in core_contracts.GATEWAY_SLOTS:
            raise Violation('respawn_slot starts a gateway or projection slot: ' + name)
        cid = self.registry['containers'].get(name)
        if cid is None or self.inspect('container', cid)['State']['Running']:
            raise Violation(f'respawn_slot needs {name} started once and now stopped')
        gen = 1
        while (self.root / 'logs' / f'{name}.gen{gen}.log').exists():
            gen += 1
        logs = self.command(['docker', 'logs', '--timestamps', cid], check=False)
        (self.root / 'logs' / f'{name}.gen{gen}.log').write_text(redact(logs.stdout + logs.stderr, self.secret_values))
        self.command(['docker', 'rm', cid])
        del self.registry['containers'][name]
        self.save()
        if name in core_contracts.PROJECTION_SLOTS:
            env = self.projection_slot_env(name)
            command = (self.projector_slot_command(name) if self.slot_artifact(name) != 'projector_stub'
                       else ['python3', '-I', f'/artifacts/{self.slot_artifact(name)}/bin'])
            self.spawn(name, command, env)
        else:
            join = self.registry['containers'].get(name + self.DRIVER_SIDECAR) if self.driver_sidecar(name) else None
            env = self.gateway_slot_env(name)
            self.spawn(name, self.gateway_slot_command(name), env, join=join)
        port, path = self.ready_target(name)
        self.wait_role_ready(name, port, path, timeout=90)
        self.close_fault(name)
        witness = {'kind': 'respawn', 'target': name, 'generation': gen, 'container_id': self.registry['containers'][name]}
        if name in core_contracts.PROJECTION_SLOTS:
            witness.update(database=self.projection_database(name), sources=(self.projection_members(name)
                                                                            if self.slot_artifact(name) != 'projector_stub' else None))
        else:
            witness['pg_url'] = env.get('GATEWAY_PG_URL', '').rsplit('@', 1)[-1]
        return self.record_fault(witness)

    def replay_count(self, member, streams):
        """The replay-count probe of one core member (replay_count.py inside the member's container): its driver's network
        publications on the given replay streams and the bytes of its /dev/shm."""
        if member not in ENGINES or not member.startswith('ae'):
            raise Violation('the replay-count probe reads a core member: ' + str(member))
        script = Path(__file__).with_name('replay_count.py').read_text()
        r = self.execute(member, ['python3', '-I', '-', ','.join(str(s) for s in streams)], input=script, timeout=30,
                         check=False)
        lines = [l for l in (r.stdout or '').splitlines() if l.startswith('{')]
        if r.returncode != 0 or not lines:
            return {'error': f'exit {r.returncode}: {(r.stderr or "")[-200:]}'}
        return json.loads(lines[-1])

    # ---------------------------------------------------------------- faults

    def open_fault(self, role, duration_s, heal_bound_s=60, reason=None):
        """Register ``role`` as a deliberate fault target for its duration plus the heal bound."""
        row_id = self.registry['fault_seq'] = self.registry.get('fault_seq', 0) + 1
        row = {'row_id': row_id, 'until_ns': time.time_ns() + int((duration_s + heal_bound_s) * 1e9)}
        if reason:
            row['reason'] = reason
        self.registry.setdefault('fault_targets', {})[role] = row
        self.save()
        return row_id

    def close_fault(self, role):
        """The heal was OBSERVED (ready, or the branch actually taken); only then is the row closed."""
        row = (self.registry.get('fault_targets') or {}).pop(role, None)
        self.save()
        return row

    def record_fault(self, witness):
        witness.setdefault('at_ns', time.time_ns())
        self.registry.setdefault('faults', []).append(witness); self.save()
        return witness

    def _fault_target(self, name):
        if (name not in set(ENGINES) | set(SLOTS) | core_contracts.GATEWAY_ROLES | core_contracts.PROJECTION_ROLES
                | core_contracts.MARKETDATA_ROLES | {'projector'}
                or name not in self.registry['containers']):
            raise Violation('unsupported or unstarted fault target: ' + name)
        return self.registry['containers'][name]

    def kill(self, name, heal_bound_s=KILL_HEAL_BOUND_S):
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if not before['Running']: raise Inconclusive('fault target was already stopped')
        self.command(['docker', 'kill', '--signal=KILL', cid])
        after = self.inspect('container', cid)['State']
        if after['Running'] or after['ExitCode'] != 137: raise Inconclusive('SIGKILL was not observed')
        self.registry.setdefault('last_kill', {})[name] = {'at': self.clock(), 'finished_at': after['FinishedAt']}
        row_id = self.open_fault(name, 0, heal_bound_s)
        return self.record_fault({'kind': 'kill', 'row_id': row_id, 'target': name, 'container_id': cid, 'before_running': True,
                                  'after_running': False, 'exit_observed': True, 'exit_code': after['ExitCode'],
                                  'before_pid': before['Pid'], 'finished_at': after['FinishedAt']})

    def pause(self, name, duration_s=15, heal_bound_s=60):
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if before['Paused']: raise Inconclusive('fault target was already paused')
        if not before['Running']: raise Inconclusive('fault target is not running')
        self.command(['docker', 'pause', cid])
        after = self.inspect('container', cid)['State']
        if not after['Paused']: raise Inconclusive('docker pause was not observed')
        row_id = self.open_fault(name, duration_s, heal_bound_s)
        return self.record_fault({'kind': 'pause', 'row_id': row_id, 'target': name, 'container_id': cid,
                                  'before_paused': False, 'after_paused': True, 'declared_duration_s': duration_s})

    def unpause(self, name):
        """Thaw. The fault row stays open: whether the process survived (reconnect) or exits 70 is the drill's branch."""
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if not before['Paused']: raise Inconclusive('fault target is not paused')
        self.command(['docker', 'unpause', cid])
        after = self.inspect('container', cid)['State']
        if after['Paused']: raise Inconclusive('docker unpause was not observed')
        return self.record_fault({'kind': 'unpause', 'target': name, 'container_id': cid, 'before_paused': True,
                                  'after_paused': False})

    # The state letter (proc(5) field 3) of the container's pid 1 and, when the slot runs a staged aeronmd, of that
    # driver. Shell builtins only: the slot image need not carry cut or awk.
    PROCESS_STATES = ('read -r a b c r < /proc/1/stat; echo "main $c"; '
                      'if [ -f /data/aeronmd.pid ]; then read -r p < /data/aeronmd.pid; '
                      'if [ -r /proc/$p/stat ]; then read -r a b c r < /proc/$p/stat; echo "driver $c"; '
                      'else echo "driver gone"; fi; fi')

    def process_states(self, name):
        """{'main': letter, 'driver': letter | 'gone'} of a running container (no 'driver' without a staged aeronmd). A
        slot with a driver sidecar: the driver's letter is its sidecar's pid 1, 'gone' when the sidecar is not running."""
        out = self.execute(name, ['sh', '-c', self.PROCESS_STATES], timeout=15, check=False)
        states = {}
        for text in (out.stdout or '').splitlines():
            key, _, value = text.strip().partition(' ')
            if key in ('main', 'driver') and value:
                states[key] = value
        if self.driver_sidecar(name):
            d = self.slot_driver(name)
            states['driver'] = (d.get('state') or 'gone') if d['running'] else 'gone'
            states['driver_sidecar'] = d['container']
        return states

    def freeze_main(self, name, duration_s=15, heal_bound_s=60):
        """SIGSTOP the container's pid 1 (the slot command execs oe-gateway or oe-stream, so pid 1 is the binary). The
        daemon sends it (``docker kill --signal=STOP``): a signal from inside the container cannot stop its own pid 1. An
        external driver (the slot's sidecar, or the session stub's staged aeronmd) is a separate process and keeps
        running; an embedded driver is part of the stopped process. The witness records both states as observed."""
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if not before['Running'] or before['Paused']:
            raise Inconclusive('fault target is not running: ' + name)
        self.command(['docker', 'kill', '--signal=STOP', cid])
        states = self.process_states(name)
        if states.get('main') != 'T':
            raise Inconclusive(f'SIGSTOP of {name} pid 1 was not observed: {states}')
        row_id = self.open_fault(name, duration_s, heal_bound_s)
        return self.record_fault({'kind': 'sigstop', 'row_id': row_id, 'target': name, 'container_id': cid, 'pid': 1,
                                  'main_state': states['main'], 'driver_state': states.get('driver'),
                                  'declared_duration_s': duration_s})

    def thaw_main(self, name):
        """SIGCONT the container's pid 1. The fault row stays open: whether the process reconnects or exits 70 is the
        drill's branch."""
        cid = self._fault_target(name)
        self.command(['docker', 'kill', '--signal=CONT', cid])
        running = self.inspect('container', cid)['State']['Running']
        states = self.process_states(name) if running else {}
        if states.get('main') == 'T':
            raise Inconclusive(f'SIGCONT of {name} pid 1 was not observed: {states}')
        return self.record_fault({'kind': 'sigcont', 'target': name, 'container_id': cid, 'pid': 1, 'running': running,
                                  'main_state': states.get('main'), 'driver_state': states.get('driver')})

    def exec_kill(self, name, pidfile, signal='KILL', heal_bound_s=60):
        """Kill the process whose pid a file in the container's /data holds (the staged aeronmd, C13)."""
        if signal not in {'KILL', 'TERM'}:
            raise Violation('exec_kill supports KILL and TERM only (never a stop signal)')
        if not re.fullmatch(r'/data/[A-Za-z0-9._-]+\.pid', pidfile):
            raise Violation('exec_kill reads a pid file under /data only')
        self._fault_target(name)
        out = self.execute(name, ['sh', '-c', f'p=$(cat {pidfile}); echo $p; kill -{signal} $p'], timeout=15)
        pid = int(out.stdout.strip().splitlines()[0])
        row_id = self.open_fault(name, 0, heal_bound_s)
        return self.record_fault({'kind': 'exec_kill', 'row_id': row_id, 'target': name, 'pidfile': pidfile, 'pid': pid, 'signal': signal})

    def wait_exit(self, name, code, bound_s):
        """Wait for the container to exit with ``code`` (an int, or 'nonzero': C13 asserts non-zero and records the value).
        An engine's exit is recorded in last_kill, so restart()'s 12.5 s AE rule fires after a driver death."""
        cid = self._fault_target(name)
        started = deadline = self.clock(); deadline += bound_s
        while True:
            state = self.inspect('container', cid)['State']
            if not state['Running']:
                seen = state['ExitCode']
                if (seen == 0) if code == 'nonzero' else (seen != code):
                    raise Inconclusive(f'{name} exited {seen}, expected {code}')
                if name in ENGINES or name == 'shadow0':
                    self.registry.setdefault('last_kill', {})[name] = {'at': self.clock(), 'finished_at': state['FinishedAt'],
                                                                       'cause': 'exit', 'exit_code': seen}
                return self.record_fault({'kind': 'exit', 'target': name, 'exit_code': seen, 'expected': code,
                                          'finished_at': state['FinishedAt'], 'waited_s': round(self.clock() - started, 3)})
            if self.clock() >= deadline:
                raise Inconclusive(f'{name} did not exit within {bound_s} s')
            self.sleep(0.25)

    def restart(self, name, ready_timeout=60, readiness=None, wait_ready=True):
        """``docker start`` a killed or exited container (same state dir, same env) and return once /ready answers 200.
        An AE member is not started before 12.5 s after its kill (measured: earlier it hangs on the old archive mark
        file with the container Up). A gateway or stream slot on a sidecar driver must come back on that SAME driver;
        any other external slot (the session stub's in-container driver included) must come back on a NEW driver."""
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if before['Running']: raise Inconclusive('restart target is still running: ' + name)
        old = (self.registry.get('driver_identity') or {}).get(name)
        waited = None
        killed = (self.registry.get('last_kill') or {}).get(name)
        if (name.startswith('ae') or name == 'shadow0') and killed:
            minimum = core_contracts.SHADOW_RESTART_MIN_AFTER_KILL_S if name == 'shadow0' else AE_RESTART_MIN_AFTER_KILL_S
            remaining = killed['at'] + minimum - self.clock()
            if remaining > 0:
                self.sleep(remaining)
            waited = round(self.clock() - killed['at'], 3)
        self.command(['docker', 'start', cid])
        started = self.inspect('container', cid)['State']
        if not wait_ready:
            # A start whose outcome is the drill's to observe (the replica's re-bootstrap exits 3): the fault stays open
            witness = {'kind': 'start', 'target': name, 'container_id': cid, 'exit_code': before['ExitCode'],
                       'started_at': started['StartedAt'], 'ready': None}
            if waited is not None:
                witness['waited_after_kill_s'] = waited
            return self.record_fault(witness)
        port, path = self.ready_target(name)
        path = readiness or path
        self.wait_role_ready(name, port, path, timeout=ready_timeout, since=started['StartedAt'])
        witness = {'kind': 'restart', 'target': name, 'container_id': cid, 'before_running': False, 'exit_code': before['ExitCode'],
                   'after_running': True, 'started_at': started['StartedAt'], 'ready': True, 'readiness': path}
        if waited is not None:
            witness['waited_after_kill_s'] = waited
        if old is not None and self.driver_sidecar(name):
            # The driver has its own lifetime: the restarted binary must attach to the same sidecar driver
            new = self.driver_identity(name)
            if (new['sidecar'], new['started_at']) != (old['sidecar'], old['started_at']):
                raise Inconclusive(f'{name} came back on another driver: {old} -> {new}')
            witness['driver'] = {'reused': True, 'identity': new}
        elif old is not None:
            new = self.driver_identity(name)
            if new['cnc_mtime'] == old['cnc_mtime'] or new['started_at'] == old['started_at']:
                raise Inconclusive(f'{name} driver identity did not change across the restart: {old} -> {new}')
            self.registry['driver_identity'][name] = new
            witness['driver'] = {'old': old, 'new': new}
        self.close_fault(name)
        return self.record_fault(witness)

    # ---------------------------------------------------------------- lifecycle helpers

    def stop(self, name, signal='TERM', heal_bound_s=KILL_HEAL_BOUND_S):
        """A polite stop: ``docker kill --signal=TERM`` then ``docker stop -t <bound>`` (which kills at the bound). Forwarder
        and bridge must exit 0 (else INCONCLUSIVE "polite stop exited N", the witness recorded first); an engine's code is
        recorded (137 at 15 s before the polite-stop fix; with it 143 in 0.17-0.29 s, judged by the drills'
        engine_polite_stop line). An escalated stop is a kill and sets last_kill.
        Opens a fault row: the stopped role is a deliberate target until it is restarted or replaced."""
        if signal not in {'TERM', 'INT'}:
            raise Violation('stop sends TERM or INT only (a kill is kill(), a pause is pause())')
        kind = role_kind(name)
        if kind is None:
            raise Violation('unsupported stop target: ' + name)
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if not before['Running']:
            raise Inconclusive('stop target is not running: ' + name)
        bound = STOP_BOUND_S[kind]
        started = self.clock()
        self.command(['docker', 'kill', '--signal=' + signal, cid])
        self.command(['docker', 'stop', '-t', str(bound), cid], timeout=bound + 30)
        after = self.inspect('container', cid)['State']
        elapsed = round(self.clock() - started, 3)
        if after['Running']:
            raise Inconclusive(f'{name} is still running after docker stop -t {bound}')
        code = after['ExitCode']
        row_id = self.open_fault(name, 0, heal_bound_s, reason='stop')
        witness = {'kind': 'stop', 'row_id': row_id, 'target': name, 'container_id': cid, 'signal': signal, 'bound_s': bound,
                   'elapsed_s': elapsed, 'exit_code': code, 'escalated_to_kill': code == 137, 'before_pid': before['Pid'],
                   'finished_at': after['FinishedAt']}
        if kind == 'forwarder':
            witness['within_contract'] = elapsed <= FORWARDER_STOP_CONTRACT_S
        if code == 137:
            self.registry.setdefault('last_kill', {})[name] = {'at': self.clock(), 'finished_at': after['FinishedAt'],
                                                               'cause': 'stop escalated'}
        self.record_fault(witness)
        if kind in ('forwarder', 'bridge') and code != 0:
            raise Inconclusive(f'polite stop exited {code}: {name}')
        return witness

    def replace_slot(self, slot, artifact, after_kill=False, keep_state=False):
        """The only way a slot's binary changes. The slot must be stopped or exited; its state dir is kept as
        ``state/<slot>.gen<n>`` and its log as ``logs/<slot>.gen<n>.log``, the container is removed, the slot restarts from
        ``artifact`` (same env, key id and IP). ``after_kill``: a replacement that exits 78 (F7_REJECTED) inside the 10 s
        session window is witnessed and started once more after the window. The fault row closes on /ready 200.
        ``keep_state`` (A05-keep): the slot's state dir stays in place for the new binary, as a production unit
        restart does; the old container's log is still kept as evidence. In embedded mode the driver dir lives in the removed
        container's own /dev/shm tmpfs and cannot survive the replacement in this rig (recorded in the witness)."""
        if slot not in ('fwd0', 'fwd1', 'bridge0', 'bridge1'):
            raise Violation('replace_slot swaps a forwarder or bridge slot only: ' + slot)
        if self.m['artifacts'].get(artifact) is None:
            raise Violation(f'replace_slot: artifact {artifact} is absent from the manifest')
        if artifact not in core_contracts.SLOT_ARTIFACTS[slot]:
            raise Violation(f'slot {slot} cannot run artifact {artifact}')
        cid = self.registry['containers'].get(slot)
        if cid is None:
            raise Inconclusive('replace_slot: slot was never started: ' + slot)
        if self.inspect('container', cid)['State']['Running']:
            raise Violation(f'replace_slot needs the slot stopped or exited: {slot} is running')
        old_name = self.slot_artifact(slot)
        old, new = self.m['artifacts'][old_name], self.m['artifacts'][artifact]
        if old['sha256'] == new['sha256']:
            raise Violation(f'replace_slot with the same binary is not a swap: {slot} {old_name} -> {artifact} ({new["sha256"][:12]})')
        killed = (self.registry.get('last_kill') or {}).pop(slot, None)      # the kill witness belongs to the old container
        if after_kill and killed is None:
            raise Violation(f'replace_slot(after_kill=True): after_kill needs a kill witness for {slot}')
        state = self.root / 'state'
        gen = 1
        while (state / f'{slot}.gen{gen}').exists():
            gen += 1
        while keep_state and (self.root / 'logs' / f'{slot}.gen{gen}.log').exists():
            gen += 1
        logs = self.command(['docker', 'logs', '--timestamps', cid], check=False)
        (self.root / 'logs' / f'{slot}.gen{gen}.log').write_text(redact(logs.stdout + logs.stderr, self.secret_values))
        if keep_state:
            self.registry.setdefault('kept_state', {})[slot] = {'generation': gen, 'state_dir': str(state / slot)}
        else:
            (state / slot).rename(state / f'{slot}.gen{gen}')
        self.inspect('container', cid)
        self.command(['docker', 'rm', cid])
        del self.registry['containers'][slot]
        self.registry.setdefault('slot_override', {})[slot] = artifact
        self.save()
        self.spawn(slot, self.slot_command(slot), self.slot_process_env(slot))
        f7, ready_s = self._await_replacement(slot, gen, killed['at'] if after_kill else None)
        row = self.slot_row(slot, artifact)
        row['generation'] = gen
        self.slots[slot] = row
        self.registry.setdefault('slots', {})[slot] = row
        build = row['health'].get('build') if isinstance(row['health'], dict) else None
        self.close_fault(slot)
        witness = {'kind': 'replace_slot', 'target': slot, 'generation': gen, 'after_kill': after_kill,
                   'old': {'artifact': old_name, 'sha256': old['sha256'], 'source_sha': old['source_sha']},
                   'new': {'artifact': artifact, 'sha256': new['sha256'], 'source_sha': new['source_sha']},
                   'build_health': build, 'f7_rejected': f7, 'ready_after_s': ready_s, 'keep_state': keep_state}
        if keep_state:
            _, mode = self.slot_binary(slot)
            witness['state_dir'] = str(state / slot)
            witness['driver_dir'] = (f'/dev/shm/aeron-{slot}: the staged aeronmd deletes its dir on start (DRIVER_ENV)'
                                     if mode == 'external' else
                                     f'{EMBEDDED_DIRS["fwd" if slot.startswith("fwd") else "bridge"]}: in the removed container\'s '
                                     '/dev/shm tmpfs, not kept across a container replacement in the rig')
        if after_kill:
            witness.update(ready_after_kill_s=round(self.clock() - killed['at'], 3), ready_after_kill_bound_s=READY_AFTER_KILL_S)
        return self.record_fault(witness)

    def _await_replacement(self, slot, gen, kill_at):
        cid = self.registry['containers'][slot]
        port, path = self.ready_target(slot)
        started = self.clock()
        deadline, f7 = started + REPLACE_READY_BOUND_S, 0
        while True:
            state = self.inspect('container', cid)['State']
            if not state['Running']:
                code = state['ExitCode']
                if kill_at is not None and code == 78 and f7 == 0 and self.clock() - kill_at <= SESSION_WINDOW_S:
                    f7 = 1
                    logs = self.command(['docker', 'logs', '--timestamps', cid], check=False)
                    (self.root / 'logs' / f'{slot}.gen{gen}-f7.log').write_text(redact(logs.stdout + logs.stderr, self.secret_values))
                    self.record_fault({'kind': 'f7_rejected', 'target': slot, 'exit_code': code,
                                       'after_kill_s': round(self.clock() - kill_at, 3)})
                    remaining = kill_at + SESSION_WINDOW_S - self.clock()
                    if remaining > 0:
                        self.sleep(remaining)
                    self.command(['docker', 'start', cid])
                    deadline = self.clock() + REPLACE_READY_BOUND_S
                    continue
                raise Inconclusive(f'replacement {slot} exited {code} before /ready')
            if self.http(slot, port, path).get('status') == 200:
                return f7, round(self.clock() - started, 3)
            if self.clock() >= deadline:
                raise Inconclusive(f'replacement {slot} not ready within {REPLACE_READY_BOUND_S} s')
            self.sleep(0.1)

    def wipe_engine(self, role, projection_dump_required=True, reason=None):
        """Empty the member's bind-mounted state dir on the host (CF:243, 261), keeping the directory. The member must not be
        Running; the witness carries the byte count removed and the listing before. An AE member is the
        source of the life's money state, so its wipe needs that core life's projection dump on disk with the digest
        reset_projection recorded (a precondition, never a fallback: no dump, no wipe). The X runs' recovery line
        wipes members that ran on a foreign seed in a fixture where no money ever moved; ``projection_dump_required=False``
        names that with a ``reason`` (required), recorded in the witness."""
        if role not in ENGINES and role != 'shadow0':
            raise Violation('wipe_engine wipes an engine member or the replica only: ' + role)
        cid = self._fault_target(role)
        if self.inspect('container', cid)['State']['Running']:
            raise Violation('wipe_engine refuses a running member: ' + role)
        if role == 'shadow0':
            # The replica branch: its BASE_DIR holds a log copy and shadows, never the money state of a life
            projection_dump_required, reason = False, reason or 'replica: BASE_DIR holds a log copy and shadows, not a money source'
        if not projection_dump_required and not reason:
            raise Violation('wipe_engine without the projection dump needs a reason')
        if role.startswith('ae') and projection_dump_required:
            life = self.life('core')
            dump = (self.registry.get('projection_dumps') or {}).get(str(life))
            if not dump:
                raise Violation(f'wipe_engine refuses {role}: no projection dump of core life {life} (reset_projection first)')
            path = Path(dump['dump'])
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != dump['sha256']:
                raise Violation(f'wipe_engine refuses {role}: the core life {life} projection dump is missing or changed: {path}')
        state = self.root / 'state' / role
        listing, total = {}, 0
        for path in sorted(state.rglob('*')):
            if path.is_file() or path.is_symlink():
                size = path.lstat().st_size
                listing[str(path.relative_to(state))] = size
                total += size
        for child in list(state.iterdir()):
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        if any(state.iterdir()):
            raise Inconclusive('wipe_engine left files behind in ' + str(state))
        if role not in (self.registry.get('fault_targets') or {}):
            self.open_fault(role, 0, REGENESIS_HEAL_BOUND_S, reason='wiped')
        witness = {'kind': 'wipe_engine', 'target': role, 'bytes_removed': total, 'files_removed': len(listing),
                   'listing_before': listing}
        if not projection_dump_required:
            witness['projection_dump'] = 'not required: ' + reason
        return self.record_fault(witness)

    def wipe_shadows(self, role):
        """Remove a stopped AE member's shadow recordings from its bind-mounted archive: every ``<id>-<base>.rec`` whose
        catalog descriptor names the shadow stream (SHADOW_STREAM_ID). Everything else stays: the log and snapshots the
        member's ``cluster/recording.log`` names, and the money journal recording, which the projector reads. The member
        then holds no local shadow, so a stub restore must pull one. A segment file the catalog does not describe is
        refused (its stream is unknown), never guessed. The witness lists what was removed."""
        import release_cut
        if role not in ENGINES or not role.startswith('ae'):
            raise Violation('wipe_shadows wipes an AE member\'s shadows only: ' + role)
        cid = self._fault_target(role)
        if self.inspect('container', cid)['State']['Running']:
            raise Violation('wipe_shadows refuses a running member: ' + role)
        base = self.root / 'state' / role / 'state'
        log = base / 'cluster' / 'recording.log'
        if not log.is_file():
            raise Inconclusive(f'wipe_shadows: {role} has no recording.log')
        keep = {e['recording_id'] for e in release_cut.recording_log(log)}
        descriptors = catalog_descriptors(base / 'archive')
        files = sorted((base / 'archive').glob('*-*.rec'))
        unknown = sorted({int(p.stem.split('-')[0]) for p in files} - set(descriptors))
        if unknown:
            raise Inconclusive(f'wipe_shadows: {role} archive.catalog does not describe recordings {unknown}: their stream '
                               'is unknown, nothing removed')
        shadows = {rid for rid, d in descriptors.items() if d['stream'] == SHADOW_STREAM_ID and rid not in keep}
        doomed = [p for p in files if int(p.stem.split('-')[0]) in shadows]
        removed, total = {}, 0
        for path in doomed:
            rid = int(path.stem.split('-')[0])
            removed[path.name] = delete_shadow_segment(path, descriptors[rid], keep)
            total += removed[path.name]
        if role not in (self.registry.get('fault_targets') or {}):
            self.open_fault(role, 0, REGENESIS_HEAL_BOUND_S, reason='shadows wiped')
        return self.record_fault({'kind': 'wipe_shadows', 'target': role, 'kept_recordings': sorted(keep),
                                  'files_removed': removed, 'bytes_removed': total})

    def reset_projection(self, out_dir=None):
        """Stop the projector, dump every table of the run's money database to ``<out>/life-<n>/money_journal.pg.jsonl``
        (life-1 rows are evidence), then drop and recreate the database with the projector's packaged migrations,
        as start_database did. The projector comes back through restart() in the next life's genesis."""
        life = self.life('core')
        cid = self.registry['containers'].get('projector')
        stopped = None
        if cid is not None and self.inspect('container', cid)['State']['Running']:
            stopped = self.stop('projector', heal_bound_s=REGENESIS_HEAL_BOUND_S)
        directory = Path(out_dir) if out_dir else self.root / 'lives' / f'life-{life}'
        directory.mkdir(parents=True, exist_ok=True)
        dump = directory / 'money_journal.pg.jsonl'
        tables = json.loads(self.psql('r01_money', "SELECT COALESCE(json_agg(table_name ORDER BY table_name), '[]'::json) "
                                                   "FROM information_schema.tables WHERE table_schema = 'public' "
                                                   "AND table_type = 'BASE TABLE'") or '[]')
        counts = {}
        with dump.open('w') as out:
            for table in tables:
                if not re.fullmatch(r'[a-z_][a-z0-9_]*', table):
                    raise Violation('unexpected projection table name: ' + repr(table))
                rows = json.loads(self.psql('r01_money', f"SELECT COALESCE(json_agg(t), '[]'::json) FROM \"{table}\" t") or '[]')
                counts[table] = len(rows)
                for row in rows:
                    out.write(json.dumps({'table': table, 'row': row}) + '\n')
        digest = hashlib.sha256(dump.read_bytes()).hexdigest()
        self.registry.setdefault('projection_dumps', {})[str(life)] = {'dump': str(dump), 'sha256': digest}
        self.save()
        self.psql('postgres', 'DROP DATABASE r01_money WITH (FORCE)')
        self.create_money_database()
        return self.record_fault({'kind': 'reset_projection', 'life': life, 'dump': str(dump), 'dump_sha256': digest,
                                  'tables': counts, 'projector_stop_exit': stopped['exit_code'] if stopped else None})

    def start_members(self, engine, ready_timeout=90):
        """``docker start`` all three members of a stopped (wiped) cluster, then /ready on each: a single member cannot elect
        alone, so restart() (one member, waits /ready) does not fit. The AE 12.5 s rule and the new-driver check apply."""
        roles = [f'{engine}{i}' for i in range(3)]
        old = {r: (self.registry.get('driver_identity') or {}).get(r) for r in roles}
        for role in roles:
            cid = self._fault_target(role)
            if self.inspect('container', cid)['State']['Running']:
                raise Inconclusive('start_members: a member is still running: ' + role)
            killed = (self.registry.get('last_kill') or {}).get(role)
            if engine == 'ae' and killed:
                remaining = killed['at'] + AE_RESTART_MIN_AFTER_KILL_S - self.clock()
                if remaining > 0:
                    self.sleep(remaining)
            self.command(['docker', 'start', cid])
        for role in roles:
            self.wait_http(role, core_contracts.engine_http_port(self.m['ports'], role), '/ready', timeout=ready_timeout)
        drivers = {}
        for role in roles:
            if old[role] is not None:
                new = self.driver_identity(role)
                if new['cnc_mtime'] == old[role]['cnc_mtime'] or new['started_at'] == old[role]['started_at']:
                    raise Inconclusive(f'{role} driver identity did not change across the restart: {old[role]} -> {new}')
                self.registry['driver_identity'][role] = drivers[role] = new
            self.close_fault(role)
        return self.record_fault({'kind': 'start_members', 'engine': engine, 'ready': True, 'drivers': drivers})

    def regenesis(self, plan, scope):
        """``me``: stop me0-2, wipe their state, start a fresh ME, ME genesis with the next life's
        genesis id; the core stays bound to the old epoch (A04 life 1 is judged on it). ``core``: stop the forwarders (if
        still Running; in A04 they fenced themselves), the bridges and ae0-2, wipe the AE, reset the projection, start a
        fresh AE and run the life-2 genesis phases; projector, bridges and forwarders come back through restart(). The
        projection is dumped before the AE wipe (wipe_engine refuses an AE member without that dump)."""
        if scope not in ('me', 'core'):
            raise Violation('regenesis scope is me or core, got ' + repr(scope))
        lives = self.registry.setdefault('lives', {})
        boot_lives = self.registry.setdefault('boot', {}).setdefault('lives', {})
        containers = self.registry['containers']
        if scope == 'me':
            life = self.life('me') + 1
            gid = self.genesis_id(life)
            lives[str(life)] = {'me': {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000)},
                                'evidence_from': {'me': self.evidence_marks()}}      # Where life n's ME rows begin
            phases = boot_lives.setdefault(str(life), {}).setdefault('me_phases', {})
            phases['started_ns'] = time.time_ns()
            for fwd in ('fwd0', 'fwd1'):      # They exit 78 (F8_EPOCH) a few seconds after the first ME start
                if fwd in containers:
                    self.open_fault(fwd, 0, REGENESIS_HEAL_BOUND_S, reason='regenesis me: F8 epoch fence expected')
            stops = [self.stop(f'me{i}', heal_bound_s=REGENESIS_HEAL_BOUND_S) for i in range(3)]
            phases['stopped_ns'] = time.time_ns()
            wipes = [self.wipe_engine(f'me{i}') for i in range(3)]
            phases['wiped_ns'] = time.time_ns()
            self.start_members('me')
            phases['me_ready_ns'] = time.time_ns()
            self.me_genesis(plan)
            phases['me_genesis_ns'] = time.time_ns()
            self.save()
            return self.record_fault({'kind': 'regenesis', 'scope': 'me', 'life': life, 'genesis_id': gid,
                                      'stop_exit_codes': [(s or {}).get('exit_code') for s in stops],
                                      'wiped_bytes': [(w or {}).get('bytes_removed') for w in wipes]})
        life = self.life('core') + 1
        if 'me' not in lives.get(str(life), {}):
            raise Violation(f'regenesis core needs the ME re-genesis of life {life} first (regenesis(plan, "me"))')
        gid = self.genesis_id(life)
        lives[str(life)].setdefault('evidence_from', {})['core'] = self.evidence_marks()   # Life n's core rows
        lives.setdefault(str(life - 1), {})['records'] = copy.deepcopy(
            {k: self.registry.get(k) for k in ('tap', 'funding', 'genesis', 'genesis_snapshot', 'risk', 'slots')})
        exited, stops = {}, []
        for fwd in ('fwd0', 'fwd1'):
            if fwd not in containers:
                continue
            state = self.inspect('container', containers[fwd])['State']
            if state['Running']:
                stops.append(self.stop(fwd, heal_bound_s=REGENESIS_HEAL_BOUND_S))
            else:
                exited[fwd] = state['ExitCode']
                self.open_fault(fwd, 0, REGENESIS_HEAL_BOUND_S, reason='regenesis core: exited before the core re-genesis')
        for role in ('bridge0', 'bridge1', 'ae0', 'ae1', 'ae2'):
            if role in containers and self.inspect('container', containers[role])['State']['Running']:
                stops.append(self.stop(role, heal_bound_s=REGENESIS_HEAL_BOUND_S))
        self.reset_projection()        # The life's projection is dumped BEFORE the AE (its source) is wiped
        self.capture_core_genesis(life - 1)      # The life's core genesisId, read before its AE log is wiped
        wipes = [self.wipe_engine(f'ae{i}') for i in range(3)]
        self.start_members('ae')
        lives[str(life)]['core'] = {'genesis_id': gid}
        self.registry['funding'] = []
        phases = boot_lives.setdefault(str(life), {}).setdefault('phases', {})
        self.run_genesis_steps(plan, LIFE2_CORE_ORDER, phases)
        self.registry['genesis'] = {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000), 'life': life,
                                    'derivation': self.genesis_derivation()}       # The life-2 record checks it
        lives[str(life)]['core'].update(ledger_capacity=self.registry['genesis']['ledger_capacity'])
        self.save()
        check_genesis_order(phases, expected=LIFE2_CORE_PHASES)
        self.audit_genesis(life)
        return self.record_fault({'kind': 'regenesis', 'scope': 'core', 'life': life, 'genesis_id': gid,
                                  'forwarders_exited': exited, 'stop_exit_codes': {(s or {}).get('target'): (s or {}).get('exit_code')
                                                                                   for s in stops},
                                  'wiped_bytes': [(w or {}).get('bytes_removed') for w in wipes]})

    def partition(self, source, target, kind, action):
        """Drop one client's UDP path to an engine port, inside that owned client's namespace."""
        if source not in self.registry['containers']:
            raise Inconclusive('partition source is not running in this fixture: ' + source)
        outputs = []
        for arguments in partition_arguments(self.m, source, target, kind, action):
            outputs.append(self.netfilter(source, arguments))
        return outputs

    def netfilter(self, target, arguments):
        # A slot with a driver sidecar has the sidecar's network namespace (the sidecar holds the slot's address)
        cid = self.registry['containers'][target + self.DRIVER_SIDECAR if self.driver_sidecar(target) else target]
        state = self.inspect('container', cid)
        if not state['State']['Running'] or state['HostConfig']['NetworkMode'] != self.registry['network_id']:
            raise Inconclusive('netfilter target is not in its owned private network')
        helper = self.m.get('netfilter_helper')
        if not helper: raise Inconclusive('hash-pinned netfilter helper required')
        root = Path(helper['path']).resolve()
        for name, entry in helper['files'].items():
            source = (root / name).resolve()
            if not source.is_relative_to(root) or hashlib.sha256(source.read_bytes()).hexdigest() != entry['sha256']:
                raise Violation('netfilter helper digest or path mismatch')
        name = 'netfilter'
        if name in self.registry['containers']: raise Violation('another netfilter helper is active')
        argv = ['docker', 'create', '--name', self.run_id + '-' + name + '-' + uuid.uuid4().hex[:8],
                '--network', 'container:' + cid, '--label', LABEL + '=' + self.run_id,
                '--label', LABEL + '.token=' + self.token, '--user', '0', '--read-only',
                '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
                '--security-opt', 'no-new-privileges', '--pids-limit', '16', '--memory', '64m',
                '--memory-swap', '64m', '--cpus', '0.25', '--tmpfs', '/tmp:rw,nosuid,size=1m',
                '--env', 'XTABLES_LIBDIR=/tool/extensions', '--env', 'XTABLES_LOCKFILE=/tmp/xtables.lock',
                '--mount', 'type=bind,src=' + str(root) + ',dst=/tool,readonly',
                '--entrypoint', '/tool/ld.so', self.m['image'], '--library-path', '/tool',
                '/tool/iptables-legacy', *arguments]
        helper_id = self.command(argv).stdout.strip()
        self.registry['containers'][name] = helper_id; self.save()
        try:
            self.inspect('container', helper_id)
            output = self.command(['docker', 'start', '-a', helper_id], timeout=15)
            if self.inspect('container', helper_id)['State']['ExitCode'] != 0:
                raise Inconclusive('netfilter helper did not finish successfully')
            return output.stdout
        finally:
            self.inspect('container', helper_id)
            self.command(['docker', 'rm', '-f', helper_id])
            del self.registry['containers'][name]; self.save()
