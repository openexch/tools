# SPDX-License-Identifier: Apache-2.0
"""Fixture v2: the OMS + ledger core topology (RC2 S14, harness H0 / 2.7).

Same ownership, evidence and teardown rules as the legacy Fixture (it is reused, not copied): every
Docker object carries the run label and an unpredictable token, nothing is reset, failed state is
kept. What changes: the role set (no OMS, no market gateway, no legacy bridge), per-run session keys
for AE and ME with secrets redacted from every retained log, the core probe and journal probe,
optional slots for the C++ forwarder and bridge that start from a pinned binary or are skipped and
said so, a reserved ``shadow0`` slot for RCS, cpuset-pinned engines and production timeouts (D20).
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
# RC2 S15 (contract 5.2). The staged aeronmd deletes its dir on start and shutdown so that a restart of a killed
# container (the tmpfs /dev/shm survives a kill) never attaches the new process to the dead driver's cnc.dat.
DRIVER_ENV = {'AERON_DIR_DELETE_ON_START': '1', 'AERON_DIR_DELETE_ON_SHUTDOWN': '1'}
EMBEDDED_DIRS = {'fwd': '/dev/shm/fwd-embedded', 'bridge': '/dev/shm/bridge-embedded'}
PROBE_AERON_DIR = '/dev/shm/probe-aeron'
DRIVER_WAIT_TENTHS = 300                      # 30 s for the staged aeronmd to publish its cnc.dat
TAP_REGISTER_BOUND_S = 30                     # review F5: the tap's 'registered' note, observed before ME genesis
AE_RESTART_MIN_AFTER_KILL_S = 12.5            # W0 answer 2: a restart earlier hits "active mark file detected" and hangs
KILL_HEAL_BOUND_S = 120
GENESIS_PHASES = ['genesis_snapshot_ns', 'tap_started_ns', 'me_genesis_ns', 'bridges_ready_ns', 'core_bound_ns',
                  'first_deposit_ns', 'funded_ns', 'forwarders_ready_ns']
# RC2 S16 5.1: a second core life runs on an ME that regenesis('me') already re-genesised, so it has no me_genesis phase
LIFE2_CORE_PHASES = [p for p in GENESIS_PHASES if p != 'me_genesis_ns']
GENESIS_ORDER = [('snapshot_genesis', 'genesis_snapshot_ns'), ('start_tap_witness', 'tap_started_ns'),
                 ('me_genesis', 'me_genesis_ns'), ('arm_money_journal', 'money_journal_ns'),
                 ('start_projector', 'projector_ns'), ('start_bridges', 'bridges_ready_ns'),
                 ('core_genesis', 'core_bound_ns'), ('configure_risk', 'risk_ns'),
                 ('fund', 'funded_ns'), ('verify_funded', 'verified_ns'), ('start_forwarders', 'forwarders_ready_ns')]
LIFE2_CORE_ORDER = [step for step in GENESIS_ORDER if step[0] != 'me_genesis']
# RC2 S16 5.1 stop(): the polite-stop bound per role (docker stop -t). Forwarder: exit 0, contract <= 1 s (RUN:465-472);
# bridge: exit 0 within 10 s (RUN:1768-1770); engines: 15 s then kill (20.1 line 4) is the escalation bound only; on the W9
# jars the code and time are judged by the drills' engine_polite_stop line (143 within ENGINE_SHUTDOWN_TIMEOUT_S + slack).
STOP_BOUND_S = {'forwarder': 3, 'bridge': 10, 'engine': 15, 'projector': 10}
FORWARDER_STOP_CONTRACT_S = 1.0
SESSION_WINDOW_S = 10.0          # the core's session timeout a killed forwarder's session outlives it by (F-S16-11)
READY_AFTER_KILL_S = 5.0         # 20.1 line 7: the ready_after_kill bound, a setting (measured 1.12 s in DR-A05)
REPLACE_READY_BOUND_S = 60       # stops a hung replacement wait; not a line
REGENESIS_HEAL_BOUND_S = 900     # a stopped or fenced role stays a fault target across both regenesis scopes and the halt phase
ENGINE_LIBS_DIR = '/artifacts/engine_libs'
PROJECTOR_LIBS_DIR = '/artifacts/projector_libs'      # RC2 S17 W2
ENGINE_DRIVER_PIDFILE = '/data/aeronmd.pid'
DEFAULT_RISK = {'version': 1, 'min_qty': 1, 'max_qty': 10**6 * FP, 'collar_bps': 5000, 'per_sec': 1000, 'max_open': 5000,
                'slippage_bps': 100}
PORT_OFFSETS = {'archive': 1, 'ingress': 2, 'member': 3, 'log': 4, 'transfer': 5}
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


def check_genesis_order(phases, expected=GENESIS_PHASES):
    """Contract 5.3: the empty snapshot and the tap come first; no deposit may precede either. ``expected`` is the phase
    list of the life being checked (S16 5.1: LIFE2_CORE_PHASES for a core re-genesis on an already re-genesised ME)."""
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
    """tick, min, max, lot of the market rows the T1CoreDriver genesis encodes (one literal row for every market)."""
    rows = {tuple(int(v.replace('_', '')) for v in hit) for hit in T1_ROW.findall(source)}
    if len(rows) != 1:
        raise Violation(f'T1CoreDriver: expected one literal market rows encoding, found {sorted(rows)}')
    tick, low, high, lot = rows.pop()
    return {'tick': tick, 'min': low, 'max': high, 'lot': lot}


def role_kind(name):
    """forwarder | bridge | engine | projector, or None for a role the fixture never stops politely."""
    if name in ENGINES:
        return 'engine'
    if name in ('fwd0', 'fwd1'):
        return 'forwarder'
    if name in ('bridge0', 'bridge1'):
        return 'bridge'
    return 'projector' if name == 'projector' else None


def partition_arguments(manifest, source, target, kind, action):
    """iptables arguments for a (src role, dst role, port kind) UDP drop, applied in the source's namespace.

    Engines are addressed per member (``ae1``) or as a whole cluster (``ae``). The rule sits on OUTPUT in
    the source container, so only that client's packets to that port are lost (G10: forwarder -> ME,
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


class CoreFixture(Fixture):
    # time seams: the fault helpers wait on real time, the unit tests on a fake clock
    clock = staticmethod(time.time)
    sleep = staticmethod(time.sleep)

    def __init__(self, manifest_path, attach=False, keyring=None, drill=False):
        """``drill=True`` (the S15 drills) refuses an ME whose artifact does not enforce credentials; core-boot keeps both."""
        self.manifest_path = Path(manifest_path).absolute()
        self.m = json.loads(self.manifest_path.read_text())
        validate_core_manifest(self.m, self.manifest_path, require_me_enforced=drill)
        # RC2 S16 5.2: the edk-cnctimeout control's switch, refused on every other manifest before the box is touched
        self.engine_driver_skip = core_contracts.check_engine_driver_skip(self.m, self.manifest_path,
                                                                          os.environ.get('ENGINE_DRIVER_SKIP'))
        self.root = Path(self.m['state_root'])
        self.run_id = self.m['run_id']
        self.gateway = str(ipaddress.ip_network(self.m['network']['subnet']).network_address + 1)
        self.pg = Path(self.m['postgres_bin'])
        self.pg_port = self.m['postgres_port']
        if type(self.pg_port) is not int or not 1024 < self.pg_port < 65536:
            raise Violation('invalid fixture postgres port')
        self.keys = keyring or KeyRing()
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
        for role in core_contracts.OPTIONAL_BINARIES:
            artifact = self.m['artifacts'][role]
            if artifact is None:
                continue
            target = dest / role; target.mkdir()
            what = 'slot artifact changed while staging: ' + role
            self._stage(artifact['path'], target / 'bin', artifact['sha256'], what, 0o755)
            for name, lib in (artifact.get('libs') or {}).items():
                # contract 3.2: only a lib with exec: true (aeronmd) gets the exec bit; the shared objects do not
                self._stage(lib['path'], target / name, lib['sha256'], what, 0o755 if lib.get('exec') else 0o644)
        # RC2 S16 5.3: the engine containers' staged aeronmd and its pinned properties; RC2 S17 W2: the projector's, the same set
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
        self.create_money_database()

    def create_money_database(self):
        """The run's money database and the projector jar's packaged migrations (start_database, and reset_projection)."""
        self.psql('postgres', 'CREATE DATABASE r01_money')
        with zipfile.ZipFile(self.m['artifacts']['projector']['path']) as jar:
            schemas = sorted(n for n in jar.namelist() if n.startswith('db/migration/V') and n.endswith('.sql'))
            if not schemas: raise Inconclusive('missing packaged projector schema')
            for name in schemas:
                self.psql('r01_money', jar.read(name).decode())

    # ---------------------------------------------------------------- processes

    def spawn(self, name, command, environment=None):
        if name not in self.m['nodes'] or name in self.registry['containers']:
            raise Violation('unknown or duplicate fixture process')
        assert_production_timeouts(environment or {}, self.allowed_env())
        if any(core_contracts.JVM_TIMEOUT.search(str(a)) for a in command):
            raise Violation('D20: refusing a JVM timeout override for ' + name)
        # RC2 S17 W3: a seeded member (seed_state) or a slot replaced with keep_state starts on the dir already in place
        prepared = name in (self.registry.get('seeded') or {}) or name in (self.registry.get('kept_state') or {})
        bound = (self.registry.get('bound_state') or {}).get(name)     # review V1: a member bound to another fixture's root
        state = self.root / 'state' / name
        if bound:
            state = Path(bound)
        else:
            state.mkdir(parents=True, exist_ok=prepared)
        limits = self.m['limits']
        memory_mb = (limits.get('memory_mb_by_role') or {}).get(name, limits['memory_mb'])
        shm_mb = (limits.get('shm_mb_by_role') or {}).get(name, limits['shm_mb'])
        cpus = limits['cpu_set_by_role'].get(name, self.m['cpu_set'])
        args = ['docker', 'create', '--name', self.run_id + '-' + name,
                '--network', self.registry['network_id'], '--ip', self.m['nodes'][name],
                '--label', LABEL + '=' + self.run_id, '--label', LABEL + '.token=' + self.token,
                '--user', f'{os.getuid()}:{os.getgid()}', '--workdir', '/data', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
                '--memory', str(memory_mb) + 'm', '--memory-swap', str(memory_mb) + 'm',
                '--cpuset-cpus', ','.join(map(str, cpus)),
                '--cpus', str(limits.get('cpu_quota_by_role', {}).get(name, 1)),
                '--shm-size', str(shm_mb) + 'm', '--tmpfs', '/tmp:rw,nosuid,size=128m',
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
               'CLUSTER_PORT_BASE': str(self.m['ports'][engine + '_base'])}
        if engine == 'me':
            env.update(METRICS_PORT=str(self.m['ports']['me_metrics']), SETTLEMENT_JOURNAL_ENABLED='true',
                       SETTLEMENT_JOURNAL_DIR='/data/journal', SETTLEMENT_JOURNAL_ARCHIVE_BIND='0.0.0.0')
            env['MATCH_ENGINE_FROM_CONFIG'] = 'true'    # RUN:158: the replicated EngineConfig decides, not an env knob
            env[self.m['credentials']['me']['keys_env']] = self.keys.table('me')
        else:
            env['ASSETS_NODE_PORT'] = str(self.m['ports']['ae_metrics'])
            env['ASSETS_AUTH_KEYS'] = self.keys.table('ae')
        if self.engine_driver() == 'external':
            # RC2 S16 5.3: TC:84-91 / ATC:37-42 external mode attaches to the wrapper's aeronmd at AERON_DIR (TC:155, ATC:70)
            env.update(TRANSPORT_DRIVER_MODE='external', AERON_DIR=f'/dev/shm/aeron-{engine}{index}')
        return env

    def engine_driver(self):
        """5.2: ``embedded`` (dev default, D-S15-4) or ``external`` (the staged aeronmd in the engine container, C13)."""
        return self.m.get('engine_driver', 'embedded')

    def projector_driver(self):
        """RC2 S17 W2 (W10, PO-11 (a)): ``embedded`` (the default; the projector's own Java driver) or ``external`` (the staged
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
        """5.3: embedded engines run ``java -jar`` as before; external engines run through the S15 wrapper shape (CF:347-356):
        a fresh driver dir, the staged aeronmd on the pinned driver.properties plus the dev overlay in the background with its
        pid in /data (exec_kill), a 30 s wait for its cnc.dat with the driver alive, then ``exec java`` (the engine's own
        awaitExternalDriver is the second wait, TC:266-283, ATC:117-131). A member named by ENGINE_DRIVER_SKIP (control
        edk-cnctimeout only, 5.2) starts java with no driver at all."""
        role = engine + str(index)
        jar = JAVA + ['-jar', f'/artifacts/{engine}.jar']
        if self.engine_driver() != 'external':
            return jar
        d = '/dev/shm/aeron-' + role
        if role in getattr(self, 'engine_driver_skip', ()):
            return ['sh', '-c', f'rm -rf {d}; mkdir -p {d}; exec {shlex.join(jar)}']
        return self._driver_wrapper(role, ENGINE_LIBS_DIR, jar)

    def engine_driver_pidfile(self, role):
        """5.1: the pid file the engine wrapper writes, so exec_kill can kill an engine's staged aeronmd."""
        if role == 'projector':
            if self.projector_driver() != 'external':
                raise Violation(f'projector runs no staged driver (projector_driver {self.projector_driver()})')
            return ENGINE_DRIVER_PIDFILE
        if role not in ENGINES or self.engine_driver() != 'external':
            raise Violation(f'{role} runs no staged driver (engine_driver {self.engine_driver()})')
        return ENGINE_DRIVER_PIDFILE

    def probe_env(self, principal):
        env = {'CORE_AE_ADDRESSES': ','.join(self.m['nodes'][f'ae{i}'] for i in range(3)),
               'CORE_AE_PORT_BASE': str(self.m['ports']['ae_base']), 'CLUSTER_PORT_STRIDE': str(self.m['ports']['stride']),
               'CORE_LOCAL_HOST': self.m['nodes']['probe']}
        if principal is not None:
            env['AE_AUTH_CREDENTIAL'] = self.keys.credential(principal, 'ae')
        return env

    def t1_env(self):
        """Environment of the pinned T1 drivers (PROBE_ENV): the probe principals' credentials, 5 ME markets (PO-7)."""
        cred = self.keys.credential
        return {'T1_ADMIN_KEY': cred('probe-admin', 'ae'), 'T1_TOOL_KEY': cred('probe-tool', 'ae'),
                'T1_GATEWAY_KEY': cred('probe-gateway', 'ae'), 'T1_ME_ADMIN_KEY': cred('probe-admin', 'me'),
                'T1_ME_MARKETS': '5', 'T1_LOCAL_HOST': self.m['nodes']['probe']}

    def projector_env(self):
        return {'PROJECTOR_POSTGRES_URL': f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_money',
                'PROJECTOR_POSTGRES_USER': 'runtime_fixture', 'PROJECTOR_POSTGRES_PASSWORD': 'synthetic-fixture-only',
                'PROJECTOR_AE_JOURNAL_ARCHIVES': ','.join(self.m['nodes'][f'ae{i}'] + ':' + str(19301 + 100 * i) for i in range(3)),
                'PROJECTOR_LOCAL_HOST': self.m['nodes']['projector'], 'PROJECTOR_METRICS_PORT': str(self.m['ports']['projector_http']),
                **self.projector_driver_env()}

    def projector_driver_env(self):
        """RC2 S17 W2: no key in the manifest = the S16 env unchanged; embedded never sets AERON_DIR (ProjectorDriver refuses
        it); external names the staged driver's dir."""
        if 'projector_driver' not in self.m:
            return {}
        if self.projector_driver() == 'external':
            return {'PROJECTOR_DRIVER_MODE': 'external', 'AERON_DIR': '/dev/shm/aeron-projector'}
        return {'PROJECTOR_DRIVER_MODE': 'embedded'}

    def probe_command(self):
        """The probe idles; with pinned probe_libs it also runs the aeronmd the T1 drivers attach to (contract 3.3)."""
        if not (self.m.get('probe_libs') or {}).get('aeronmd'):
            return ['sleep', 'infinity']
        d = PROBE_AERON_DIR
        env = ' '.join(f'{k}={v}' for k, v in sorted(DRIVER_ENV.items()))
        script = (f'rm -rf {d}; mkdir -p {d}; AERON_DIR={d} {env} LD_LIBRARY_PATH=/artifacts/probe /artifacts/probe/aeronmd & '
                  f'echo $! > /data/aeronmd.pid; i=0; while [ ! -f {d}/cnc.dat ] && [ $i -lt {DRIVER_WAIT_TENTHS} ]; do sleep 0.1; i=$((i+1)); done; '
                  f'[ -f {d}/cnc.dat ] || {{ echo "probe aeronmd did not come up" >&2; exit 1; }}; exec sleep infinity')
        return ['sh', '-c', script]

    def genesis_id(self, life=1):
        """The ME/core genesis identity, odd and distinct per life (S16 5.1). RC2 S17 W3 (coordinator): derived from the run_id
        at run time (core_contracts.derive_genesis_id), not from the kind's constant seed, so RC2 step 7 sees a distinct id per
        genesis run; the rule is recorded with the genesis (genesis_derivation)."""
        return core_contracts.derive_genesis_id(self.run_id, life)

    def genesis_derivation(self):
        return {'rule': core_contracts.GENESIS_DERIVATION, 'run_id': self.run_id}

    def life(self, scope='core'):
        """The newest life whose ``scope`` (me | core) genesis has started (S16 5.1); 1 before any genesis record."""
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
        """core-boot control: an S6 ME refuses a session that presents no credential."""
        ingress = ','.join(f'{i}={self.m["nodes"][f"me{i}"]}:{self.m["ports"]["me_base"] + i * self.m["ports"]["stride"] + 2}'
                           for i in range(3))
        argv = JAVA + ['-cp', '/artifacts/journal-probe.jar:/artifacts/me.jar', 'JournalProbe', 'open-legs',
                       f'ingress={ingress}', f'local={self.m["nodes"]["probe"]}']
        return self.execute('probe', argv, timeout=90, check=False, accepted=(0, 1))

    def tap_paths(self, life=1):
        """S16 5.1: one tap per life, ``tap-life<n>.jsonl/.out/.err/.sessions.jsonl`` in the probe's /data (host: state/probe)."""
        stem = f'tap-life{int(life)}'
        host = self.root / 'state' / 'probe'
        return {k: host / (stem + suffix) for k, suffix in
                (('rows', '.jsonl'), ('out', '.out'), ('err', '.err'), ('sessions', '.sessions.jsonl'))}

    def start_tap(self, duration_ms, life=1):
        """Independent dispatch/order/admission witness (TOOL session, harness Q4), in the background, on per-life files."""
        cid = self.registry['containers']['probe']; self.inspect('container', cid)
        command = ['docker', 'exec', '-d']
        environment = self.probe_env('probe-tool')
        assert_production_timeouts(environment, self.allowed_env())
        for key, value in sorted(environment.items()): command += ['--env', f'{key}={value}']
        data = {k: '/data/' + v.name for k, v in self.tap_paths(life).items()}
        argv = JAVA + ['-cp', '/artifacts/core-probe.jar:/artifacts/ae.jar', 'CoreProbe', 'tap', f'out={data["rows"]}',
                       f'sessions={data["sessions"]}', f'duration_ms={int(duration_ms)}']
        self.command([*command, cid, 'sh', '-c', shlex.join(argv) + f' > {data["out"]} 2> {data["err"]}'])
        return self.tap_paths(life)['rows']

    def start_story(self, kv, name='story'):
        """S15 6: one ``CoreProbe story`` JVM in the background on the GATEWAY principal. Returns the host paths of its
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

    def funding_plan(self, script, users, seed):
        """The deposit table of ``CoreProbe story script=funding`` (no cluster), one owner of the amounts (section 6)."""
        meaning, reply = self.core('story', None, script='funding', seed=seed, users=','.join(map(str, users)),
                                   out='/data/funding-plan.jsonl', **{'for': script})
        if meaning != 'ANSWERED':
            raise Inconclusive('story funding plan: ' + meaning)
        rows = [json.loads(l)['row'] for l in (self.root / 'state' / 'probe' / 'funding-plan.jsonl').read_text().splitlines() if l]
        return [{'request': r['request'], 'user': r['user'], 'asset': r['asset'], 'amount': r['amount']} for r in rows]

    def read_tap_summary(self, life=None):
        """CoreProbe tap's exit lines: ``TAP first= last= rows= gaps=`` and the JSON summary (5.7 rule 1), plus its
        session-transition sidecar. Inconclusive while the tap JVM has not printed them (it is still running or died).
        ``life`` defaults to the current core life (S16 5.1)."""
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
        metric = 'assets_cluster_role' if engine == 'ae' else 'match_cluster_role'
        leaders = []
        for i in range(3):
            try:
                if self.metrics(f'{engine}{i}', self.m['ports'][engine + '_metrics']).get(metric) == 2.0:
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
        """Boot the topology. ``plan=None`` is the S14 boot (empty core, slots up; core-boot). A ``plan`` runs the
        contract 5.3 genesis phases and leaves a funded, OPEN core with bridges and forwarders ready."""
        self.check_image(); self.stage_artifacts(); self.start_network(); self.start_database()
        self.spawn('probe', self.probe_command())
        if before_engines is not None:          # RC2 S17 review V1: the X-R precheck, with the projection database up
            before_engines()
        boot = {'started_ns': time.time_ns(), 'phases': {}}
        self.registry['boot'] = boot
        for engine in ('ae', 'me'):
            for i in range(3):
                self.spawn(engine + str(i), self.engine_command(engine, i), self.engine_env(engine, i))
        for engine, port in [('ae', self.m['ports']['ae_metrics']), ('me', self.m['ports']['me_metrics'])]:
            for i in range(3): self.wait_http(engine + str(i), port, '/ready')
        if self.engine_driver() == 'external':
            # S16 5.1 (F-S16-7): every external engine's driver is registered, so restart() demands a NEW driver
            for role in ENGINES:
                if role not in getattr(self, 'engine_driver_skip', ()):
                    self.registry.setdefault('driver_identity', {})[role] = self.driver_identity(role)
            self.save()
        boot['phases']['engines_ready_ns'] = time.time_ns()
        if plan is None:
            self.arm_money_journal(None); self.start_projector(None)
            cut = str(self.m.get('manifest_kind', '')).startswith('s17')
            for slot in sorted(SLOTS):
                if cut and slot == 'fwd0':
                    # RC2 S17 W3 (coordinator): the cut forwarder waits for the ME epoch (not ready on a bare ME), so the
                    # cut's core-boot binds the epoch (the ME genesis, behaviour 2) before the forwarder slots
                    self.registry['lives'] = {'1': {'me': {'genesis_id': self.genesis_id(1)}}}
                    self.me_genesis({})
                    boot['phases']['me_genesis_ns'] = time.time_ns()
                self.slots[slot] = self.start_slot(slot)
        else:
            self.genesis(plan)
        boot['phases']['complete_ns'] = time.time_ns()
        self.registry['slots'] = self.slots; self.registry['boot'] = boot
        self.registry['startup_complete'] = True; self.save()

    # ---------------------------------------------------------------- genesis (contract 5.3)

    def genesis(self, plan):
        """Phases 2..11 of 5.3, in this order, with a timestamp per phase. ``plan``: {users, funding: [{user, asset,
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

    def audit_genesis(self):
        """Contract 7.2 / review V10: right after every s17 genesis the audit (3.5) is taken into ``audit.json`` of the state
        root; runner.py turns it and the run's evidence into ``rc2-activation-record.json``. Never fatal: the record judges it."""
        if not str(self.m.get('manifest_kind', '')).startswith('s17'):
            return None
        import r10_cut
        try:
            return r10_cut.audit_fixture(self, self.root / 'audit.json')
        except Exception as error:
            (self.root / 'audit.json').write_text(json.dumps({'status': 'ERROR', 'error': str(error)[:500], 'findings':
                                                              [str(error)[:300]], 'stopped': [], 'members_up': {}}) + '\n')
            return None

    def run_genesis_steps(self, plan, order, phases):
        for step, phase in order:
            if step == 'fund':
                phases['first_deposit_ns'] = time.time_ns()
            getattr(self, step)(plan)
            phases[phase] = time.time_ns()
            self.save()

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
        # S16 5.1: registry['tap'] is the current life's tap; every life's record stays under lives[n]
        self.registry['tap'] = {'path': str(path), 'started_ns': started_ns, 'duration_ms': duration, 'life': life,
                                'sessions': str(sessions)}
        self.registry.setdefault('lives', {}).setdefault(str(life), {})['tap'] = self.registry['tap']
        self.save()
        note = self.wait_tap_registered(path, started_ns, sessions=sessions)
        self.registry['tap'].update(registered_at_ms=note['at_ms'], registered_leader=note.get('leader'))
        self.save()

    def wait_tap_registered(self, path, started_ns, bound_s=TAP_REGISTER_BOUND_S, sessions=None):
        """Review F5: the tap's own 'registered' transition (its sessions sidecar, CoreProbe 5.7) is observed before any
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
                raise Inconclusive(f'the tap did not register within {bound_s} s (5.3 step 3): {tail}')
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
        base = '/artifacts/me.jar' if main == 'T1MeDriver' else '/artifacts/ae.jar'
        argv = JAVA + ['-cp', f'{jar}:{base}', main, *map(str, args)]
        return self.execute('probe', argv, environment=self.t1_env(), timeout=timeout, check=check, accepted=accepted)

    def _ingress(self, engine):
        nodes, ports = self.m['nodes'], self.m['ports']
        return ','.join(f'{i}={nodes[f"{engine}{i}"]}:{ports[engine + "_base"] + i * ports["stride"] + 2}' for i in range(3))

    def me_genesis(self, plan):
        """Step 4: EngineConfig FRESH through T1MeDriver (D-S15-2); markets 2..5 exist at the ME (PO-7)."""
        self._driver('t1_me_driver', 'T1MeDriver', 'genesis', PROBE_AERON_DIR, self._ingress('me'),
                     self.genesis_id(self.life('me')), plan.get('ledger_capacity', 100_000))

    def arm_money_journal(self, plan):
        meaning, reply = self.core('money-journal', 'probe-admin', state='on')
        if meaning != 'ANSWERED':
            raise Inconclusive('money journal could not be armed through the core probe: ' + meaning)

    def start_projector(self, plan):
        if 'projector' in self.registry['containers']:      # S16 5.1: a second life restarts the same container, never spawns
            self.restart('projector')
            return
        self.spawn('projector', self.projector_command(), self.projector_env())
        self.wait_http('projector', self.m['ports']['projector_http'], '/health')

    def start_or_restart_slot(self, slot):
        """start_slot on the first life; restart() of the same container on a later one (regenesis, S16 5.1)."""
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
        self._driver('t1_core_driver', 'T1CoreDriver', 'genesis', PROBE_AERON_DIR, self._ingress('ae'),
                     self.genesis_id(self.life('core')), plan.get('ledger_capacity', 100_000), 0, 'via-bridge')

    def t1_market(self):
        """W5 item 3: the market rows of the pinned T1CoreDriver genesis, read from its source (the W3 constant had maxPrice
        10^18, the driver sends 1_000_000_000_000_000L = 10^15: the tables differed, so the driver's re-run met STALE at
        CoreConfig 1, CoreConfigStateMachine.java:94-98 at eb559a7)."""
        return t1_market_rows(Path(self.m['t1_core_driver']['source_path']).read_text())

    def core_config(self, version, genesis_id=None):
        """RC2 S17 W3 (5.2 (iii)): one CoreConfig through ``CoreProbe core-config`` on the ADMIN principal, with the values the
        genesis driver sends (configVersion = behaviorVersion = version, the genesisId, its market rows), so a later driver run
        meets an equal record (DUPLICATE). Returns [version, AdminAck result name]."""
        gid = genesis_id or self.genesis_id(self.life('core'))
        meaning, reply = self.core('core-config', 'probe-admin', version=version, behavior=version, genesis=gid, **self.t1_market())
        acks = [r for r in (reply or {}).get('replies') or [] if r.get('t') == 'AdminAck']
        if not acks:
            raise Inconclusive(f'CoreConfig {version}: no AdminAck ({meaning})')
        return [version, acks[-1]['result']]

    def core_genesis_partial(self, plan, stop_after, genesis_id=None):
        """X-A2: the core genesis stopped after CoreConfig ``stop_after`` (1 or 2): the W0 scratch switch ``-Dt1.maxv=k`` as a
        harness option (the driver's three frames leave within 70 ms, so an outside kill cannot stop it, 20.1 line 12)."""
        if stop_after not in (1, 2):
            raise Violation('a partial genesis stops after CoreConfig 1 or 2, got ' + repr(stop_after))
        results = [self.core_config(v, genesis_id) for v in range(1, stop_after + 1)]
        row = {'stop_after': stop_after, 'genesis_id': genesis_id or self.genesis_id(self.life('core')), 'results': results}
        self.registry['partial_genesis'] = row; self.save()
        return row

    def core_genesis_finish(self, plan, genesis_id=None):
        """X-A2 recovery: CoreConfig 3 only (5.2 (iii)), measured."""
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
        ``funding_for`` takes the story's own deposit table (``CoreProbe story script=funding``, section 6)."""
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
        """S16 5.1: drill-time funding on the TOOL principal (A04's halt-time deposits and withdrawals), appended to
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
        # RC2 S17 W3 (5.2 (ii), 20.1 line 11): a member a scenario stopped (a registered fault target, not Running) is skipped
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
        """RC2 S17 W3 (5.2 (ii)): (members to read, members skipped) of an engine. Skipped: a registered fault target whose
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
        """RC2 S17 review V1 (X-R, 6.9 step 3: "the forward order on the same state roots"): the members' /data are the dirs of
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

    # ---------------------------------------------------------------- seeds (RC2 S17 W3, contract 5.2)

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
        """The artifact a slot runs: the manifest's, or the one replace_slot swapped in (S16 R7, witnessed)."""
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
                   'AE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'), 'FWD_ME_INGRESS': me_ingress,
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
               'BRIDGE_AE_CLUSTER_ADDRESSES': ','.join(nodes[f'ae{i}'] for i in range(3)),
               'BRIDGE_AE_PORT_BASE': str(ports['ae_base']), 'CLUSTER_PORT_STRIDE': str(ports['stride']),
               'BRIDGE_AE_EGRESS_ENDPOINT': nodes[slot] + ':19394', 'AE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'),
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
        is set only by the RED-1 drill (8.1: the nc forwarders may answer /ready 503 STALLED; liveness is /health)."""
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
            return ports[role[:2] + '_metrics'], '/ready'
        raise Violation('no readiness target for ' + role)

    def start_slot(self, slot):
        artifact_name = self.slot_artifact(slot)
        if slot == 'shadow0':
            if artifact_name is not None:
                raise Inconclusive('shadow0 is reserved for RCS S9; this fixture does not start a shadow replica')
            return {'state': 'RESERVED', 'reason': 'RCS S9 fills the shadow replica role'}
        artifact = self.m['artifacts'][artifact_name] if artifact_name else None
        if artifact is None:
            return {'state': 'SKIPPED_ABSENT', 'artifact': artifact_name,
                    'reason': 'no pinned binary for this slot yet (C++ ' + ('forwarder RC2 S12' if slot.startswith('fwd')
                                                                           else 'bridge RC2 S9/S10') + ')'}
        self.spawn(slot, self.slot_command(slot), self.slot_process_env(slot))
        port, path = self.ready_target(slot)
        self.wait_http(slot, port, path)
        return self.slot_row(slot, artifact_name)

    def slot_row(self, slot, artifact_name, register_driver=True):
        artifact = self.m['artifacts'][artifact_name]
        port, path = self.ready_target(slot)
        row = {'state': 'STARTED', 'artifact': artifact_name, 'sha256': artifact['sha256'], 'source_sha': artifact['source_sha'],
               'driver': artifact['driver'], 'readiness': path}
        try:    # /health is the witness only (aeConnected, halted, meEpoch ...); readiness was /ready
            row['health'] = json.loads(self.http(slot, port, '/health')['body'])
        except (ValueError, KeyError, TypeError):
            row['health'] = None
        if artifact['driver'] == 'external' and register_driver:
            self.registry.setdefault('driver_identity', {})[slot] = self.driver_identity(slot)
            self.save()
        return row

    def driver_identity(self, role):
        """cnc.dat mtime (ns) of the role's staged aeronmd plus the container's StartedAt. Inside a container the aeronmd
        pid is always 9 and the inode always 6 (W0 answer 5), so neither can tell two drivers apart."""
        out = self.execute(role, ['stat', '-c', '%.9Y', f'/dev/shm/aeron-{role}/cnc.dat'], timeout=15)
        started = self.inspect('container', self.registry['containers'][role])['State']['StartedAt']
        return {'cnc_mtime': out.stdout.strip(), 'started_at': started}

    # ---------------------------------------------------------------- faults

    def open_fault(self, role, duration_s, heal_bound_s=60, reason=None):
        """Register ``role`` as a deliberate fault target (F-S15-17) for its duration plus the heal bound."""
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
        if name not in set(ENGINES) | set(SLOTS) | {'projector'} or name not in self.registry['containers']:
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
        S16 5.1 (F-S16-7): an engine's exit is recorded in last_kill, so restart()'s 12.5 s AE rule fires after a driver death."""
        cid = self._fault_target(name)
        started = deadline = self.clock(); deadline += bound_s
        while True:
            state = self.inspect('container', cid)['State']
            if not state['Running']:
                seen = state['ExitCode']
                if (seen == 0) if code == 'nonzero' else (seen != code):
                    raise Inconclusive(f'{name} exited {seen}, expected {code}')
                if name in ENGINES:
                    self.registry.setdefault('last_kill', {})[name] = {'at': self.clock(), 'finished_at': state['FinishedAt'],
                                                                       'cause': 'exit', 'exit_code': seen}
                return self.record_fault({'kind': 'exit', 'target': name, 'exit_code': seen, 'expected': code,
                                          'finished_at': state['FinishedAt'], 'waited_s': round(self.clock() - started, 3)})
            if self.clock() >= deadline:
                raise Inconclusive(f'{name} did not exit within {bound_s} s')
            self.sleep(0.25)

    def restart(self, name, ready_timeout=60, readiness=None):
        """``docker start`` a killed or exited container (same state dir, same env) and return once /ready answers 200.
        An AE member is not started before 12.5 s after its kill (W0 answer 2: earlier it hangs on the old archive mark
        file with the container Up). An external slot must come back on a NEW driver."""
        cid = self._fault_target(name)
        before = self.inspect('container', cid)['State']
        if before['Running']: raise Inconclusive('restart target is still running: ' + name)
        old = (self.registry.get('driver_identity') or {}).get(name)
        waited = None
        killed = (self.registry.get('last_kill') or {}).get(name)
        if name.startswith('ae') and killed:
            remaining = killed['at'] + AE_RESTART_MIN_AFTER_KILL_S - self.clock()
            if remaining > 0:
                self.sleep(remaining)
            waited = round(self.clock() - killed['at'], 3)
        self.command(['docker', 'start', cid])
        started = self.inspect('container', cid)['State']
        port, path = self.ready_target(name)
        path = readiness or path
        self.wait_http(name, port, path, timeout=ready_timeout)
        witness = {'kind': 'restart', 'target': name, 'container_id': cid, 'before_running': False, 'exit_code': before['ExitCode'],
                   'after_running': True, 'started_at': started['StartedAt'], 'ready': True, 'readiness': path}
        if waited is not None:
            witness['waited_after_kill_s'] = waited
        if old is not None:
            new = self.driver_identity(name)
            if new['cnc_mtime'] == old['cnc_mtime'] or new['started_at'] == old['started_at']:
                raise Inconclusive(f'{name} driver identity did not change across the restart: {old} -> {new}')
            self.registry['driver_identity'][name] = new
            witness['driver'] = {'old': old, 'new': new}
        self.close_fault(name)
        return self.record_fault(witness)

    # ---------------------------------------------------------------- lifecycle helpers (RC2 S16 5.1)

    def stop(self, name, signal='TERM', heal_bound_s=KILL_HEAL_BOUND_S):
        """A polite stop: ``docker kill --signal=TERM`` then ``docker stop -t <bound>`` (which kills at the bound). Forwarder
        and bridge must exit 0 (else INCONCLUSIVE "polite stop exited N", the witness recorded first); an engine's code is
        recorded (20.1 line 4: 137 at 15 s before W9; on the W9 jars 143 in 0.17-0.29 s, judged by the drills'
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
            raise Inconclusive(f'polite stop exited {code}: {name} (contract 5.1)')
        return witness

    def replace_slot(self, slot, artifact, after_kill=False, keep_state=False):
        """R7: the only way a slot's binary changes. The slot must be stopped or exited; its state dir is kept as
        ``state/<slot>.gen<n>`` and its log as ``logs/<slot>.gen<n>.log``, the container is removed, the slot restarts from
        ``artifact`` (same env, key id and IP). ``after_kill``: a replacement that exits 78 (F7_REJECTED) inside the 10 s
        session window is witnessed and started once more after the window (F-S16-11). The fault row closes on /ready 200.
        ``keep_state`` (RC2 S17 W3, A05-keep): the slot's state dir stays in place for the new binary, as a production unit
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
        Running; the witness carries the byte count removed and the listing before. S16 fix round V6: an AE member is the
        source of the life's money state, so its wipe needs that core life's projection dump on disk with the digest
        reset_projection recorded (a precondition, never a fallback: no dump, no wipe). RC2 S17 W3: the X runs' recovery line
        wipes members that ran on a foreign seed in a fixture where no money ever moved; ``projection_dump_required=False``
        names that with a ``reason`` (required), recorded in the witness."""
        if role not in ENGINES:
            raise Violation('wipe_engine wipes an engine member only: ' + role)
        cid = self._fault_target(role)
        if self.inspect('container', cid)['State']['Running']:
            raise Violation('wipe_engine refuses a running member: ' + role)
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

    def reset_projection(self, out_dir=None):
        """Stop the projector, dump every table of the run's money database to ``<out>/life-<n>/money_journal.pg.jsonl``
        (F-S16-9: life-1 rows are evidence), then drop and recreate the database with the projector's packaged migrations,
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
        port = self.m['ports'][engine + '_metrics']
        for role in roles:
            self.wait_http(role, port, '/ready', timeout=ready_timeout)
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
        """S16 5.1 (F-REGEN, H:266). ``me``: stop me0-2, wipe their state, start a fresh ME, ME genesis with the next life's
        genesis id; the core stays bound to the old epoch (A04 life 1 is judged on it). ``core``: stop the forwarders (if
        still Running; in A04 they fenced themselves), the bridges and ae0-2, wipe the AE, reset the projection, start a
        fresh AE and run the life-2 genesis phases; projector, bridges and forwarders come back through restart(). The
        projection is dumped before the AE wipe (V6; wipe_engine refuses an AE member without that dump)."""
        if scope not in ('me', 'core'):
            raise Violation('regenesis scope is me or core, got ' + repr(scope))
        lives = self.registry.setdefault('lives', {})
        boot_lives = self.registry.setdefault('boot', {}).setdefault('lives', {})
        containers = self.registry['containers']
        if scope == 'me':
            life = self.life('me') + 1
            gid = self.genesis_id(life)
            lives[str(life)] = {'me': {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000)}}
            phases = boot_lives.setdefault(str(life), {}).setdefault('me_phases', {})
            phases['started_ns'] = time.time_ns()
            for fwd in ('fwd0', 'fwd1'):      # 20.1 line 6: they exit 78 (F8_EPOCH) a few seconds after the first ME start
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
        self.reset_projection()        # V6: the life's projection is dumped BEFORE the AE (its source) is wiped
        wipes = [self.wipe_engine(f'ae{i}') for i in range(3)]
        self.start_members('ae')
        lives[str(life)]['core'] = {'genesis_id': gid}
        self.registry['funding'] = []
        phases = boot_lives.setdefault(str(life), {}).setdefault('phases', {})
        self.run_genesis_steps(plan, LIFE2_CORE_ORDER, phases)
        self.registry['genesis'] = {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000), 'life': life}
        lives[str(life)]['core'].update(ledger_capacity=self.registry['genesis']['ledger_capacity'])
        self.save()
        check_genesis_order(phases, expected=LIFE2_CORE_PHASES)
        return self.record_fault({'kind': 'regenesis', 'scope': 'core', 'life': life, 'genesis_id': gid,
                                  'forwarders_exited': exited, 'stop_exit_codes': {(s or {}).get('target'): (s or {}).get('exit_code')
                                                                                   for s in stops},
                                  'wiped_bytes': [(w or {}).get('bytes_removed') for w in wipes]})

    def partition(self, source, target, kind, action):
        """G10: drop one client's UDP path to an engine port, inside that owned client's namespace."""
        if source not in self.registry['containers']:
            raise Inconclusive('partition source is not running in this fixture: ' + source)
        outputs = []
        for arguments in partition_arguments(self.m, source, target, kind, action):
            outputs.append(self.netfilter(source, arguments))
        return outputs

    def netfilter(self, target, arguments):
        cid = self.registry['containers'][target]
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
