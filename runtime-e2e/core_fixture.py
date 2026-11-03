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


def check_genesis_order(phases):
    """Contract 5.3: the empty snapshot and the tap come first; no deposit may precede either."""
    for name in GENESIS_PHASES:
        if name not in phases:
            raise Violation('genesis phase missing: ' + name)
    if phases['first_deposit_ns'] < phases['genesis_snapshot_ns'] or phases['first_deposit_ns'] < phases['tap_started_ns']:
        raise Violation('genesis snapshot after money moved')
    for earlier, later in zip(GENESIS_PHASES, GENESIS_PHASES[1:]):
        if phases[earlier] > phases[later]:
            raise Violation(f'genesis phase out of order: {later} before {earlier}')


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
        state = self.root / 'state' / name; state.mkdir(parents=True)
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
        return env

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
                'PROJECTOR_LOCAL_HOST': self.m['nodes']['projector'], 'PROJECTOR_METRICS_PORT': str(self.m['ports']['projector_http'])}

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

    def genesis_id(self):
        """The ME/core genesis identity: the manifest seed made odd, as T1 does (RUN: randbits(62) | 1). Recorded in the sample."""
        return hex(self.m['seed'] | 1)

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

    def start_tap(self, duration_ms):
        """Independent dispatch/order/admission witness (TOOL session, harness Q4), in the background."""
        cid = self.registry['containers']['probe']; self.inspect('container', cid)
        command = ['docker', 'exec', '-d']
        environment = self.probe_env('probe-tool')
        assert_production_timeouts(environment, self.allowed_env())
        for key, value in sorted(environment.items()): command += ['--env', f'{key}={value}']
        argv = JAVA + ['-cp', '/artifacts/core-probe.jar:/artifacts/ae.jar', 'CoreProbe', 'tap', 'out=/data/tap.jsonl',
                       f'duration_ms={int(duration_ms)}']
        self.command([*command, cid, 'sh', '-c', shlex.join(argv) + ' > /data/tap.out 2> /data/tap.err'])
        return self.root / 'state' / 'probe' / 'tap.jsonl'

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

    def read_tap_summary(self):
        """CoreProbe tap's exit lines: ``TAP first= last= rows= gaps=`` and the JSON summary (5.7 rule 1), plus its
        session-transition sidecar. Inconclusive while the tap JVM has not printed them (it is still running or died)."""
        out = self.root / 'state' / 'probe' / 'tap.out'
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

    def start(self, plan=None):
        """Boot the topology. ``plan=None`` is the S14 boot (empty core, slots up; core-boot). A ``plan`` runs the
        contract 5.3 genesis phases and leaves a funded, OPEN core with bridges and forwarders ready."""
        self.check_image(); self.stage_artifacts(); self.start_network(); self.start_database()
        self.spawn('probe', self.probe_command())
        boot = {'started_ns': time.time_ns(), 'phases': {}}
        self.registry['boot'] = boot
        for engine in ('ae', 'me'):
            for i in range(3):
                self.spawn(engine + str(i), JAVA + ['-jar', f'/artifacts/{engine}.jar'], self.engine_env(engine, i))
        for engine, port in [('ae', self.m['ports']['ae_metrics']), ('me', self.m['ports']['me_metrics'])]:
            for i in range(3): self.wait_http(engine + str(i), port, '/ready')
        boot['phases']['engines_ready_ns'] = time.time_ns()
        if plan is None:
            self.arm_money_journal(None); self.start_projector(None)
            for slot in sorted(SLOTS):
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
        order = [('snapshot_genesis', 'genesis_snapshot_ns'), ('start_tap_witness', 'tap_started_ns'),
                 ('me_genesis', 'me_genesis_ns'), ('arm_money_journal', 'money_journal_ns'),
                 ('start_projector', 'projector_ns'), ('start_bridges', 'bridges_ready_ns'),
                 ('core_genesis', 'core_bound_ns'), ('configure_risk', 'risk_ns'),
                 ('fund', 'funded_ns'), ('verify_funded', 'verified_ns'), ('start_forwarders', 'forwarders_ready_ns')]
        for step, phase in order:
            if step == 'fund':
                phases['first_deposit_ns'] = time.time_ns()
            getattr(self, step)(plan)
            phases[phase] = time.time_ns()
        self.registry['genesis'] = {'genesis_id': self.genesis_id(), 'ledger_capacity': plan.get('ledger_capacity', 100_000)}
        self.save()
        check_genesis_order(phases)

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
        started_ns = time.time_ns()
        path = self.start_tap(duration)
        self.registry['tap'] = {'path': str(path), 'started_ns': started_ns, 'duration_ms': duration}
        self.save()
        note = self.wait_tap_registered(path, started_ns)
        self.registry['tap'].update(registered_at_ms=note['at_ms'], registered_leader=note.get('leader'))
        self.save()

    def wait_tap_registered(self, path, started_ns, bound_s=TAP_REGISTER_BOUND_S):
        """Review F5: the tap's own 'registered' transition (its sessions sidecar, CoreProbe 5.7) is observed before any
        gate change; a fixed sleep was not evidence (a late registration loses [SUSPENDED, GENESIS] and O12 would FAIL on
        a host cause). Not seen within the bound: INCONCLUSIVE, never a guess."""
        sessions = path.with_name(path.name + '.sessions.jsonl')
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
                err = path.with_name('tap.err')
                tail = err.read_text()[-300:] if err.exists() else ''
                raise Inconclusive(f'the tap did not register within {bound_s} s (5.3 step 3): {tail}')
            self.sleep(0.2)

    def tap_gate(self, market=0):
        """The last admission row the tap recorded for ``market`` (0 = GLOBAL), or None: the observed gate state."""
        tap = Path(self.registry['tap']['path'])
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

    def _driver(self, key, main, *args, timeout=150):
        if key not in self.m:
            raise Inconclusive(f'manifest has no {key}: the genesis drivers are pinned through build_core_probes.py --ct-dir')
        jar = '/artifacts/' + key.replace('_', '-') + '.jar'
        base = '/artifacts/me.jar' if main == 'T1MeDriver' else '/artifacts/ae.jar'
        argv = JAVA + ['-cp', f'{jar}:{base}', main, *map(str, args)]
        return self.execute('probe', argv, environment=self.t1_env(), timeout=timeout)

    def _ingress(self, engine):
        nodes, ports = self.m['nodes'], self.m['ports']
        return ','.join(f'{i}={nodes[f"{engine}{i}"]}:{ports[engine + "_base"] + i * ports["stride"] + 2}' for i in range(3))

    def me_genesis(self, plan):
        """Step 4: EngineConfig FRESH through T1MeDriver (D-S15-2); markets 2..5 exist at the ME (PO-7)."""
        self._driver('t1_me_driver', 'T1MeDriver', 'genesis', PROBE_AERON_DIR, self._ingress('me'), self.genesis_id(),
                     plan.get('ledger_capacity', 100_000))

    def arm_money_journal(self, plan):
        meaning, reply = self.core('money-journal', 'probe-admin', state='on')
        if meaning != 'ANSWERED':
            raise Inconclusive('money journal could not be armed through the core probe: ' + meaning)

    def start_projector(self, plan):
        self.spawn('projector', JAVA + ['-jar', '/artifacts/projector.jar'], self.projector_env())
        self.wait_http('projector', self.m['ports']['projector_http'], '/health')

    def start_bridges(self, plan):
        """Step 6. The core's GLOBAL gate binds only through a bridge's FRESH 68, so no bridge is no genesis."""
        for slot in ('bridge0', 'bridge1'):
            self.slots[slot] = self.start_slot(slot)
        if not any(self.slots[s]['state'] == 'STARTED' for s in ('bridge0', 'bridge1')):
            raise Inconclusive('the core genesis binds the ME epoch through a bridge; both bridge slots are empty')

    def core_genesis(self, plan):
        """Step 7: CoreConfig 1 -> 2 -> 3, OPEN GLOBAL retried until the bridge binds the epoch. users = 0: no
        fire-and-forget deposits (T1C:269-281); the oracle-grade funding is step 9."""
        self._driver('t1_core_driver', 'T1CoreDriver', 'genesis', PROBE_AERON_DIR, self._ingress('ae'), self.genesis_id(),
                     plan.get('ledger_capacity', 100_000), 0, 'via-bridge')

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
        for i in range(3):
            events = journal_decode.decode_dump(self.journal_dump(f'me{i}'), profile, require_end=True)
            if [e['type'] for e in events] != ['engine_config']:
                raise Violation(f'me{i} journal is not a clean genesis: {[e["type"] for e in events]}')

    def start_forwarders(self, plan):
        for slot in ('fwd0', 'fwd1'):
            self.slots[slot] = self.start_slot(slot)
        for slot in ('shadow0',):
            self.slots[slot] = self.start_slot(slot)

    # ---------------------------------------------------------------- slots

    def slot_binary(self, slot):
        """(artifact name, driver mode) of the binary pinned for a slot; Inconclusive when the slot is empty."""
        name = self.m['slot_artifacts'][slot]
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
        artifact_name = self.m['slot_artifacts'][slot]
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
        row = {'state': 'STARTED', 'artifact': artifact_name, 'sha256': artifact['sha256'], 'source_sha': artifact['source_sha'],
               'driver': artifact['driver'], 'readiness': path}
        try:    # /health is the witness only (aeConnected, halted, meEpoch ...); readiness was /ready
            row['health'] = json.loads(self.http(slot, port, '/health')['body'])
        except (ValueError, KeyError, TypeError):
            row['health'] = None
        if artifact['driver'] == 'external':
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

    def open_fault(self, role, duration_s, heal_bound_s=60):
        """Register ``role`` as a deliberate fault target (F-S15-17) for its duration plus the heal bound."""
        row_id = self.registry['fault_seq'] = self.registry.get('fault_seq', 0) + 1
        self.registry.setdefault('fault_targets', {})[role] = {
            'row_id': row_id, 'until_ns': time.time_ns() + int((duration_s + heal_bound_s) * 1e9)}
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
        cid = self._fault_target(name)
        started = deadline = self.clock(); deadline += bound_s
        while True:
            state = self.inspect('container', cid)['State']
            if not state['Running']:
                if state['ExitCode'] != code:
                    raise Inconclusive(f'{name} exited {state["ExitCode"]}, expected {code}')
                return self.record_fault({'kind': 'exit', 'target': name, 'exit_code': code, 'finished_at': state['FinishedAt'],
                                          'waited_s': round(self.clock() - started, 3)})
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
