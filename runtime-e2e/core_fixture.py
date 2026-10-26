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

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import ENGINES, PROCESS_ENV, SLOTS, assert_production_timeouts, check_image_config, validate_core_manifest
from credentials import KeyRing, redact
from fixture import JAVA, LABEL, Fixture

ENGINE_COMMON = {'CLUSTER_PORT_STRIDE': '100', 'BASE_DIR': '/data/state', 'TRANSPORT_DRIVER_MODE': 'embedded',
                 'TRANSPORT_IDLE_MODE': 'backoff', 'TRANSPORT_TERM_LENGTH': '1m', 'TRANSPORT_LOG_TERM_LENGTH': '1m',
                 'TRANSPORT_SNAPSHOT_TERM_LENGTH': '1m', 'MATCH_ENGINE_BOOK_CAPACITY': '4096',
                 'SNAPSHOT_LOG_BYTES': '1073741824', 'SNAPSHOT_INTERVAL_MINUTES': '5'}
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
    def __init__(self, manifest_path, attach=False, keyring=None):
        self.manifest_path = Path(manifest_path).absolute()
        self.m = json.loads(self.manifest_path.read_text())
        validate_core_manifest(self.m, self.manifest_path)
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
        sequence = self.registry['command_seq']; self.registry['command_seq'] += 1; self.save()
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

    def stage_artifacts(self):
        dest = self.root / 'artifacts'; dest.mkdir()
        for role in core_contracts.REQUIRED_JARS:
            artifact = self.m['artifacts'][role]
            path = dest / (role + '.jar'); shutil.copyfile(artifact['path'], path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != artifact['sha256']:
                raise Violation('artifact changed while staging: ' + role)
        for role in core_contracts.OPTIONAL_BINARIES:
            artifact = self.m['artifacts'][role]
            if artifact is None:
                continue
            target = dest / role; target.mkdir()
            path = target / 'bin'; shutil.copyfile(artifact['path'], path); path.chmod(0o755)
            files = [(path, artifact['sha256'])]
            for name, lib in (artifact.get('libs') or {}).items():
                copy = target / name; shutil.copyfile(lib['path'], copy); files.append((copy, lib['sha256']))
            for file, digest in files:
                if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                    raise Violation('slot artifact changed while staging: ' + role)
        for key, filename in [('core_probe', 'core-probe.jar'), ('journal_probe', 'journal-probe.jar')]:
            path = dest / filename; shutil.copyfile(self.m[key]['path'], path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != self.m[key]['sha256']:
                raise Violation('probe changed while staging: ' + key)

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
        cpus = limits['cpu_set_by_role'].get(name, self.m['cpu_set'])
        args = ['docker', 'create', '--name', self.run_id + '-' + name,
                '--network', self.registry['network_id'], '--ip', self.m['nodes'][name],
                '--label', LABEL + '=' + self.run_id, '--label', LABEL + '.token=' + self.token,
                '--user', f'{os.getuid()}:{os.getgid()}', '--workdir', '/data', '--read-only',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
                '--memory', str(limits['memory_mb']) + 'm', '--memory-swap', str(limits['memory_mb']) + 'm',
                '--cpuset-cpus', ','.join(map(str, cpus)),
                '--cpus', str(limits.get('cpu_quota_by_role', {}).get(name, 1)),
                '--shm-size', str(limits['shm_mb']) + 'm', '--tmpfs', '/tmp:rw,nosuid,size=128m',
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
        assert_production_timeouts(environment or {}, self.allowed_env() | {'ME_AUTH_CREDENTIAL'})
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

    def metrics(self, role, port):
        response = self.http(role, port, '/metrics')
        if response['status'] != 200:
            raise Inconclusive(f'{role} metrics unavailable: {response.get("status")}')
        return parse_prometheus(response['body'])

    def start(self):
        self.check_image(); self.stage_artifacts(); self.start_network(); self.start_database()
        self.spawn('probe', ['sleep', 'infinity'])
        boot = {'started_ns': time.time_ns(), 'phases': {}}
        for engine in ('ae', 'me'):
            for i in range(3):
                self.spawn(engine + str(i), JAVA + ['-jar', f'/artifacts/{engine}.jar'], self.engine_env(engine, i))
        for engine, port in [('ae', self.m['ports']['ae_metrics']), ('me', self.m['ports']['me_metrics'])]:
            for i in range(3): self.wait_http(engine + str(i), port, '/ready')
        boot['phases']['engines_ready_ns'] = time.time_ns()
        meaning, reply = self.core('money-journal', 'probe-admin', state='on')
        if meaning != 'ANSWERED':
            raise Inconclusive('money journal could not be armed through the core probe: ' + meaning)
        db = {'PROJECTOR_POSTGRES_URL': f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_money',
              'PROJECTOR_POSTGRES_USER': 'runtime_fixture', 'PROJECTOR_POSTGRES_PASSWORD': 'synthetic-fixture-only',
              'PROJECTOR_AE_JOURNAL_ARCHIVES': ','.join(self.m['nodes'][f'ae{i}'] + ':' + str(19301 + 100 * i) for i in range(3)),
              'PROJECTOR_LOCAL_HOST': self.m['nodes']['projector'], 'PROJECTOR_METRICS_PORT': str(self.m['ports']['projector_http'])}
        self.spawn('projector', JAVA + ['-jar', '/artifacts/projector.jar'], db)
        self.wait_http('projector', self.m['ports']['projector_http'], '/health')
        for slot in sorted(SLOTS):
            self.slots[slot] = self.start_slot(slot)
        boot['phases']['complete_ns'] = time.time_ns()
        self.registry['slots'] = self.slots; self.registry['boot'] = boot
        self.registry['startup_complete'] = True; self.save()

    # ---------------------------------------------------------------- slots

    def slot_env(self, slot):
        nodes, ports = self.m['nodes'], self.m['ports']
        ae_ingress = ','.join(f'{i}={nodes[f"ae{i}"]}:{ports["ae_base"] + i * ports["stride"] + 2}' for i in range(3))
        me_ingress = ','.join(f'{i}={nodes[f"me{i}"]}:{ports["me_base"] + i * ports["stride"] + 2}' for i in range(3))
        if slot.startswith('fwd'):
            env = {'FWD_CORE_INGRESS': ae_ingress, 'FWD_CORE_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:0',
                   'AE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'), 'FWD_ME_INGRESS': me_ingress,
                   'FWD_ME_RESPONSE_CHANNEL': f'aeron:udp?endpoint={nodes[slot]}:0', 'AERON_DIR': '/dev/shm/aeron',
                   'FWD_RING_CAPACITY': '65536', 'FWD_TICK_CAP_MS': '100', 'FWD_HEAD_PROBE_MS': '10000',
                   'FWD_KEEPALIVE_MS': '1000', 'FWD_HTTP_PORT': str(ports['forwarder_http']), 'FWD_TICKS_ENABLED': 'true',
                   'FWD_RELEASE_RELAY': 'false'}
            env[self.m['credentials']['me']['credential_env']] = self.keys.credential(slot, 'me')
            return env
        return {'BRIDGE_ME_JOURNAL_ARCHIVES': ','.join(f'{nodes[f"me{i}"]}:{ports["me_base"] + i * ports["stride"] + 10}' for i in range(3)),
                'BRIDGE_JOURNAL_CONTROL_STREAM': '4010', 'BRIDGE_JOURNAL_STREAM': '4001',
                'BRIDGE_JOURNAL_CHANNEL': 'aeron:ipc', 'BRIDGE_REPLAY_STREAM': '4012', 'BRIDGE_LOCAL_HOST': nodes[slot],
                'BRIDGE_AE_CLUSTER_ADDRESSES': ','.join(nodes[f'ae{i}'] for i in range(3)),
                'BRIDGE_AE_PORT_BASE': str(ports['ae_base']), 'CLUSTER_PORT_STRIDE': str(ports['stride']),
                'BRIDGE_AE_EGRESS_ENDPOINT': nodes[slot] + ':19394', 'AE_AUTH_CREDENTIAL': self.keys.credential(slot, 'ae'),
                'BRIDGE_INSTANCE_ID': str(self.keys.keys[(slot, 'ae')][0]), 'BRIDGE_METRICS_PORT': str(ports['bridge_http']),
                'BRIDGE_DRIVER_DIR': '/dev/shm/aeron-bridge'}

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
        binary = f'/artifacts/{artifact_name}/bin'
        env = {**self.slot_env(slot), 'LD_LIBRARY_PATH': f'/artifacts/{artifact_name}'}
        if artifact['driver'] == 'java_media_driver':
            driver = shlex.join(JAVA + ['-cp', '/artifacts/me.jar', 'io.aeron.driver.MediaDriver'])
            script = (driver + ' & i=0; while [ ! -f /dev/shm/aeron/cnc.dat ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; '
                      'exec ' + shlex.quote(binary))
            self.spawn(slot, ['sh', '-c', script], env)
        else:
            self.spawn(slot, [binary], env)
        port = self.m['ports']['forwarder_http' if slot.startswith('fwd') else 'bridge_http']
        if slot.startswith('bridge'):
            # O1 health contract kept by the C++ bridge: {halted, aeConnected}, 503 when halted.
            self.wait_http(slot, port, '/health', predicate=lambda r: json.loads(r['body']).get('aeConnected') is True)
        else:
            self.wait_http(slot, port, '/health')
        return {'state': 'STARTED', 'artifact': artifact_name, 'sha256': artifact['sha256'], 'source_sha': artifact['source_sha']}

    # ---------------------------------------------------------------- faults

    def kill(self, name):
        if name not in set(ENGINES) | set(SLOTS) | {'projector'} or name not in self.registry['containers']:
            raise Violation('unsupported or unstarted fault target: ' + name)
        cid = self.registry['containers'][name]
        before = self.inspect('container', cid)['State']
        if not before['Running']: raise Inconclusive('fault target was already stopped')
        self.command(['docker', 'kill', '--signal=KILL', cid])
        after = self.inspect('container', cid)['State']
        if after['Running'] or after['ExitCode'] != 137: raise Inconclusive('SIGKILL was not observed')
        return {'kind': 'kill', 'target': name, 'container_id': cid, 'before_running': True, 'after_running': False,
                'exit_observed': True, 'exit_code': after['ExitCode'], 'before_pid': before['Pid'],
                'finished_at': after['FinishedAt']}

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
