# SPDX-License-Identifier: Apache-2.0
"""Owned, private-network Docker fixture; runs frozen jars and never builds them."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import zipfile

from contracts import Inconclusive, Violation, validate_manifest

LABEL = 'org.openexchange.runtime-fixture'
PORT_PROFILE = {'me_base': 9000, 'ae_base': 19300, 'stride': 100, 'me_probe': 19500,
                'ae_probe': 19700, 'oms_http': 18080, 'market_http': 8081,
                'bridge_http': 9600, 'projector_http': 9601}
JAVA = ['java', '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED',
        '--add-opens', 'java.base/sun.nio.ch=ALL-UNNAMED',
        '--add-opens', 'java.base/java.nio=ALL-UNNAMED',
        '-Xms128m', '-Xmx512m', '-Duser.home=/data', '-Daeron.dir=/dev/shm/aeron',
        '-Daeron.threading.mode=SHARED', '-Daeron.archive.threading.mode=SHARED',
        '-Daeron.archive.segment.file.length=1048576']


class Fixture:
    def __init__(self, manifest_path, attach=False):
        self.manifest_path = Path(manifest_path).absolute()
        self.m = json.loads(self.manifest_path.read_text())
        validate_manifest(self.m, self.manifest_path)
        if self.m.get('ports') != PORT_PROFILE:
            raise Inconclusive('explicit port profile does not match this frozen gateway fixture')
        for role, cpu in self.m['limits'].get('cpu_quota_by_role', {}).items():
            if role not in self.m['nodes'] or type(cpu) not in (int, float) or not 0 < cpu <= len(self.m['cpu_set']):
                raise Violation('invalid bounded fixture CPU quota')
        for role, cpus in self.m['limits'].get('cpu_set_by_role', {}).items():
            if (role != 'probe' or not isinstance(cpus, list) or not cpus or len(set(cpus)) != len(cpus)
                    or any(type(cpu) is not int or cpu < 0 or cpu >= os.cpu_count() for cpu in cpus)
                    or set(cpus) & set(self.m['cpu_set'])):
                raise Violation('measurement probe CPUs must be explicit and separate from service CPUs')
        self.root = Path(self.m['state_root'])
        self.run_id = self.m['run_id']
        self.gateway = str(ipaddress.ip_network(self.m['network']['subnet']).network_address + 1)
        self.pg = Path(self.m['postgres_bin'])
        self.pg_port = self.m['postgres_port']
        if type(self.pg_port) is not int or not 1024 < self.pg_port < 65536:
            raise Violation('invalid fixture postgres port')
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
            cpus = self.m['cpu_set']
            if not cpus or not set(cpus).issubset(os.sched_getaffinity(0)):
                raise Inconclusive('fixture CPU set is unavailable')
            self.root.mkdir()
            self.token = uuid.uuid4().hex
            self.registry = {'run_id': self.run_id, 'token': self.token,
                             'manifest_sha256': hashlib.sha256(self.manifest_path.read_bytes()).hexdigest(),
                             'containers': {}, 'network_id': None, 'pg_started': False, 'command_seq': 0}
            self.save()
        (self.root / 'logs').mkdir(exist_ok=True)

    def save(self):
        temp = self.root / 'owner.json.tmp'
        temp.write_text(json.dumps(self.registry, indent=2) + '\n')
        temp.replace(self.root / 'owner.json')

    def command(self, argv, *, input=None, timeout=60, check=True, env=None):
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
        output.write_text(r.stdout + r.stderr)
        with (self.root / 'commands.jsonl').open('a') as log:
            log.write(json.dumps({'argv': [str(a) for a in argv], 'exit_code': r.returncode,
                                  'elapsed_ns': time.monotonic_ns() - started, 'output': str(output),
                                  'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}) + '\n')
        if check and r.returncode:
            raise Inconclusive(f'child exit {r.returncode}: {argv[:3]}; evidence {output}')
        return r

    def inspect(self, kind, resource_id):
        row = json.loads(self.command(['docker', kind, 'inspect', resource_id]).stdout)[0]
        labels = row.get('Labels', {}) if kind == 'network' else row.get('Config', {}).get('Labels', {})
        if labels.get(LABEL) != self.run_id or labels.get(LABEL + '.token') != self.token:
            raise Violation('refusing operation on an unowned Docker resource')
        return row

    def start_network(self):
        existing = self.command(['docker', 'network', 'ls', '--format', '{{.ID}}']).stdout.split()
        if existing:
            networks = json.loads(self.command(['docker', 'network', 'inspect', *existing]).stdout)
            wanted = ipaddress.ip_network(self.m['network']['subnet'])
            for row in networks:
                for config in (row.get('IPAM', {}).get('Config') or []):
                    subnet = config.get('Subnet')
                    if subnet and ':' not in subnet and wanted.overlaps(ipaddress.ip_network(subnet)):
                        raise Inconclusive('fixture subnet overlaps an existing Docker network')
        network = self.command(['docker', 'network', 'create', '--internal', '--subnet', self.m['network']['subnet'],
            '--gateway', self.gateway, '--label', LABEL + '=' + self.run_id,
            '--label', LABEL + '.token=' + self.token, self.run_id]).stdout.strip()
        self.registry['network_id'] = network; self.save()
        self.inspect('network', network)

    def psql(self, database, sql):
        if database not in {'postgres','r01_oms','r01_market','r01_money'}:
            raise Violation('unknown fixture database')
        return self.command([self.pg / 'psql', '-h', self.gateway, '-p', self.pg_port, '-U', 'runtime_fixture',
                             '-d', database, '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql]).stdout.strip()

    def start_database(self):
        data = self.root / 'postgres'
        self.command([self.pg / 'initdb', '-D', data, '-A', 'trust', '-U', 'runtime_fixture',
                      '--no-locale', '--encoding=UTF8'])
        socket_dir = self.root / 'pgsocket'; socket_dir.mkdir()
        with (data / 'postgresql.conf').open('a') as config:
            config.write(f"\nlisten_addresses='{self.gateway}'\nport={self.pg_port}\nunix_socket_directories=''\n"
                         "shared_preload_libraries='timescaledb'\nshared_buffers='64MB'\nmax_connections=80\n"
                         "max_worker_processes=12\ntimescaledb.max_background_workers=4\n")
        (data / 'pg_hba.conf').write_text('local all all trust\nhost all all ' + self.m['network']['subnet'] + ' trust\n')
        self.command([self.pg / 'pg_ctl', '-D', data, '-l', self.root / 'logs/postgres.log', '-w', 'start'])
        self.registry['pg_started'] = True
        self.registry['pg_pid'] = int((data / 'postmaster.pid').read_text().splitlines()[0]); self.save()
        for name in ['r01_oms','r01_market','r01_money']:
            self.psql('postgres', 'CREATE DATABASE ' + name)
        self.psql('r01_market', 'CREATE EXTENSION timescaledb')
        for role, database in [('oms','r01_oms'), ('projector','r01_money')]:
            with zipfile.ZipFile(self.m['artifacts'][role]['path']) as jar:
                schemas = sorted(name for name in jar.namelist() if name.startswith('db/migration/V') and name.endswith('.sql'))
                if not schemas: raise Inconclusive('missing packaged database schema: ' + role)
                for name in schemas:
                    self.psql(database, jar.read(name).decode())

    def stage_artifacts(self):
        dest = self.root / 'artifacts'; dest.mkdir()
        for role, artifact in self.m['artifacts'].items():
            path = dest / (role + '.jar'); shutil.copyfile(artifact['path'], path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != artifact['sha256']:
                raise Violation('artifact changed while staging')
        for key, filename in [('test_helper', 'fixture-probe.jar'), ('benchmark_helper', 'benchmark-probe.jar')]:
            if not self.m.get(key): continue
            helper = self.m[key]; path = dest / filename
            shutil.copyfile(helper['path'], path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != helper['sha256']:
                raise Violation('test probe changed while staging')

    def spawn(self, name, command, environment=None):
        if name not in self.m['nodes'] or name in self.registry['containers']:
            raise Violation('unknown or duplicate fixture process')
        state = self.root / 'state' / name; state.mkdir(parents=True)
        limits = self.m['limits']
        args = ['docker','create','--name',self.run_id + '-' + name,
                '--network',self.registry['network_id'],'--ip',self.m['nodes'][name],
                '--label',LABEL + '=' + self.run_id,'--label',LABEL + '.token=' + self.token,
                '--user',f'{os.getuid()}:{os.getgid()}', '--workdir','/data','--read-only',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',
                '--memory',str(limits['memory_mb']) + 'm','--memory-swap',str(limits['memory_mb']) + 'm',
                '--cpuset-cpus',','.join(map(str,limits.get('cpu_set_by_role', {}).get(name,self.m['cpu_set']))),
                '--cpus',str(limits.get('cpu_quota_by_role', {}).get(name, 1)),
                '--shm-size',str(limits['shm_mb']) + 'm','--tmpfs','/tmp:rw,nosuid,size=128m',
                '--log-opt','max-size=32m','--log-opt','max-file=3',
                '--mount',f'type=bind,src={state},dst=/data',
                '--mount',f'type=bind,src={self.root / "artifacts"},dst=/artifacts,readonly']
        for key, value in sorted((environment or {}).items()): args += ['--env', key + '=' + str(value)]
        args += ['--entrypoint',command[0],self.m['image'],*command[1:]]
        resource_id = self.command(args).stdout.strip()
        self.registry['containers'][name] = resource_id; self.save()
        self.inspect('container', resource_id)
        self.command(['docker','start',resource_id])
        return resource_id

    def execute(self, name, argv, *, input=None, timeout=30, environment=None, check=True):
        resource_id = self.registry['containers'][name]
        self.inspect('container', resource_id)
        command = ['docker','exec','-i']
        for key, value in sorted((environment or {}).items()): command += ['--env', key + '=' + str(value)]
        return self.command([*command,resource_id,*argv],input=input,timeout=timeout,check=check)

    def http(self, name, port, path, method='GET', body=None, user=None):
        if name not in self.m['nodes'] or not path.startswith('/'):
            raise Violation('HTTP target outside fixture')
        request = {'url':f'http://{self.m["nodes"][name]}:{port}{path}','method':method,'body':body,'user':user}
        code = '''import json,sys,urllib.request,urllib.error
r=json.loads(sys.stdin.read());headers={"Content-Type":"application/json"}
if r['user'] is not None:headers['Authorization']='Bearer dev:'+str(r['user'])
data=json.dumps(r['body']).encode() if r['body'] is not None else None
try:
 response=urllib.request.urlopen(urllib.request.Request(r['url'],data=data,headers=headers,method=r['method']),timeout=5)
 print(json.dumps({'status':response.status,'body':response.read().decode()}))
except urllib.error.HTTPError as e:print(json.dumps({'status':e.code,'body':e.read().decode()}))
except Exception as e:print(json.dumps({'status':0,'error':str(e)}))
'''
        response = self.execute('probe',['python3','-c',code],input=json.dumps(request),timeout=15)
        return json.loads(response.stdout)

    def wait_http(self, name, port, path, timeout=90, predicate=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = self.http(name,port,path)
            if response['status'] == 200 and (predicate is None or predicate(response)):
                return response
            for role, cid in self.registry['containers'].items():
                state = self.inspect('container', cid)['State']
                if not state['Running']:
                    raise Inconclusive(f'fixture process {role} exited {state["ExitCode"]} before readiness')
            time.sleep(.5)
        raise Inconclusive('startup deadline exceeded: ' + name + path)

    def bridge_env(self, client_name='bridge'):
        return {'BRIDGE_ME_JOURNAL_ARCHIVES':','.join(self.m['nodes'][f'me{i}'] + ':' + str(9010 + 100*i) for i in range(3)),
                'BRIDGE_AE_CLUSTER_ADDRESSES':','.join(self.m['nodes'][f'ae{i}'] for i in range(3)),
                'BRIDGE_AE_PORT_BASE':'19300','BRIDGE_AE_EGRESS_ENDPOINT':self.m['nodes'][client_name] + ':19394',
                'BRIDGE_LOCAL_HOST':self.m['nodes'][client_name], 'BRIDGE_METRICS_PORT':'9600',
                'CLUSTER_PORT_STRIDE':'100','BRIDGE_HALT_ON_GAP':'true'}

    def start(self):
        self.stage_artifacts(); self.start_network(); self.start_database()
        self.spawn('probe',['sleep','infinity'])
        common = {'CLUSTER_PORT_STRIDE':'100','BASE_DIR':'/data/state','TRANSPORT_DRIVER_MODE':'embedded',
                  'TRANSPORT_IDLE_MODE':'backoff','TRANSPORT_TERM_LENGTH':'1m','TRANSPORT_LOG_TERM_LENGTH':'1m',
                  'TRANSPORT_SNAPSHOT_TERM_LENGTH':'1m',
                  'MATCH_ENGINE_BOOK_CAPACITY':'4096','SNAPSHOT_LOG_BYTES':'1073741824','SNAPSHOT_INTERVAL_MINUTES':'5'}
        for engine, port in [('ae',19300),('me',9000)]:
            addresses = ','.join(self.m['nodes'][engine + str(i)] for i in range(3))
            for i in range(3):
                env = {**common,'CLUSTER_NODE':str(i),'CLUSTER_ADDRESSES':addresses,'CLUSTER_PORT_BASE':str(port)}
                if engine == 'me':
                    env.update(METRICS_PORT='19500',SETTLEMENT_JOURNAL_ENABLED='true',
                               SETTLEMENT_JOURNAL_DIR='/data/journal',SETTLEMENT_JOURNAL_ARCHIVE_BIND='0.0.0.0')
                else: env['ASSETS_NODE_PORT'] = '19700'
                self.spawn(engine + str(i),JAVA + ['-jar','/artifacts/' + engine + '.jar'],env)
        for engine, port in [('ae',19700),('me',19500)]:
            for i in range(3): self.wait_http(engine + str(i),port,'/ready')
        self.execute('probe',JAVA + ['-jar','/artifacts/bridge.jar','set-money-journal','on'],
                     environment=self.bridge_env('probe'))
        self.spawn('bridge',JAVA + ['-jar','/artifacts/bridge.jar'],self.bridge_env())
        db = {'PROJECTOR_POSTGRES_URL':f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_money',
              'PROJECTOR_POSTGRES_USER':'runtime_fixture','PROJECTOR_POSTGRES_PASSWORD':'synthetic-fixture-only',
              'PROJECTOR_AE_JOURNAL_ARCHIVES':','.join(self.m['nodes'][f'ae{i}'] + ':' + str(19301 + 100*i) for i in range(3)),
              'PROJECTOR_LOCAL_HOST':self.m['nodes']['projector'],'PROJECTOR_METRICS_PORT':'9601'}
        self.spawn('projector',JAVA + ['-jar','/artifacts/projector.jar'],db)
        env = {'OMS_HTTP_PORT':'18080','OMS_GRPC_PORT':'19091','OMS_AUTH_MODE':'dev','OMS_AUDIT_LOG':'off',
               'OMS_POSTGRES_URL':f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_oms',
               'OMS_POSTGRES_USER':'runtime_fixture','OMS_POSTGRES_PASSWORD':'synthetic-fixture-only',
               'OMS_NODE_ID':'7','CLUSTER_PORT_STRIDE':'100',
               'CLUSTER_ADDRESSES':','.join(self.m['nodes'][f'me{i}'] for i in range(3)),
               'CLUSTER_PORT_BASE':'9000','EGRESS_HOST':self.m['nodes']['oms'],'EGRESS_PORT':'19093',
               'AE_CLUSTER_ADDRESSES':','.join(self.m['nodes'][f'ae{i}'] for i in range(3)),
               'AE_CLUSTER_PORT_BASE':'19300','AE_EGRESS_HOST':self.m['nodes']['oms'],'AE_EGRESS_PORT':'19393'}
        self.spawn('oms',JAVA + ['-jar','/artifacts/oms.jar'],env)
        market = {'CLUSTER_ADDRESSES':env['CLUSTER_ADDRESSES'],'CLUSTER_PORT_BASE':'9000','CLUSTER_PORT_STRIDE':'100',
                  'EGRESS_HOST':self.m['nodes']['market'],'EGRESS_PORT':'19094','GATEWAY_TYPE':'market',
                  'MARKET_PG_URL':f'jdbc:postgresql://{self.gateway}:{self.pg_port}/r01_market',
                  'MARKET_PG_USER':'runtime_fixture','MARKET_PG_PASSWORD':'synthetic-fixture-only'}
        self.spawn('market',JAVA + ['-cp','/artifacts/market.jar','com.match.infrastructure.gateway.MarketGatewayMain'],market)
        self.wait_http('oms',18080,'/api/v1/health',predicate=lambda r: json.loads(r['body']).get('clusterConnected') is True)
        self.wait_http('bridge',9600,'/health',predicate=lambda r: json.loads(r['body']).get('aeConnected') is True)
        self.wait_http('projector',9601,'/health')
        self.wait_http('market',8081,'/health')
        self.registry['startup_complete'] = True; self.save()

    def kill(self, name):
        if name not in {'me0','me1','me2','ae0','ae1','ae2','oms','bridge','market','projector'}:
            raise Violation('unsupported fault target')
        cid = self.registry['containers'][name]
        before = self.inspect('container',cid)['State']
        if not before['Running']: raise Inconclusive('fault target was already stopped')
        self.command(['docker','kill','--signal=KILL',cid])
        after = self.inspect('container',cid)['State']
        proof = {'kind':'kill','target':name,'container_id':cid,'before_running':before['Running'],
                 'after_running':after['Running'],'exit_observed':not after['Running'],'exit_code':after['ExitCode'],
                 'before_pid':before['Pid'],'finished_at':after['FinishedAt']}
        if after['Running'] or after['ExitCode'] != 137: raise Inconclusive('SIGKILL was not observed')
        return proof

    def collect_logs(self):
        for name, cid in self.registry['containers'].items():
            self.inspect('container',cid)
            logs = self.command(['docker','logs','--timestamps',cid],check=False)
            (self.root / 'logs' / (name + '.log')).write_text(logs.stdout + logs.stderr)

    def close(self):
        failures = []
        try:
            self.collect_logs()
        except Exception as error:
            failures.append('log collection: ' + str(error))
        for name, cid in reversed(list(self.registry['containers'].items())):
            try:
                self.inspect('container',cid)
                self.command(['docker','rm','-f',cid])
                del self.registry['containers'][name]; self.save()
            except Exception as error: failures.append(name + ': ' + str(error))
        if self.registry['pg_started']:
            data = self.root / 'postgres'
            pid = int((data / 'postmaster.pid').read_text().splitlines()[0])
            if pid != self.registry['pg_pid'] or str(data).encode() not in Path(f'/proc/{pid}/cmdline').read_bytes():
                raise Violation('Postgres process ownership changed; refusing stop')
            self.command([self.pg / 'pg_ctl','-D',data,'-m','fast','-w','stop'])
            self.registry['pg_started'] = False; self.save()
        network = self.registry['network_id']
        if network and not self.registry['containers']:
            self.inspect('network',network)
            self.command(['docker','network','rm',network])
            self.registry['network_id'] = None; self.save()
        self.registry['teardown_failures'] = failures; self.save()
        if failures: raise Inconclusive('fixture teardown incomplete: ' + '; '.join(failures))
