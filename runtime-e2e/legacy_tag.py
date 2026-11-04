# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 legacy tag profile (contract 3.2, 5.2 (i), 20.1 lines 3, 5, 21; D-S17-25). The frozen R02 fixture (``fixture.py``) runs
the v0.5.0-beta jars only with W0's two adaptations (S17/evidence/dry-run/legacy_patch.py), now harness code:

 1. host drift, not a tag property: the timescaledb loader package is 2.31.0 while ``timescaledb-2-postgresql-16`` is held at
    2.28.2, so ``CREATE EXTENSION timescaledb`` is pinned to ``TIMESCALEDB_VERSION`` (a setting; align the host packages instead
    and set it to the installed version);
 2. the tag engines (cluster-kit 0.1.2) have no ``/ready`` and the tag AE no HTTP endpoint: an engine ``/ready`` wait is a
    log-marker wait (ME "SERVICE onStart complete", AE "Money journal writer started") plus ``MARKER_SETTLE_S``.

Plus the tag-engine settings: ``shm_mb`` / ``memory_mb`` 4096 (a tag snapshot needs about 192 MB of /dev/shm, the tag ignores
TRANSPORT_SNAPSHOT_TERM_LENGTH), the engines stopped by SIGKILL (they ignore SIGTERM, exit 137), and the snapshot trigger
``ClusterTool <clusterDir> snapshot`` by ``docker exec`` on the leader read from ``list-members``, witnessed by ``recording-log``.

Used for seed production and X-R only: no X run puts a tag jar under test (0.1). The manifest takes only the jars pinned in
``R10/old-artifacts.sha256`` (W1).
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from contracts import Inconclusive, Violation
import fixture
from fixture import JAVA

TIMESCALEDB_VERSION = '2.28.2'          # setting: the host's held extension package (20.1 line 3)
MARKERS = {'me': 'SERVICE onStart complete', 'ae': 'Money journal writer started'}
MARKER_SETTLE_S = 3
SHM_MB = 4096                           # settings, not acceptance limits (PO 2026-11-03)
MEMORY_MB = 4096
SNAPSHOT_BOUND_S = 40                   # the recording.log SNAPSHOT entry appeared 1 to 30 s after the trigger (W0)
CLUSTER_TOOL = ['java', '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED', '-cp']
CLUSTER_DIR = '/data/state/cluster'
B0 = Path('/home/emre/Apps/openexchange/.runtime-handoff/20260927-r00')
TEMPLATE = B0 / 'workspace/notebook/reports/runtime-handoff-execution/R02-closure/a05-01/manifest.json'
PINS = B0 / 'workspace/notebook/reports/runtime-handoff-execution/R10/old-artifacts.sha256'
JARS = B0 / 'r10-old/w1/jars'
# fixture role -> (tag jar file, repo); the six frozen roles of the legacy fixture (LCT:85, 3.2)
TAG_JARS = {'me': ('match-cluster.jar', 'match'), 'market': ('match-gateway.jar', 'match'), 'ae': ('assets-cluster.jar', 'assets'),
            'bridge': ('assets-bridge.jar', 'assets'), 'projector': ('assets-projector.jar', 'assets'), 'oms': ('oms-app.jar', 'oms')}
ENGINES = [e + str(i) for e in ('me', 'ae') for i in range(3)]


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tree_hash(root):
    """sha256 over the sorted relative paths and file sha256 (5.2 seed_state); symlinks are not followed."""
    h, files, size = hashlib.sha256(), 0, 0
    root = Path(root)
    for p in sorted(root.rglob('*')):
        if p.is_file() and not p.is_symlink():
            h.update(str(p.relative_to(root)).encode() + b'\0' + bytes.fromhex(sha256_file(p)))
            files += 1
            size += p.stat().st_size
    return {'sha256': h.hexdigest(), 'files': files, 'bytes': size}


def _pins(path):
    pins = {}
    for line in Path(path).read_text().splitlines():
        if line.strip() and not line.startswith('#'):
            parts = line.split()
            pins[parts[0]] = {'name': parts[1], **dict(p.split('=', 1) for p in parts[2:] if '=' in p)}
    return pins


def legacy_manifest(name, octet, runs, jars=JARS, pins=PINS, template=TEMPLATE, shm_mb=SHM_MB, memory_mb=MEMORY_MB):
    """A legacy (schema v1) manifest on the pinned v0.5.0-beta jars, derived from the R02 template (only artifacts, identity,
    subnet and the tag settings change; mk_legacy.py of W0). Writes ``<runs>/<name>/manifest.json``; returns (path, manifest)."""
    if not re.fullmatch(r'[a-z0-9-]{1,40}', name) or not 2 <= octet <= 254:
        raise Violation('legacy manifest: a short name and a /24 octet')
    pinned = _pins(pins)
    m = json.loads(Path(template).read_text())
    rid = 'r01-' + secrets.token_hex(6)
    root = Path(runs) / name
    m['run_id'] = rid
    m['state_root'] = str(root / 'fixtures' / rid)
    m['network'] = {'subnet': f'172.30.{octet}.0/24', 'internal': True}
    m.pop('journal_cutover', None)
    m['nodes'] = {k: f'172.30.{octet}.{v.rsplit(".", 1)[1]}' for k, v in m['nodes'].items() if k != 'xprojector'}
    m['artifacts'] = {}
    for role, (jar, _) in TAG_JARS.items():
        path = Path(jars) / jar
        digest = sha256_file(path)
        pin = pinned.get(digest)
        if pin is None or pin['name'] != 'v0.5.0-beta/' + jar:
            raise Violation(f'{jar} is not pinned in {pins} (sha256 {digest})')
        m['artifacts'][role] = {'path': str(path), 'sha256': digest, 'source_sha': pin['source_sha']}
    m['cpu_set'] = [4, 5, 6, 7, 8, 9, 10, 11]
    m['limits']['cpu_set_by_role'] = {'probe': [2, 3]}
    m['limits']['cpu_quota_by_role'] = {'probe': 2}
    m['limits']['shm_mb'] = shm_mb
    m['limits']['memory_mb'] = memory_mb
    m.pop('test_helper', None); m.pop('benchmark_helper', None)
    m['postgres_port'] = 55600 + octet
    m['legacy_tag_profile'] = {'timescaledb_version': TIMESCALEDB_VERSION, 'markers': dict(MARKERS), 'settle_s': MARKER_SETTLE_S,
                               'engine_stop': 'SIGKILL', 'note': 'RC2 S17 legacy tag profile (5.2 (i)); seed production and X-R only'}
    root.mkdir(parents=True, exist_ok=True)
    out = root / 'manifest.json'
    out.write_text(json.dumps(m, indent=1) + '\n')
    return out, m


class LegacyTagFixture(fixture.Fixture):
    """The R02 fixture with the legacy tag profile."""
    sleep = staticmethod(time.sleep)

    def psql(self, database, sql):
        if sql == 'CREATE EXTENSION timescaledb':
            sql = f"CREATE EXTENSION timescaledb VERSION '{TIMESCALEDB_VERSION}'"
        return super().psql(database, sql)

    def wait_http(self, name, port, path, timeout=90, predicate=None):
        if path == '/ready' and name[:2] in MARKERS and name in self.registry['containers']:
            cid = self.registry['containers'][name]
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                out = subprocess.run(['docker', 'logs', cid], capture_output=True, text=True)
                if MARKERS[name[:2]] in (out.stdout or '') + (out.stderr or ''):
                    self.sleep(MARKER_SETTLE_S)
                    return {'status': 200, 'body': 'tag engine: log marker (no /ready at v0.5.0-beta): ' + MARKERS[name[:2]]}
                self.sleep(1)
            raise Inconclusive('tag engine log marker missing: ' + name)
        return super().wait_http(name, port, path, timeout, predicate)

    def stop_engines(self, names=ENGINES):
        """The tag engines ignore SIGTERM (exit 137 after docker stop): SIGKILL, the state recovery meets in production too."""
        for name in names:
            if name not in ENGINES:
                raise Violation('stop_engines stops engine members only: ' + name)
            self.command(['docker', 'kill', '--signal', 'KILL', self.registry['containers'][name]])

    def cluster_tool(self, node, *args):
        jar = f'/artifacts/{node[:2]}.jar'
        result = self.execute(node, CLUSTER_TOOL + [jar, 'io.aeron.cluster.ClusterTool', CLUSTER_DIR, *args], timeout=60,
                              check=False)
        return (result.stdout or '') + (result.stderr or '')

    def leader(self, engine):
        for i in range(3):
            for token in self.cluster_tool(f'{engine}{i}', 'list-members').replace(',', ' ').split():
                if token.startswith('leaderMemberId=') and int(token.split('=')[1]) >= 0:
                    return int(token.split('=')[1])
        raise Inconclusive(f'no {engine} leader in list-members')

    def snapshot(self, engine, bound_s=SNAPSHOT_BOUND_S):
        """``ClusterTool snapshot`` on the leader; returns (leader, recording-log text with the new SNAPSHOT entry)."""
        lead = self.leader(engine)
        node = f'{engine}{lead}'
        before = self.cluster_tool(node, 'recording-log').count('SNAPSHOT')
        text = self.cluster_tool(node, 'snapshot')
        if 'applied successfully' not in text and 'SNAPSHOT' not in text:
            raise Inconclusive(f'{node} snapshot not applied: {text[:200]}')
        deadline = time.monotonic() + bound_s
        while time.monotonic() < deadline:
            self.sleep(1.5)
            log = self.cluster_tool(node, 'recording-log')
            if log.count('SNAPSHOT') > before:
                return lead, log
        raise Inconclusive(f'{node}: no SNAPSHOT entry in recording.log within {bound_s} s')

    def recording_log(self, node):
        return self.cluster_tool(node, 'recording-log')


# ------------------------------------------------------------------ X-R dumps (6.9 step 1; 20.1 line 21)

DATABASES = ['r01_oms', 'r01_money', 'r01_market']


def _psql_out(f, db, sql, inp=None):
    r = subprocess.run([str(f.pg / 'psql'), '-h', f.gateway, '-p', str(f.pg_port), '-U', 'runtime_fixture', '-d', db,
                        '-v', 'ON_ERROR_STOP=1', '-tA', '-q', '-c', sql], input=inp, capture_output=True, text=True)
    if r.returncode:
        raise Inconclusive(f'psql {db}: {r.stderr[:300]}')
    return r.stdout


def pg_dump(f, db):
    """``r01_market`` (TimescaleDB): the user hypertables' rows as CSV (a data-only pg_dump of the catalog cannot be restored over
    a fresh extension); the other databases: ``pg_dump --data-only --inserts``."""
    if db == 'r01_market':
        tables = [t for t in _psql_out(f, db, "SELECT hypertable_name FROM timescaledb_information.hypertables WHERE "
                                              "hypertable_schema='public' ORDER BY 1").split() if t]
        lines = []
        for t in tables:
            lines += ['INSERT ' + t + ' ' + row for row in
                      _psql_out(f, db, f'COPY (SELECT * FROM public.{t} ORDER BY 1) TO STDOUT WITH (FORMAT csv)').splitlines()]
        return '\n'.join(lines) + '\n'
    r = subprocess.run([str(f.pg / 'pg_dump'), '-h', f.gateway, '-p', str(f.pg_port), '-U', 'runtime_fixture', '-d', db,
                        '--data-only', '--disable-triggers', '--no-owner', '--no-comments', '--inserts', '--rows-per-insert=1'],
                       capture_output=True, text=True)
    if r.returncode:
        raise Inconclusive(f'pg_dump {db}: {r.stderr[:300]}')
    return r.stdout


def dump_d(f, keep=None):
    """D0/D1 of 6.9: sha256 over the sorted INSERT lines of each database plus the tag AE balances, holds and lastAppliedTradeId
    read with ``bridge.jar dump`` (the tag AE's query path)."""
    from observe import ae_dump
    d = {}
    for db in DATABASES:
        text = pg_dump(f, db)
        lines = sorted(line for line in text.splitlines() if line.startswith('INSERT'))
        d[db] = {'rows': len(lines), 'sha256': hashlib.sha256('\n'.join(lines).encode()).hexdigest()}
        if keep is not None:
            (Path(keep) / f'{db}.dump.sql').write_text(text)
    ae = ae_dump(f)
    balances = sorted([[r['userId'], r['assetId'], r['available'], r['locked']] for r in ae['balances']])
    holds = sorted([[r['orderId'], r['userId'], r['assetId'], r['remaining']] for r in ae['holds']])
    d['ae'] = {'balances': len(balances), 'holds': len(holds), 'lastAppliedTradeId': ae['lastAppliedTradeId'],
               'sha256': hashlib.sha256(json.dumps([balances, holds, ae['lastAppliedTradeId']]).encode()).hexdigest()}
    d['combined'] = hashlib.sha256(json.dumps({k: v['sha256'] for k, v in d.items()}, sort_keys=True).encode()).hexdigest()
    return d
