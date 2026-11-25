# SPDX-License-Identifier: Apache-2.0
"""The short observation drill on the fixture (``core-observation-drill``) and the scenario id of the box observation
(``demo-observation-24h``, observation.scenario).

The drill is the fixture twin of the box observation. On a critical-path kind (``cps``, ``cps-ext``) it boots the stack,
funds two users through the gateway, runs money-check with the core expected side at Q0, starts the observation sampler
on this host (the fixture is the one-host case: docker is the supervisor) and a crossing-pairs load through gw0 for
OBS_DRILL_WINDOW_S, plants at most one fault, stops the load, quiesces (cancel-all, the money history at the core's
head, money-check at Q2), merges the sample set and runs the verdict over it. money-check runs in the fixture's own
driver mode (``cps``: embedded; ``cps-ext``: external, on the probe's staged aeronmd), recorded as money_check_driver.

OBS_DRILL_FAULT (one per run; the verdict must name exactly the planted line and the planted service):
  none              the clean run: the verdict PASSes
  freeze-projector  SIGSTOP of the order projector that holds the lease (pj0 or pj1, as the lease says) for the fault
                    window: V3 ``alive and unreachable: oe-projector/<slot>``; the relation-read cross-check
                    (oe_projection_state.applied_seq) is printed next to it and is flat while frozen. The gateway's
                    history age is a consequence of the freeze: the window is recorded as a history action (V12)
  freeze-bridge     SIGSTOP of bridge0: V3 ``alive and unreachable: ct-bridge/bridge0``. The two control builds of the
                    verdict run over the same samples: V3 judging the bridge by the core's log position must PASS
                    (-> ``verdict line V3 is vacuous for ct-bridge``), reading an unreadable counter as a missing sample
                    must end INCONCLUSIVE (-> ``frozen process read as a gap``)
  kill-core         a core follower killed and restarted three times, no action recorded: V2 ``repeated restart:
                    core/<slot> x3``
  grow-file         OBS_DRILL_GROW_MB written by hand into ae0's state directory: V7 ``unexplained disk growth: core/ae0
                    state <bytes>``
Both frozen processes are resumed and must catch up (their work counter reaches the head within OBS_DRILL_CATCHUP_S).

OBS_DRILL_CONTROL=skip-plant: the fault step is skipped; the run must end INCONCLUSIVE ``fault was never planted``.

Settings (drill bounds; the measured values are recorded as data): OBS_DRILL_WINDOW_S 600, OBS_DRILL_SAMPLE_S 10,
OBS_DRILL_LOAD_EVERY_S 5, OBS_DRILL_STALL_S 60, OBS_DRILL_CATCHUP_S 120, OBS_DRILL_GROW_MB 256, OBS_DRILL_FREEZE_S 150 (how long a frozen process stays frozen),
OBS_DRILL_EXIT_WAIT_S 5 (after the resume: a process that exited is restarted, as its supervisor would, and the restart is
recorded as an action), OBS_DRILL_KILL_GAP_S 30 (each restarted life lasts at least this long, more than two sample
periods, so the sampler sees every life). Inputs:
OBS_SAMPLER_BIN (the obs-sampler binary for this host) and OBS_DRILL_CUT (the release cut manifest money-check runs
CoreDump and the order snapshot reader from); without either the run ends INCONCLUSIVE naming it.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from contracts import Inconclusive, Violation
import core_contracts
from core_fixture import PROBE_AERON_DIR
import observation
import smoke_core
from smoke_core import CriticalPathDrill, money_call, order_call

SCENARIOS = ('core-observation-drill',)
KINDS = ('cps', 'cps-ext')
FAULTS = ('none', 'freeze-projector', 'freeze-bridge', 'kill-core', 'grow-file')
CONTROLS = ('skip-plant',)
NOT_PLANTED = 'fault was never planted'
SETTINGS = {'OBS_DRILL_WINDOW_S': 600, 'OBS_DRILL_SAMPLE_S': 10, 'OBS_DRILL_LOAD_EVERY_S': 5, 'OBS_DRILL_STALL_S': 60,
            'OBS_DRILL_CATCHUP_S': 120, 'OBS_DRILL_GROW_MB': 256, 'OBS_DRILL_FREEZE_S': 150, 'OBS_DRILL_EXIT_WAIT_S': 5,
            'OBS_DRILL_KILL_GAP_S': 30}
USERS = 93001
KILLS = 3


def is_scenario(name):
    return name in SCENARIOS


def drill_settings(environ=os.environ):
    out = {}
    for key, default in SETTINGS.items():
        value = environ.get(key)
        if value in (None, ''):
            out[key] = default
        elif not value.isdigit() or int(value) < 1:
            raise Violation(f'{key} must be a positive integer, got {value!r}')
        else:
            out[key] = int(value)
    fault = environ.get('OBS_DRILL_FAULT') or 'none'
    if fault not in FAULTS:
        raise Inconclusive(f'OBS_DRILL_FAULT is one of {", ".join(FAULTS)}, got {fault!r}')
    control = environ.get('OBS_DRILL_CONTROL') or None
    if control is not None and control not in CONTROLS:
        raise Inconclusive(f'unknown control: {control}')
    if control and fault == 'none':
        raise Inconclusive('OBS_DRILL_CONTROL=skip-plant needs a fault to skip')
    return out, fault, control


def check_scenario(manifest, name, environ=os.environ):
    if not is_scenario(name):
        raise Inconclusive('unknown observation scenario: ' + name)
    kind = manifest.get('manifest_kind')
    if kind not in KINDS:
        raise Inconclusive(f'{name} runs on {" or ".join(KINDS)} (forwarders, bridges, projectors and the market slot); '
                           f'this manifest is {kind}')
    return drill_settings(environ)


def scenario(fixture, name, out_dir):
    settings, fault, control = check_scenario(fixture.m, name)
    result = ObservationDrill(fixture, name, Path(out_dir) / 'drill', None, settings, fault, control).run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} fault {fault} on {fixture.m.get("manifest_kind")} (engines {fixture.engine_driver()})')


def expected(fault, slot):
    """(line, text prefix) the verdict must name for a fault, or None for the clean run."""
    return {'none': None,
            'freeze-projector': ('V3', f'alive and unreachable: oe-projector/{slot}'),
            'freeze-bridge': ('V3', 'alive and unreachable: ct-bridge/bridge0'),
            'kill-core': ('V2', f'repeated restart: core/{slot} x{KILLS}'),
            'grow-file': ('V7', 'unexplained disk growth: core/ae0 state ')}[fault]


def verdict_line(verdict, fault, slot):
    """The drill's main line: the clean run PASSes; a planted run FAILs on exactly its line and service."""
    want = expected(fault, slot)
    if want is None:
        ok = verdict['status'] == 'PASS'
        return _line(ok, f'verdict {verdict["status"]}: {verdict["failures"] + verdict["inconclusive"]}',
                     'clean run did not pass: ' + '; '.join(verdict['failures'] + verdict['inconclusive']),
                     inconclusive=not ok and verdict['status'] == 'INCONCLUSIVE')
    line, prefix = want
    exact = verdict['status'] == 'FAIL' and len(verdict['failures']) == 1 and verdict['failures'][0].startswith(f'{line} {prefix}')
    text = (f'verdict line {line} is vacuous' if not any(f.startswith(f'{line} {prefix}') for f in verdict['failures'])
            else 'the verdict named more than the planted line and service: ' + '; '.join(verdict['failures']))
    return _line(exact, f'verdict {verdict["status"]}: {verdict["failures"] + verdict["inconclusive"]}', text)


def _line(holds, detail, text=None, inconclusive=False):
    out = {'holds': bool(holds) and not inconclusive, 'detail': detail}
    if not out['holds'] and text:
        out['text'] = text
    if inconclusive:
        out['inconclusive'] = True
    return out


# ------------------------------------------------------------------ money-check in the probe container

# Exit codes of money-check that are evidence, not a failed command: 0 green, 1 operational, 2 violated, 3 unstable,
# 4 indeterminate (a check was not judged). Only 0 holds the drill's money_check lines.
MONEY_CHECK_EXITS = (0, 1, 2, 3, 4)


def money_check_driver(fixture):
    """(driver mode, aeron dir) of the drill's money-check: the fixture's own driver mode, so the external kind
    (cps-ext) runs both reads on the probe's staged aeronmd, as the box does, and the embedded kind on their own
    driver. An external kind without the probe's aeronmd is not run in the other mode: INCONCLUSIVE."""
    mode = fixture.engine_driver()
    if mode == 'embedded':
        return 'embedded', None
    if mode != 'external':
        raise Inconclusive(f'money-check has no driver mode for engine_driver {mode!r}')
    if not (fixture.m.get('probe_libs') or {}).get('aeronmd'):
        raise Inconclusive('money-check in external driver mode needs the probe\'s aeronmd: the manifest pins no '
                           'probe_libs.aeronmd')
    return 'external', PROBE_AERON_DIR


def money_check_argv(fixture, point, users):
    """The money-check command of one quiesce point, as it runs in the probe container."""
    nodes, ports = fixture.m['nodes'], fixture.m['ports']
    mode, aeron_dir = money_check_driver(fixture)
    return ['python3', '-I', '/data/mc/money_check.py', '--store', 'core', '--cut', '/data/mc/cut.json',
            '--artifact-root', '/data/mc/jars', '--core-addresses', ','.join(nodes[f'ae{i}'] for i in range(3)),
            '--core-port-base', str(ports['ae_base']), '--core-port-stride', '100', '--local-host', nodes['probe'],
            '--driver-mode', mode, *(['--aeron-dir', aeron_dir] if aeron_dir else []),
            '--tool-key-file', '/data/mc/tool.key', '--admin-key-file', '/data/mc/admin.key',
            '--funding-file', f'/data/mc/funding-{point}.json', '--zero-hold-users', f'{users[0]}-{users[-1]}',
            '--core-metrics', ','.join(f'http://{nodes[f"ae{i}"]}:{core_contracts.engine_http_port(ports, f"ae{i}")}/metrics' for i in range(3)),
            '--json']


# ------------------------------------------------------------------ the sampler configuration of the fixture host

# The last field is the manifest port key; None for an engine slot, whose port is computed by the cluster-kit rule
SERVICE_KINDS = {'ae': ('core', 'core member', None), 'me': ('match', 'ME member', None),
                 'bridge': ('ct-bridge', 'ct-bridge', 'bridge_http'), 'fwd': ('ct-forwarder', 'ct-forwarder', 'forwarder_http'),
                 'projector': ('money-projector', 'money projector', 'projector_http'),
                 'shadow': ('core-replica', 'core-replica', None),
                 'gw': ('oe-gateway', 'oe-gateway', 'gateway_admin'), 'st': ('oe-stream', 'oe-stream', 'stream_admin'),
                 'pj': ('oe-projector', 'oe-projector', 'projector_admin'), 'md': ('oe-marketdata', 'oe-marketdata', 'md_admin')}


def service_name(slot):
    prefix = slot.rstrip('0123456789')
    return f'{SERVICE_KINDS[prefix][0]}/{slot}'


def pg_queries():
    md = core_contracts.MARKETDATA_DATABASE
    return [
        {'name': 'money_rows', 'db': 'r01_money',
         'sql': 'SELECT (SELECT count(*) FROM money_journal) + (SELECT count(*) FROM money_journal_leg)'},
        {'name': 'money_size', 'db': 'r01_money',
         'sql': "SELECT pg_total_relation_size('money_journal') + pg_total_relation_size('money_journal_leg')"},
        {'name': 'money_max_seq', 'db': 'r01_money', 'sql': 'SELECT COALESCE(max(journal_seq), 0) FROM money_journal'},
        {'name': 'order_rows', 'db': 'r01_gateway',
         'sql': 'SELECT (SELECT count(*) FROM oe_orders) + (SELECT count(*) FROM oe_order_events) + (SELECT count(*) FROM oe_fills)'},
        {'name': 'order_size', 'db': 'r01_gateway',
         'sql': "SELECT pg_total_relation_size('oe_orders') + pg_total_relation_size('oe_order_events') + "
                "pg_total_relation_size('oe_fills')"},
        {'name': 'oe_applied_seq', 'db': 'r01_gateway', 'sql': 'SELECT applied_seq FROM oe_projection_state'},
        {'name': 'md_rows', 'db': md, 'sql': 'SELECT (SELECT count(*) FROM md_trades) + (SELECT count(*) FROM md_candles)'},
        {'name': 'md_size', 'db': md, 'sql': "SELECT pg_total_relation_size('md_trades') + pg_total_relation_size('md_candles')"},
    ]


def sampler_config(fixture, out_file, shm_pids):
    """The obs-sampler configuration of the fixture host: every started slot, its HTTP routes, the state directories of
    the disk model, the fixture's PostgreSQL and the /dev/shm of the probe and of ae0 (each container has its own)."""
    m, nodes, ports = fixture.m, fixture.m['nodes'], fixture.m['ports']
    containers = fixture.registry['containers']
    services = []
    for slot in sorted(containers):
        prefix = slot.rstrip('0123456789')
        if prefix not in SERVICE_KINDS or slot not in nodes:
            continue
        _, kind, port_key = SERVICE_KINDS[prefix]
        port = core_contracts.engine_http_port(ports, slot) if port_key is None else ports[port_key]
        base = f'http://{nodes[slot]}:{port}'
        svc = {'name': service_name(slot), 'kind': kind, 'container': containers[slot], 'metrics': base + '/metrics',
               'health': base + '/health'}
        if prefix != 'projector':
            svc['ready'] = base + '/ready'
        services.append(svc)
    state = fixture.root / 'state'
    dirs = [{'name': 'core/ae0 state', 'path': str(state / 'ae0' / 'state'), 'model': 'core_log', 'service': 'core/ae0'},
            {'name': 'match/me0 state', 'path': str(state / 'me0' / 'state'), 'model': 'me_log', 'service': 'match/me0'},
            {'name': 'match/me0 journal', 'path': str(state / 'me0' / 'journal'), 'model': 'me_settlement_journal',
             'service': 'match/me0'},
            {'name': 'money history', 'path': '', 'model': 'money_db', 'db': 'r01_money', 'rows': 'money_rows', 'size': 'money_size'},
            {'name': 'order history', 'path': '', 'model': 'order_db', 'db': 'r01_gateway', 'rows': 'order_rows', 'size': 'order_size'},
            {'name': 'market history', 'path': '', 'model': 'market_db', 'db': core_contracts.MARKETDATA_DATABASE,
             'rows': 'md_rows', 'size': 'md_size'},
            {'name': 'pg wal', 'path': '', 'model': 'pg_wal'},
            {'name': 'logs', 'path': str(fixture.root / 'logs'), 'model': 'log_dir'},
            {'name': 'samples', 'path': str(Path(out_file).parent), 'model': 'sampler_file'}]
    pg = {'command': [str(fixture.pg / 'psql'), '-h', fixture.gateway, '-p', str(m['postgres_port']), '-U',
                      core_contracts.FIXTURE_SUPERUSER],
          'databases': ['r01_money', 'r01_gateway', core_contracts.MARKETDATA_DATABASE], 'wal_from': 'postgres',
          'queries': pg_queries()}
    return {'host': 'fixture', 'out': str(out_file), 'supervisor': 'docker', 'services': services,
            'volumes': [str(fixture.root)], 'dirs': dirs, 'shm': [f'/proc/{p}/root/dev/shm' for p in shm_pids], 'pg': pg}


# ------------------------------------------------------------------ the drill

class ObservationDrill(CriticalPathDrill):
    def __init__(self, fixture, name, out_dir, control, settings, fault, obs_control):
        super().__init__(fixture, name, out_dir, control)
        self.o, self.fault, self.obs_control = settings, fault, obs_control
        self.actions, self.planted, self.target = [], None, None
        self.record.update(obs_settings=settings, fault=fault, obs_control=obs_control)

    def users(self, n=2):
        return list(range(USERS, USERS + n))

    # ---------------------------------------------------------------- inputs

    def inputs(self):
        sampler = os.environ.get('OBS_SAMPLER_BIN')
        if not sampler or not Path(sampler).is_file():
            raise Inconclusive('no sampler binary: OBS_SAMPLER_BIN names no file')
        cut = os.environ.get('OBS_DRILL_CUT')
        if not cut or not Path(cut).is_file():
            raise Inconclusive('no cut manifest for money-check: OBS_DRILL_CUT names no file')
        self.record['sampler'] = {'path': sampler, 'sha256': hashlib.sha256(Path(sampler).read_bytes()).hexdigest()}
        return sampler, json.loads(Path(cut).read_text()), cut

    def stage_money_check(self, cut, cut_path):
        """money-check, the cut manifest and the three jars it names, in the probe container's /data/mc."""
        mc = self.probe_dir / 'mc'
        (mc / 'jars').mkdir(parents=True, exist_ok=True)
        here = Path(__file__).resolve().parent.parent / 'money-check'
        for name in ('money_check.py', 'core_expected.py'):
            shutil.copyfile(here / name, mc / name)
        for entry in (cut['tools']['core-dump'], cut['harness']['core_probe'], cut['artifacts']['core-cluster.jar']):
            shutil.copyfile(entry['path'], mc / 'jars' / Path(entry['path']).name)
        shutil.copyfile(cut_path, mc / 'cut.json')
        for name, principal in (('tool.key', 'probe-tool'), ('admin.key', 'probe-admin')):
            path = mc / name
            path.write_text(self.f.keys.credential(principal, 'ae') + '\n')
            path.chmod(0o600)

    def leader_value(self, series):
        vals = []
        for i in range(3):
            v = self.metric(f'ae{i}', series)
            role = self.metric(f'ae{i}', 'core_cluster_role')
            if role == 2 and v is not None:
                return v
            if v is not None:
                vals.append(v)
        return max(vals) if vals else None

    def metric(self, slot, series):
        r = self.f.http(slot, core_contracts.engine_http_port(self.f.m['ports'], slot), '/metrics')
        for text in (r.get('body') or '').splitlines():
            parts = text.split()
            if len(parts) >= 2 and parts[0] == series:
                try:
                    return float(parts[1])
                except ValueError:
                    return None
        return None

    def money_history_caught_up(self):
        head = self.leader_value('core_journal_seq')
        seen = self.metric('projector', 'projector_http', 'projector_last_journal_seq')
        return head is not None and seen is not None and seen >= head

    def funding_file(self, point):
        rows = json.loads(self.f.psql('r01_money', "SELECT COALESCE(json_agg(t), '[]'::json) FROM (SELECT asset_id, "
                                      'movement_type, sum(amount) AS amount FROM money_journal WHERE movement_type IN (2, 3) '
                                      'GROUP BY 1, 2) t') or '[]')
        out = {}
        for r in rows:
            entry = out.setdefault(str(r['asset_id']), {'deposits': 0, 'withdrawals': 0})
            entry['deposits' if r['movement_type'] == 2 else 'withdrawals'] += int(r['amount'])
        (self.probe_dir / 'mc' / f'funding-{point}.json').write_text(json.dumps(out))

    def quiesce(self, point):
        """The money history at the core's head, then money-check with the core expected side in the probe container."""
        _, waited = self.wait_for(self.money_history_caught_up, self.o['OBS_DRILL_CATCHUP_S'])
        self.funding_file(point)
        argv = money_check_argv(self.f, point, self.users())
        mode, aeron_dir = money_check_driver(self.f)
        self.record['money_check_driver'] = {'mode': mode, 'aeron_dir': aeron_dir}
        t0 = time.time()
        out = self.f.execute('probe', argv, timeout=600, check=False, accepted=MONEY_CHECK_EXITS)
        doc = None
        for text in reversed((out.stdout or '').splitlines()):
            if text.startswith('{'):
                doc = json.loads(text)
                break
        doc = doc or {'status': 'ERROR', 'error': (out.stderr or '')[-400:]}
        doc['exit_code'] = out.returncode
        doc['driver_mode'] = mode
        doc['history_wait_s'] = waited
        doc['wall_s'] = round(time.time() - t0, 1)
        (self.out / f'{point}.json').write_text(json.dumps(doc, indent=1) + '\n')
        (self.out / f'{point}.stderr').write_text(out.stderr or '')
        return doc

    # ---------------------------------------------------------------- faults

    def follower(self):
        for slot in ('ae2', 'ae1', 'ae0'):
            if self.metric(slot, 'core_cluster_role') == 0:
                return slot
        raise Inconclusive('no core follower found to kill')

    def lease_holder(self):
        for slot in ('pj0', 'pj1'):
            if self.metric(slot, 'projector_admin', 'projector_lease_held') == 1:
                return slot
        raise Inconclusive('no order projector holds the lease')

    def plant(self):
        f, fault = self.f, self.fault
        if self.obs_control == 'skip-plant':
            self.planted = {'skipped': True}
            return
        if fault == 'freeze-projector':
            self.target = self.lease_holder()
            self.planted = {'freeze': f.freeze_main(self.target, duration_s=self.o['OBS_DRILL_WINDOW_S'])}
        elif fault == 'freeze-bridge':
            self.target = 'bridge0'
            self.planted = {'freeze': f.freeze_main('bridge0', duration_s=self.o['OBS_DRILL_WINDOW_S'])}
        elif fault == 'kill-core':
            self.target = self.follower()
            witnesses = []
            for _ in range(KILLS):
                witnesses.append(f.kill(self.target))
                witnesses.append(f.restart(self.target, ready_timeout=120))
                # each life lasts long enough for the sampler to see it (a life shorter than a sample is invisible to V2)
                self.sleep(self.o['OBS_DRILL_KILL_GAP_S'])
            self.planted = {'kills': witnesses}
        elif fault == 'grow-file':
            self.target = 'ae0'
            path = f.root / 'state' / 'ae0' / 'state' / 'planted-growth.bin'
            with open(path, 'wb') as fh:
                chunk = os.urandom(1 << 20)
                for _ in range(self.o['OBS_DRILL_GROW_MB']):
                    fh.write(chunk)
            self.planted = {'file': str(path), 'bytes': path.stat().st_size}
        self.mark('planted')

    def resume(self):
        """Thaw a frozen process and wait for its work counter to reach the head. (holds, detail)."""
        if self.fault not in ('freeze-projector', 'freeze-bridge') or not self.planted or self.planted.get('skipped'):
            return None
        self.f.thaw_main(self.target)
        self.mark('resumed')
        # A process frozen longer than its own session bounds may exit when it runs again (the product's choice, recorded):
        # the supervisor's restart is emulated and recorded as an action, so it is explained, not a fault
        self.sleep(self.o['OBS_DRILL_EXIT_WAIT_S'])
        state = self.f.inspect('container', self.f.registry['containers'][self.target])['State']
        if not state['Running']:
            self.record['exit_after_resume'] = {'target': self.target, 'exit_code': state['ExitCode']}
            self.actions.append({'ts_ms': int(time.time() * 1000), 'service': service_name(self.target), 'action': 'restart',
                                 'note': f'supervisor restart after {self.target} exited {state["ExitCode"]} on resume'})
            self.f.restart(self.target, ready_timeout=self.o['OBS_DRILL_CATCHUP_S'])
        if self.fault == 'freeze-projector':
            head = lambda: self.leader_value('core_order_journal_seq')
            seen = lambda: self.metric(self.target, 'projector_admin', 'projector_applied_seq')
        else:
            head = lambda: max(v for v in (self.metric(f'me{i}', 'match_engine_next_journal_seq') for i in range(3))
                               if v is not None) - 1
            seen = lambda: self.metric('bridge0', 'bridge_http', 'bridge_core_cursor')
        target = head()
        value, waited = self.wait_for(lambda: (seen() or -1) >= target, self.o['OBS_DRILL_CATCHUP_S'])
        self.f.close_fault(self.target)
        if self.fault == 'freeze-projector':
            # the history outage window ends once the projector is back at the head (and the gateways probed it)
            for a in self.actions:
                if a['action'] == 'history':
                    a['until_ms'] = int(time.time() * 1000) + 2 * self.o['OBS_DRILL_SAMPLE_S'] * 1000
        return _line(bool(value), f'{self.target} back at {seen()} of head {target} after {waited} s',
                     f'{self.target} did not catch up within {self.o["OBS_DRILL_CATCHUP_S"]} s')

    # ---------------------------------------------------------------- run

    def run(self):
        f, o = self.f, self.o
        sampler, cut, cut_path = self.inputs()
        a, b = self.users()
        self.boot_cps([a, b])
        self.stage_money_check(cut, cut_path)
        self.calls([money_call(a, 'deposit', smoke_core.QUOTE_ASSET, 1000 * smoke_core.FP, 'fund'),
                    money_call(b, 'deposit', smoke_core.BASE_ASSET, 100 * smoke_core.FP, 'fund')])
        # Q0: after genesis and seeding, before the load
        q0 = self.quiesce('Q0')
        if f.slots.get('md0', {}).get('state') == 'STARTED':
            self.start_mdfeed()
        sample_dir = self.out / 'samples'
        sample_dir.mkdir()
        out_file = sample_dir / 'samples-fixture.jsonl'
        pids = [f.inspect('container', f.registry['containers'][s])['State']['Pid'] for s in ('probe', 'ae0')]
        config = sampler_config(f, out_file, pids)
        (self.out / 'sampler-config.json').write_text(json.dumps(config, indent=1) + '\n')
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'OBS_SAMPLER_CONFIG': str(self.out / 'sampler-config.json'),
               'OBS_SAMPLE_S': str(o['OBS_DRILL_SAMPLE_S'])}
        log = open(self.out / 'sampler.log', 'w')
        proc = subprocess.Popen([sampler], env=env, stdout=log, stderr=subprocess.STDOUT)
        self.mark('window_open')
        opened = self.clock()
        window = o['OBS_DRILL_WINDOW_S']
        plant_at = window / 3
        resume_at = plant_at + o['OBS_DRILL_FREEZE_S']
        batches, catch = 0, None
        try:
            while self.clock() - opened < window:
                t = self.clock() - opened
                if self.planted is None and t >= plant_at and self.fault != 'none':
                    self.plant()
                    if self.fault == 'freeze-projector' and self.target:
                        self.actions.append({'ts_ms': int(time.time() * 1000), 'service': '*', 'action': 'history',
                                             'until_ms': int(time.time() * 1000) + int((resume_at - t + o['OBS_DRILL_CATCHUP_S']) * 1000),  # extended at catch-up
                                             'note': f'the order history is behind while {self.target} is frozen (the planted fault)'})
                if catch is None and self.planted and t >= resume_at:
                    catch = self.resume() or False
                self.pairs(a, b, 2, 1, tag='obs-load')
                batches += 1
                self.sleep(o['OBS_DRILL_LOAD_EVERY_S'])
            if catch is None and self.planted:
                catch = self.resume() or False
            self.mark('load_stopped')
            # two more samples after the load
            self.sleep(2 * o['OBS_DRILL_SAMPLE_S'])
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(30)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.close()
        self.mark('window_closed')
        self.record['load_batches'] = batches
        self.cancel_all([a, b])
        q2 = self.quiesce('Q2')
        self.stop_mdfeed() if f.slots.get('md0', {}).get('state') == 'STARTED' else None
        if self.fault == 'grow-file' and self.planted and self.planted.get('file'):
            Path(self.planted['file']).unlink(missing_ok=True)
        return self.judge(out_file, q0, q2, catch)

    def snapshot_interval_s(self):
        env = self.f.inspect('container', self.f.registry['containers']['ae0'])['Config']['Env']
        for e in env:
            if e.startswith('SNAPSHOT_INTERVAL_MINUTES='):
                return int(e.split('=', 1)[1]) * 60
        return None

    def judge(self, out_file, q0, q2, catch):
        o = self.o
        d = out_file.parent
        (d / 'actions.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in self.actions))
        (d / 'Q0.json').write_text(json.dumps(q0))
        (d / 'Q2.json').write_text(json.dumps(q2))
        mode = self.metric('ae0', 'core_snapshot_mode')
        interval = self.snapshot_interval_s()
        settings = {'OBS_WINDOW_S': o['OBS_DRILL_WINDOW_S'], 'OBS_MAX_GAP_S': 3 * o['OBS_DRILL_SAMPLE_S'],
                    'OBS_STALL_S': o['OBS_DRILL_STALL_S'], 'OBS_SPIN_S': 2 * o['OBS_DRILL_STALL_S'],
                    'OBS_SNAPSHOT_INTERVAL_S': interval, 'OBS_ZERO_HOLD_USERS': [[USERS, USERS + 1]]}
        inputs = {'snapshot_mode': 'shadow' if mode == 1 else 'full', 'me_driver_mode': self.f.engine_driver()}
        (d / 'sampleset.json').write_text(json.dumps({'schema': observation.SCHEMA, 'hosts': {'fixture': out_file.name},
                                                      'actions': 'actions.jsonl', 'quiesce': {'Q0': 'Q0.json', 'Q2': 'Q2.json'},
                                                      'settings': settings, 'inputs': inputs}, indent=1) + '\n')
        loaded = observation.load_sample_set(d)
        verdict = observation.judge(loaded)
        (self.out / 'verdict.json').write_text(json.dumps(verdict, indent=1, default=str) + '\n')
        lines = {}
        if self.obs_control == 'skip-plant':
            lines['fault_planted'] = _line(False, 'the fault step was skipped', NOT_PLANTED, inconclusive=True)
        elif self.fault != 'none':
            lines['fault_planted'] = _line(bool(self.planted), json.dumps(self.planted, default=str)[:400], NOT_PLANTED,
                                           inconclusive=not self.planted)
        slot = self.target
        lines['verdict'] = verdict_line(verdict, self.fault, slot)
        lines['sample_chain'] = _line(not loaded['chain_errors'], json.dumps(loaded['chain_errors']) or 'chain intact',
                                      'sample chain broken')
        lines['money_check_q0'] = _line(q0.get('exit_code') == 0, f'Q0 exit {q0.get("exit_code")} {q0.get("status")}',
                                        f'money-check at Q0: {q0.get("status")} {q0.get("error", "")}')
        lines['money_check_q2'] = _line(q2.get('exit_code') == 0, f'Q2 exit {q2.get("exit_code")} {q2.get("status")}',
                                        f'money-check at Q2: {q2.get("status")} {q2.get("error", "")}')
        if catch is not None and catch is not False:
            lines['resumed_and_caught_up'] = catch
        elif self.fault in ('freeze-projector', 'freeze-bridge') and self.obs_control is None:
            lines['resumed_and_caught_up'] = _line(False, 'never resumed', 'frozen process was never resumed')
        if self.fault == 'freeze-projector' and slot:
            vals = [r.get('pg', {}).get('values', {}).get('oe_applied_seq') for r in loaded['hosts']['fixture']
                    if r.get('type') == 'sample']
            self.record['relation_cross_check'] = {'oe_projection_state.applied_seq': vals}
        if self.fault == 'freeze-bridge' and self.obs_control is None:
            by_core = observation.judge(loaded, kinds=observation.BRIDGE_BY_CORE_POSITION)
            as_gap = observation.judge(loaded, unreadable_as_gap=True)
            vacuous = not any(t.startswith('V3 alive and unreachable: ct-bridge/') for t in by_core['failures'])
            gap = as_gap['status'] == 'INCONCLUSIVE' and not any('ct-bridge' in t for t in as_gap['failures'])
            self.record['controls'] = {
                'bridge_by_core_position': {'status': by_core['status'], 'failures': by_core['failures'],
                                            'text': observation.CONTROL_BRIDGE_VACUOUS if vacuous else None},
                'unreadable_as_gap': {'status': as_gap['status'], 'inconclusive': as_gap['inconclusive'],
                                      'text': observation.CONTROL_READ_AS_GAP if gap else None}}
            lines['control_bridge_by_core_position'] = _line(vacuous, f'control build status {by_core["status"]}',
                                                             'control vacuous: the frozen bridge still failed V3')
            lines['control_unreadable_as_gap'] = _line(gap, f'control build status {as_gap["status"]}',
                                                       'control vacuous: the frozen bridge was not read as a gap')
        status, _ = smoke_core.verdict(lines)
        if self.obs_control == 'skip-plant':
            others = [k for k, v in lines.items() if not v['holds'] and k not in ('fault_planted', 'verdict')]
            status = 'INCONCLUSIVE'
            self.record['control_text'] = NOT_PLANTED
            self.record['other_failures'] = others
        result = {'status': status, 'lines': lines, 'record': self.record,
                  'verdict': {'status': verdict['status'], 'failures': verdict['failures'],
                              'inconclusive': verdict['inconclusive'], 'ready_on_failing': verdict['side']['ready_on_failing']}}
        failing = [v.get('text') for v in lines.values() if not v['holds'] and v.get('text')]
        if status != 'PASS':
            result['error'] = '; '.join(failing)
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'requests.json').write_text(json.dumps(self.log, indent=1, default=str) + '\n')
        return result
