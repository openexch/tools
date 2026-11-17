# SPDX-License-Identifier: Apache-2.0
"""Measurement runs on the product gateway and stream binaries: recorded data, never a pass line.

* ``gateway-egress-cost``: what the core sends to each client session, and what each binary holds, at idle and under a
  known order load, plus (when a market-sim binary is given) under the simulator's default bot mix.

  Bytes on the wire. A counting rule (no target, so it changes nothing) is inserted at the top of INPUT inside each
  counted slot's network namespace through the fixture's hash-pinned netfilter helper: for a gateway or stream slot one
  on the slot's fixed response port (the core's egress to that session, Aeron data frames with their IP and UDP
  headers, heartbeats and retransmits included) and, for every slot counted, one per core member address (everything
  the members send to the slot, which adds the status messages of the slot's ingress publication). The forwarder's
  response port is ephemeral, so it is counted by the member addresses only. Counters are read with
  ``iptables -S INPUT -v`` before and after each phase.

  Phases: idle (streams connected, no orders), load (``MEASURE_PAIRS`` crossing pairs, a maker SELL then a taker BUY,
  sent to gw0 one at a time at ``MEASURE_RATE`` requests per second, each with its own Idempotency-Key, while the
  maker and the taker are subscribed on st0), and sim (the simulator for ``SIM_S`` seconds against gw0 and st0 with
  its own API keys; skipped when ``MARKET_SIM_BINARY`` is unset). Each phase records the leader's, the gateways' and
  the streams' /metrics before and after (the stream watermark is the exchange-wide eventSeq, so its delta is the
  number of order events the core broadcast).

  Footprint: every ``MEASURE_SAMPLE_S`` the binary's /proc/1/status (VmRSS, VmHWM, RssAnon, RssFile, RssShmem) and
  ``du -sk /dev/shm`` from inside each gateway and stream container and each external driver sidecar, and one
  ``docker stats`` row per container.

Every size, rate and bound is a setting (``SETTINGS``, overridden by an environment variable of the same name).
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import time

from contracts import Inconclusive, Violation
import core_contracts
import gateway_probe
import gateway_scenarios
from gateway_scenarios import GatewayDrill, line, PAIR_PRICE, UNIT

MEASUREMENTS = ('gateway-egress-cost',)
SETTINGS = {
    'MEASURE_IDLE_S': 60, 'MEASURE_PAIRS': 200, 'MEASURE_RATE': 20, 'MEASURE_LOAD_BOUND_S': 900,
    'MEASURE_SETTLE_S': 5, 'MEASURE_SAMPLE_S': 5, 'MEASURE_TAP_S': 3600,
    'SIM_S': 600, 'SIM_SAMPLE_S': 15, 'SIM_EXIT_BOUND_S': 120, 'SIM_READY_BOUND_S': 300,
}
SIM_BINARY_ENV = 'MARKET_SIM_BINARY'
SIM_HEALTH_PORT = 8095
USER_BASE = 87001
COUNT_SLOTS = ('gw0', 'gw1', 'st0', 'st1', 'fwd0', 'fwd1')
FOOTPRINT_SLOTS = ('gw0', 'gw1', 'st0', 'st1')
# The simulator's population with its defaults: user ids from 900001, ten per market over five markets, the canary
SIM_BOT_BASE, SIM_BOTS_PER_MARKET, SIM_MARKETS, SIM_CANARY = 900001, 10, 5, 900999
# The faucet's per-request caps while the simulator seeds itself through the treasury lane: three times the largest
# per-bot float of each asset (USD 1 000 000, base floats 5, 100, 2000, 100 000, 1 000 000), so one deposit per
# asset and bot; the unknown asset of the fuzz keeps its fixture cap. A setting of this run, not of the gateway.
SIM_FAUCET_CAPS = {0: '3000000', 1: '15', 2: '300', 3: '6000', 4: '300000', 5: '3000000'}
RULE = re.compile(r'^-A INPUT (?P<match>.*?) -c (?P<pkts>\d+) (?P<bytes>\d+)\s*$')
STATUS_FIELDS = ('VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'RssShmem', 'VmSize')


def settings(environ=os.environ):
    """The settings in force: the defaults, each overridden by an environment variable of its name (a positive integer)."""
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
        elif not value.isdigit() or int(value) < 1:
            raise Violation(f'{name} must be a positive integer, got {value!r}')
        else:
            out[name] = int(value)
    return out


def sim_users():
    return [SIM_BOT_BASE + i for i in range(SIM_BOTS_PER_MARKET * SIM_MARKETS)] + [SIM_CANARY]


def counting_rules(slot, members, port):
    """The iptables argument lists that insert this slot's counting rules (no target: they only count)."""
    rules = [['-w', '2', '-I', 'INPUT', '-p', 'udp', '-s', ip] for ip in members.values()]
    if slot in core_contracts.GATEWAY_SLOTS:
        rules.append(['-w', '2', '-I', 'INPUT', '-p', 'udp', '--dport', str(port)])
    return rules


def parse_counters(text, members, port):
    """``iptables -S INPUT -v`` -> {'response_port': bytes, 'from_ae0': bytes, ..., 'packets': {...}}; a rule that is
    not one of ours is ignored; a counted rule missing from the output is absent (never zero)."""
    out, packets = {}, {}
    by_ip = {ip: name for name, ip in members.items()}
    for raw in text.splitlines():
        m = RULE.match(raw.strip())
        if not m:
            continue
        match = m.group('match').split()
        if '-j' in match:
            continue
        if '--dport' in match and match[match.index('--dport') + 1] == str(port) and '-s' not in match:
            key = 'response_port'
        elif '-s' in match and '--dport' not in match:
            ip = match[match.index('-s') + 1].split('/')[0]
            if ip not in by_ip:
                continue
            key = 'from_' + by_ip[ip]
        else:
            continue
        out[key], packets[key] = int(m.group('bytes')), int(m.group('pkts'))
    out['packets'] = packets
    return out


def parse_status(text):
    """/proc/<pid>/status fields in KiB (STATUS_FIELDS), plus ``shm_kib`` from a ``du -sk`` line."""
    out = {}
    for raw in text.splitlines():
        key, _, rest = raw.partition(':')
        if key in STATUS_FIELDS and rest.strip().endswith('kB'):
            out[key + '_kib'] = int(rest.split()[0])
        parts = raw.split()
        if len(parts) == 2 and parts[1] == '/dev/shm' and parts[0].isdigit():
            out['shm_kib'] = int(parts[0])
    return out


def delta(before, after, key):
    a, b = (after or {}).get(key), (before or {}).get(key)
    return None if a is None or b is None else a - b


def phase_cost(before, after, orders=None, idle=None, members=('ae0', 'ae1', 'ae2')):
    """Per counted slot: bytes on the response port and from the members over the phase, per second, and per order
    (net of the idle rate over the same span) when ``orders`` is given. ``before``/``after`` are counter snapshots
    ({slot: {'at_ns', 'response_port', 'from_ae0', ...}})."""
    out = {}
    for slot in sorted(set(before) & set(after)):
        b, a = before[slot], after[slot]
        span = (a['at_ns'] - b['at_ns']) / 1e9
        row = {'seconds': round(span, 3)}
        port = delta(b, a, 'response_port')
        parts = [delta(b, a, 'from_' + m) for m in members]
        total = None if any(v is None for v in parts) else sum(parts)
        row['response_port_bytes'], row['from_core_bytes'] = port, total
        for name, value in (('response_port', port), ('from_core', total)):
            if value is None or span <= 0:
                continue
            row[name + '_bytes_per_s'] = round(value / span, 1)
            if orders:
                base = ((idle or {}).get(slot) or {}).get(name + '_bytes_per_s') or 0
                row[name + '_bytes_per_order'] = round((value - base * span) / orders, 1)
        out[slot] = row
    return out


def metric(snapshot, name):
    return (snapshot or {}).get(name)


def stream_view(before, after, slot):
    """Events the core broadcast over a phase (the stream's watermark delta) and the stream's order-event queries
    (head probes and replay pages)."""
    b, a = (before or {}).get(slot) or {}, (after or {}).get(slot) or {}
    return {'events': delta(b, a, 'stream_watermark'), 'event_queries': delta(b, a, 'stream_event_queries_total'),
            'snapshot_queries': delta(b, a, 'stream_snapshot_queries_total'),
            'balance_queries': delta(b, a, 'stream_balance_queries_total')}


def footprint_summary(samples):
    """Peak and last of every footprint field per container."""
    out = {}
    for sample in samples:
        for name, row in sample['containers'].items():
            agg = out.setdefault(name, {'samples': 0})
            agg['samples'] += 1
            for key, value in row.items():
                if isinstance(value, (int, float)):
                    agg['peak_' + key] = max(agg.get('peak_' + key, value), value)
                    agg['last_' + key] = value
    return out


def sim_argv(binary, gateway, stream, keys_file, health, seconds, stats_file, caps):
    """The simulator's command line: its default bot mix and rate, the GBM reference (the fixture has no internet), no
    bridge or edge checks (not fixture roles), its keyed-request counters written every 30 s."""
    faucet = ','.join(f'{a}:{v}' for a, v in sorted(caps.items()))
    return ['timeout', '-s', 'INT', str(seconds), binary, '-mode=run', '-gateway-url', f'http://{gateway}',
            '-stream-url', f'ws://{stream}/ws/v2', '-api-keys-file', keys_file, '-faucet-max', faucet, '-source', 'gbm',
            '-health-addr', health, '-bridge-health-url', '', '-anchor-file', '', '-keyed-stats-file', stats_file,
            '-keyed-stats-interval', '30s']


def sim_metrics(text):
    """The simulator's /metrics -> {name{labels}: value} (its own exposition; unknown lines skipped)."""
    out = {}
    for raw in (text or '').splitlines():
        if not raw or raw.startswith('#'):
            continue
        name, _, value = raw.rpartition(' ')
        try:
            out[name] = float(value)
        except ValueError:
            continue
    return out


class EgressCost(GatewayDrill):
    def __init__(self, fixture, name, out_dir):
        super().__init__(fixture, name, out_dir)
        self.ms = settings()
        self.record['measure_settings'] = self.ms
        self.footprint = []
        self.sim_binary = os.environ.get(SIM_BINARY_ENV) or None

    # ---------------------------------------------------------------- boot

    def boot_measure(self, users, extra_keys):
        f = self.f
        f.gateway_user_ids = sorted(users + extra_keys)
        if extra_keys:
            f.GATEWAY_FAUCET_CAPS = {**f.GATEWAY_FAUCET_CAPS, **SIM_FAUCET_CAPS}
        f.start({'users': sorted(users), 'markets': [1, 2, 3, 4, 5], 'funding_for': 'a01-mix',
                 'seed': f.m['seed'] & 0xFFFFFFFF, 'risk': gateway_scenarios.DRILL_RISK, 'tap_ms': self.ms['MEASURE_TAP_S'] * 1000})
        self.mark('booted')
        shutil.copyfile(Path(gateway_probe.__file__), self.probe_dir / 'gateway_probe.py')
        (self.probe_dir / 'gw-keys.json').write_text(json.dumps({str(u): k for u, k in f.keys.api_keys(sorted(users)).items()}))
        f.secret_values = f.keys.secrets()
        self.record['slots'] = {k: f.slots.get(k) for k in sorted(core_contracts.GATEWAY_SLOTS)}
        self.record['faucet_caps'] = {str(k): v for k, v in sorted(f.GATEWAY_FAUCET_CAPS.items())}

    def health(self, slot):
        port = self.f.m['ports']['gateway_admin' if slot.startswith('gw') else 'stream_admin']
        try:
            return json.loads(self.f.http(slot, port, '/health').get('body') or 'null')
        except ValueError:
            return None

    # ---------------------------------------------------------------- probes

    def members(self):
        return {f'ae{i}': self.f.m['nodes'][f'ae{i}'] for i in range(3)}

    def install_counters(self):
        out = {}
        for slot in COUNT_SLOTS:
            if slot not in self.f.registry['containers']:
                out[slot] = 'not running'
                continue
            for rule in counting_rules(slot, self.members(), self.f.GATEWAY_RESPONSE_PORT):
                self.f.netfilter(slot, rule)
            out[slot] = 'counting'
        self.record['counters'] = out

    def counters(self):
        snap = {}
        for slot in COUNT_SLOTS:
            if slot not in self.f.registry['containers']:
                continue
            text = self.f.netfilter(slot, ['-w', '2', '-S', 'INPUT', '-v'])
            row = parse_counters(text, self.members(), self.f.GATEWAY_RESPONSE_PORT)
            row['at_ns'] = time.time_ns()
            snap[slot] = row
        return snap

    def metrics_all(self):
        f, ports = self.f, self.f.m['ports']
        leader, lm = self.leader_metrics()
        snap = {'at_ns': time.time_ns(), 'leader': leader,
                'core': {k: v for k, v in lm.items() if k.startswith(('core_log_position', 'core_egress', 'core_sessions',
                                                                    'core_resumable', 'core_order_entry_gate'))}}
        for slot in FOOTPRINT_SLOTS:
            port = ports['gateway_admin' if slot.startswith('gw') else 'stream_admin']
            try:
                snap[slot] = f.metrics(slot, port)
            except Inconclusive as error:
                snap[slot] = {'error': str(error)}
        return snap

    def containers(self):
        names = []
        for slot in FOOTPRINT_SLOTS:
            if slot in self.f.registry['containers']:
                names.append(slot)
            if slot + self.f.DRIVER_SIDECAR in self.f.registry['containers']:
                names.append(slot + self.f.DRIVER_SIDECAR)
        return names

    def sample_footprint(self, phase):
        f = self.f
        names = self.containers()
        row = {'at_ns': time.time_ns(), 'phase': phase, 'containers': {}}
        for name in names:
            r = f.execute(name, ['sh', '-c', 'cat /proc/1/status; cat /proc/1/comm; du -sk /dev/shm; ls -l /dev/shm/*/ 2>/dev/null'],
                          timeout=15, check=False)
            parsed = parse_status(r.stdout or '')
            row['containers'][name] = parsed
            row.setdefault('ls', {})[name] = (r.stdout or '').split('\n')[-12:]
        ids = [f.registry['containers'][n] for n in names]
        stats = f.command(['docker', 'stats', '--no-stream', '--no-trunc', '--format', '{{json .}}', *ids], timeout=60, check=False)
        by_id = {}
        for raw in (stats.stdout or '').splitlines():
            try:
                s = json.loads(raw)
            except ValueError:
                continue
            by_id[s.get('ID') or s.get('Container')] = s
        for name, cid in zip(names, ids):
            s = by_id.get(cid) or {}
            row['containers'][name]['docker_mem'] = s.get('MemUsage')
            row['containers'][name]['docker_cpu'] = s.get('CPUPerc')
        self.footprint.append(row)
        return row

    def wait_sampling(self, seconds, phase, until=None):
        deadline = self.clock() + seconds
        while self.clock() < deadline:
            if until is not None and until():
                return True
            self.sample_footprint(phase)
            self.sleep(min(self.ms['MEASURE_SAMPLE_S'], max(0.0, deadline - self.clock())))
        return until() if until is not None else True

    def snapshot(self, label):
        out = {'label': label, 'counters': self.counters(), 'metrics': self.metrics_all()}
        self.record.setdefault('snapshots', []).append(out)
        return out

    # ---------------------------------------------------------------- the load

    def pair_rows(self, maker, taker):
        rows = []
        for n in range(self.ms['MEASURE_PAIRS']):
            qty = (n + 1) * UNIT
            for side, user in (('SELL', maker), ('BUY', taker)):
                i = len(rows)
                rows.append({'i': i, 'key': _key(self.f.m['seed'], i), 'user': user, 'quantity': qty,
                             'body': {'marketId': '1', 'side': side, 'type': 'LIMIT', 'timeInForce': 'GTC',
                                      'price': gateway_probe.money(PAIR_PRICE), 'quantity': gateway_probe.money(qty)},
                             'resend': False})
        return rows

    def run_load(self, maker, taker):
        s = self.s
        rows = self.pair_rows(maker, taker)
        (self.probe_dir / 'measure-story.json').write_text(json.dumps(rows))
        argv = ['python3', '-I', '/data/gateway_probe.py', 'load', '--targets', self.gw('gw0'), '--keys', '/data/gw-keys.json',
                '--story', '/data/measure-story.json', '--out', '/data/measure-attempts.jsonl', '--done-file',
                '/data/measure.done', '--concurrency', '1', '--retry-bound-s', str(s['GW_RETRY_BOUND_S']),
                '--attempt-s', str(s['GW_ATTEMPT_S']), '--rate', str(self.ms['MEASURE_RATE'])]
        for n in ('measure-attempts.jsonl', 'measure.done'):
            (self.probe_dir / n).unlink(missing_ok=True)
        self.probe_bg(argv, 'measure-load')
        done = self.wait_sampling(self.ms['MEASURE_LOAD_BOUND_S'], 'load', until=lambda: (self.probe_dir / 'measure.done').exists())
        attempts = gateway_scenarios._jsonl(self.probe_dir / 'measure-attempts.jsonl')
        statuses = {}
        for a in attempts:
            statuses[str(a['status'])] = statuses.get(str(a['status']), 0) + 1
        accepted = sum(1 for a in attempts if a['status'] in (200, 201))
        (self.out / 'measure-attempts.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in attempts))
        return {'done': done, 'rows': len(rows), 'attempts': len(attempts), 'accepted': accepted, 'statuses': statuses}

    # ---------------------------------------------------------------- the simulator

    def run_sim(self):
        f, ms = self.f, self.ms
        binary = Path(self.sim_binary)
        if not binary.is_file():
            raise Inconclusive(f'{SIM_BINARY_ENV} names no file: {binary}')
        import hashlib
        staged = self.probe_dir / 'market-sim'
        shutil.copyfile(binary, staged)
        staged.chmod(0o755)
        keys = f.keys.api_keys(sim_users())
        (self.probe_dir / 'sim-keys').write_text(''.join(f'{keys[u]}:{u}\n' for u in sorted(keys)))
        health = f'{f.m["nodes"]["probe"]}:{SIM_HEALTH_PORT}'
        argv = sim_argv('/data/market-sim', self.gw('gw0'), self.st('st0'), '/data/sim-keys', health, ms['SIM_S'],
                        '/data/sim-keyed.json', SIM_FAUCET_CAPS)
        info = {'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'argv': argv,
                'users': len(keys), 'seconds': ms['SIM_S']}
        for n in ('sim.out', 'sim.exit', 'sim-keyed.json'):
            (self.probe_dir / n).unlink(missing_ok=True)
        cid = f.registry['containers']['probe']; f.inspect('container', cid)
        f.command(['docker', 'exec', '-d', cid, 'sh', '-c', shlex.join(argv) + ' > /data/sim.out 2>&1; echo $? > /data/sim.exit'])
        started = self.clock()
        info['started_ns'] = time.time_ns()
        series, last = [], {}
        exit_file = self.probe_dir / 'sim.exit'
        while not exit_file.exists() and self.clock() - started < ms['SIM_S'] + ms['SIM_EXIT_BOUND_S']:
            self.sleep(ms['SIM_SAMPLE_S'])
            row = {'at_ns': time.time_ns(), 'metrics': self.metrics_all()}
            r = f.http('probe', SIM_HEALTH_PORT, '/metrics')
            if r.get('status') == 200:
                last = sim_metrics(r.get('body'))
                row['sim'] = last
            series.append(row)
            self.sample_footprint('sim')
        info['ended_ns'] = time.time_ns()
        info['exit'] = exit_file.read_text().strip() if exit_file.exists() else None
        info['series'] = series
        info['last_sim_metrics'] = last
        for n in ('sim.out', 'sim-keyed.json'):
            if (self.probe_dir / n).exists():
                shutil.copyfile(self.probe_dir / n, self.out / n)
        info['keyed'] = json.loads((self.probe_dir / 'sim-keyed.json').read_text()) if (self.probe_dir / 'sim-keyed.json').exists() else None
        return info

    # ---------------------------------------------------------------- the run

    def run(self):
        f, ms = self.f, self.ms
        maker, taker = USER_BASE, USER_BASE + 10
        extra = sim_users() if self.sim_binary else []
        self.boot_measure([maker, taker], extra)
        if not f.m.get('netfilter_helper'):
            raise Inconclusive('the egress counters need the netfilter helper')
        self.record['health'] = {s: self.health(s) for s in FOOTPRINT_SLOTS}
        self.record['markets'] = self.f.http('gw0', f.m['ports']['gateway_http'], '/api/v2/markets')
        self.sample_footprint('booted')
        self.start_streams([{'user': u, 'target': self.st('st0')} for u in (maker, taker)], name='measure-streams', seconds=7200)
        self.install_counters()
        self.sleep(ms['MEASURE_SETTLE_S'])
        s0 = self.snapshot('idle-start')
        self.mark('idle_start')
        self.wait_sampling(ms['MEASURE_IDLE_S'], 'idle')
        s1 = self.snapshot('idle-end')
        self.mark('idle_end')
        idle = phase_cost(s0['counters'], s1['counters'])
        load = self.run_load(maker, taker)
        self.sleep(ms['MEASURE_SETTLE_S'])
        s2 = self.snapshot('load-end')
        self.mark('load_end')
        loaded = phase_cost(s1['counters'], s2['counters'], orders=load['accepted'], idle=idle)
        result = {'idle': {'cost': idle, 'streams': {st: stream_view(s0['metrics'], s1['metrics'], st) for st in ('st0', 'st1')},
                           'log_position': delta(s0['metrics']['core'], s1['metrics']['core'], 'core_log_position'),
                           'seconds': (s1['metrics']['at_ns'] - s0['metrics']['at_ns']) / 1e9},
                  'load': {'cost': loaded, 'orders': load,
                           'streams': {st: stream_view(s1['metrics'], s2['metrics'], st) for st in ('st0', 'st1')},
                           'log_position': delta(s1['metrics']['core'], s2['metrics']['core'], 'core_log_position')}}
        sim = None
        if self.sim_binary:
            sim = self.run_sim()
            s3 = self.snapshot('sim-end')
            self.mark('sim_end')
            result['sim'] = {'cost': phase_cost(s2['counters'], s3['counters'], idle=idle),
                             'streams': {st: stream_view(s2['metrics'], s3['metrics'], st) for st in ('st0', 'st1')},
                             'log_position': delta(s2['metrics']['core'], s3['metrics']['core'], 'core_log_position'),
                             'seconds': (s3['metrics']['at_ns'] - s2['metrics']['at_ns']) / 1e9,
                             'exit': sim['exit'], 'last_sim_metrics': sim['last_sim_metrics']}
            (self.out / 'sim.json').write_text(json.dumps(sim, indent=1, default=str) + '\n')
        else:
            result['sim'] = {'skipped': f'{SIM_BINARY_ENV} unset'}
        final = self.stop_streams('measure-streams', bound_s=60)
        self.sample_footprint('end')
        result['footprint'] = footprint_summary(self.footprint)
        result['driver'] = self.driver()
        (self.out / 'egress-cost.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'footprint-samples.json').write_text(json.dumps(self.footprint, indent=1, default=str) + '\n')
        self.record['stream_clients'] = [{k: c.get(k) for k in ('user', 'target', 'connects')} for c in final or []]
        counted = all(isinstance((loaded.get(s) or {}).get('response_port_bytes'), int) for s in ('gw0', 'st0'))
        lines = {'counters_read': line(counted, {s: loaded.get(s) for s in ('gw0', 'st0')}, 'egress counters missing',
                                       inconclusive=not counted),
                 'load_accepted': line(load['accepted'] == load['rows'], load, 'not every load order was accepted',
                                       inconclusive=not load['done'])}
        if sim is not None:
            lines['sim_ran'] = line(sim['exit'] in ('0', '124', '130') and bool(sim['last_sim_metrics']),
                                    {'exit': sim['exit'], 'metrics': bool(sim['last_sim_metrics'])},
                                    'the simulator did not run for its time', inconclusive=sim['exit'] is None)
        return self.finish(lines)


def _key(seed, i):
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f'measure-{seed}-{i}'))


def run(fixture, name, out_dir):
    if name not in MEASUREMENTS:
        raise Inconclusive('unknown measurement: ' + name)
    m = EgressCost(fixture, name, out_dir)
    result = m.run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name}: measurement on the product gateway and stream binaries ({m.driver()} driver); data, not a gate')
