# SPDX-License-Identifier: Apache-2.0
"""The observation verdict: an offline judgement over the merged sample files of obs-sampler (one file per host).

Input, a sample set: a directory with ``sampleset.json`` (schema ``obs-sampleset/1``):

  {"schema": "obs-sampleset/1",
   "hosts": {"<host>": "<sample file, relative to the directory>"},
   "actions": "actions.jsonl",                  optional: the recorded operator actions, one JSON object per line
   "quiesce": {"Q0": "q0.json", "Q2": "q2.json"},  money-check --json output at the two quiesce points
   "settings": {"OBS_WINDOW_S": 86400, ...},     overrides of SETTINGS
   "inputs": {"snapshot_mode": "shadow", "me_driver_mode": "external", ...}}

An action line: {"ts_ms": <epoch ms>, "service": "<service or *>", "action": "<restart|stop|start|gate|history|pause>",
"until_ms": <epoch ms, for a window>, "note": "..."}. A restart, a gate change or a history outage that has no action
record is a fault; one with a record is judged as explained.

The verdict lines V1 to V12 (each FAIL names its line and the service; missing evidence is INCONCLUSIVE):

  V1  samples complete per host (no gap above OBS_MAX_GAP_S, first to last at least OBS_WINDOW_S, the hash chain intact)
  V2  no repeated crash: per service the (pid, start time) pair changes at most OBS_MAX_RESTARTS times unexplained
  V3  progress pairs with life, one rule per service kind (KINDS): a live pid whose input moved must move its work
      counter within OBS_STALL_S; a counter that cannot be read counts as not moved
  V4  exactly one leader per cluster at every sample
  V5  no spin: no work and a CPU share above OBS_SPIN_CPU_PCT for OBS_SPIN_S
  V6  snapshot age under OBS_SNAPSHOT_AGE_S on every member; the ME reclaim counter advances; the core half per the
      snapshot mode (shadow: the replica purge position advances on every member)
  V7  disk growth explained per directory by its model (DISK_MODELS) within OBS_GROWTH_TOL_PCT or under a slope
  V8  /dev/shm returns to its baseline; no tool driver directory left behind
  V9  no residual hold at Q0 and Q2; the release backlog drains within OBS_STALL_S
  V10 ingress schema rejects stay 0
  V11 the order-entry gate stays OPEN except in recorded windows; no bridge halt
  V12 history age under its stale setting except in recorded windows (gateway and market data)

The process's own /health and /ready are printed next to the verdict, never used as the life signal: a frozen process
answers neither, so the life signal is the host's (the pid alive with its start time, the supervisor running).

Planted texts (the unit sets of test_observation must produce exactly these):
  V1 ``samples incomplete: gap <s> s``, V2 ``repeated restart: <service> x<n>``, V3 ``healthy without progress:
  <service> <counter>`` or ``alive and unreachable: <service>``, V4 ``no leader: <cluster>``, V5 ``spin: <service>``,
  V6 ``snapshot overdue: <member>`` or ``no reclaim in the window: <member>``, V7 ``unexplained disk growth: <dir>
  <bytes>``, V8 ``/dev/shm did not return to baseline`` or ``leftover driver directory: <dir>``, V9 ``residual hold:
  user <u> asset <a> <amount>``, V10 ``schema rejects: <n>``, V11 ``gate closed without a recorded action``, V12
  ``history stale outside a recorded window``.
"""
import bisect
import fnmatch
import hashlib
import json
from pathlib import Path
import re

SCHEMA = 'obs-sampleset/1'
LINES = tuple(f'V{i}' for i in range(1, 13))

# The settings of section "settings" of the sample set override these. Every size, bound and rate is a setting.
SETTINGS = {
    'OBS_WINDOW_S': 86400, 'OBS_MAX_GAP_S': 180, 'OBS_MAX_RESTARTS': 0, 'OBS_STALL_S': 120,
    'OBS_SPIN_CPU_PCT': 80, 'OBS_SPIN_S': 300,
    # V6: the bound is 3 x the profile's snapshot interval; with neither set the snapshot age is not judged (INCONCLUSIVE)
    'OBS_SNAPSHOT_AGE_S': None, 'OBS_SNAPSHOT_INTERVAL_S': None,
    'OBS_GROWTH_TOL_PCT': 20,
    # V6: the ME frees log bytes only once a whole archive segment is behind a snapshot, so the reclaim rule is judged
    # on a window at least this long; a shorter window (a drill) records the counters and says so
    'OBS_RECLAIM_MIN_WINDOW_S': 3600,
    # V7 slack: growth under this many MB is never a finding (a file system allocates in steps)
    'OBS_GROWTH_SLACK_MB': 64,
    # V7 slopes, set from the rehearsal's measured slope x 2; the values here are starting points
    'OBS_WAL_SLOPE_MB_H': 512, 'OBS_LOG_SLOPE_MB_H': 64, 'OBS_ME_LOG_SLOPE_MB_H': 256,
    # V7 models: bytes per core order journal event, per ME settlement journal record, the idle core log term per member
    'OBS_CORE_JOURNAL_EVENT_B': 256, 'OBS_ME_JOURNAL_RECORD_B': 256, 'OBS_IDLE_LOG_B_S': 6600,
    # V8: /dev/shm may end this many MB above its first sample
    'OBS_SHM_SLACK_MB': 64,
    # V12: the gateway's own GATEWAY_HISTORY_STALE_MS and the market service's MD_HISTORY_STALE_MS (their defaults)
    'OBS_GATEWAY_HISTORY_STALE_MS': 5000, 'OBS_MD_HISTORY_STALE_MS': 5000,
    # V5: kinds whose idle strategy spins by design (a busy-spin driver): their CPU is recorded, never judged
    'OBS_SPIN_EXEMPT': [],
    # V9: the simulator's users, whose every hold must be zero at a quiesce point (a list of [low, high] ranges). When
    # set, each quiesce document must carry a zero_holds check over exactly these users with status PASS (money-check
    # --zero-hold-users); a document without it was not judged on this rule: INCONCLUSIVE
    'OBS_ZERO_HOLD_USERS': [],
}

# Tool driver directories that must not outlive their tool (V8): CoreDump's embedded driver and the genesis tool's
TOOL_DRIVER_DIRS = ('aeron-aedump-*', 'ct-genesis-*')

# V3, one rule per service kind. ``work``: the counters whose rise is work (``age:`` marks an age gauge: work means the
# age stays under OBS_STALL_S); ``input``: the signals whose change means there was work to do, each (how, series, kind):
# ``sum`` over every service of the kind, ``max_other`` the highest of the kind's other services (the leader's position
# for a follower), ``self`` the service's own series, ``always`` (the simulator: it is the load);
# ``while``: a gauge of the service that must be above 0 for the rule to apply; ``standby``: a gauge whose 0 means the
# service is a standby that is not expected to work.
KINDS = {
    'core member': {'work': ['core_log_position', 'core_last_applied_trade_id', 'core_feed_cursor'],
                    'input': [('sum', 'gateway_requests_total', 'oe-gateway'), ('max_other', 'core_log_position', 'core member')]},
    'ME member': {'work': ['match_log_position'],
                  'input': [('sum', 'forwarder_dispatch_sent_total', 'ct-forwarder'),
                            ('max_other', 'match_log_position', 'ME member')]},
    'ct-bridge': {'work': ['bridge_core_cursor', 'bridge_forwarded_total'],
                  'input': [('max', 'match_engine_next_journal_seq', 'ME member')]},
    'ct-forwarder': {'work': ['forwarder_book_frames_total', 'forwarder_dispatch_sent_total'],
                     'input': [('self', 'forwarder_dispatch_received_total', None),
                               ('sum', 'gateway_requests_total', 'oe-gateway')]},
    'money projector': {'work': ['projector_last_journal_seq', 'projector_rows_projected_total'],
                        'input': [('max', 'core_journal_seq', 'core member')]},
    'core-replica': {'work': ['age:shadow_last_age_ms'], 'input': [('max', 'core_log_position', 'core member')]},
    'oe-projector': {'work': ['projector_applied_seq', 'projector_records_applied_total'],
                     'input': [('max', 'core_order_journal_seq', 'core member')], 'standby': 'projector_lease_held'},
    'oe-gateway': {'work': ['gateway_requests_total'], 'input': [('sum', 'sim_orders_placed_total', 'simulator')]},
    'oe-stream': {'work': ['stream_ws_frames_sent_total'], 'input': [('max', 'core_order_journal_seq', 'core member')],
                  'while': 'stream_ws_connections'},
    'oe-marketdata': {'work': ['md_ws_frames_sent_total'],
                      'input': [('sum', 'forwarder_book_frames_total', 'ct-forwarder'),
                                ('max', 'match_engine_next_journal_seq', 'ME member')],
                      'while': 'md_ws_connections'},
    'simulator': {'work': ['sim_orders_placed_total'], 'input': [('always', None, None)]},
}

# V4, V6, V9 to V12 series
ROLE = {'core': ('core member', 'core_cluster_role'), 'match': ('ME member', 'match_cluster_role')}
LEADER_ROLE = 2.0          # Aeron Cluster's Cluster.Role: 0 follower, 1 candidate, 2 leader
SNAPSHOT_AGE = {'core member': 'core_snapshot_age_seconds', 'ME member': 'match_snapshot_age_seconds'}
ME_RECLAIM = 'match_log_bytes_reclaimed_total'
CORE_PURGE = 'shadow_log_purge_position'
RELEASE_BACKLOG = 'core_release_backlog'
SCHEMA_REJECTS = 'core_ingress_schema_rejects_total'
GATE = 'core_order_entry_gate'
GATE_OPEN = 1.0            # core_order_entry_gate: 1 when the global order-entry gate is OPEN, else 0
BRIDGE_HALTED = 'bridge_halted'
HISTORY_AGE = {'oe-gateway': ('gateway_history_age_ms', 'OBS_GATEWAY_HISTORY_STALE_MS'),
               'oe-marketdata': ('md_history_age_ms', 'OBS_MD_HISTORY_STALE_MS')}
# The ME's OMS-named egress lane: printed, never judged
OMS_LANE = ('match_egress_queue_oms', 'match_egress_queue_oms_bytes', 'match_dropped_oms_egress_total')
OMS_LANE_NOTE = 'a follower drop count on this lane is expected by design; it is neither a fault nor a pass'

# V7 disk models: what each directory model explains its growth with
DISK_MODELS = {
    'core_order_journal': 'journal sequence delta (core_order_journal_seq) x OBS_CORE_JOURNAL_EVENT_B',
    'core_log': 'log position delta (core_log_position) + OBS_IDLE_LOG_B_S x seconds',
    'me_log': 'log position delta (match_log_position) - reclaimed bytes (match_log_bytes_reclaimed_total)',
    'me_settlement_journal': 'ME journal sequence delta (match_engine_next_journal_seq) x OBS_ME_JOURNAL_RECORD_B, less retention deletes',
    'replica_archive': 'the core log model of the member it follows',
    'money_db': 'row delta of money_journal and money_journal_leg x measured row size',
    'order_db': 'row deltas of the oe_* relations x measured row size',
    'market_db': 'row deltas of md_trades and md_candles x measured row size',
    'pg_wal': 'slope under OBS_WAL_SLOPE_MB_H',
    'log_dir': 'slope under OBS_LOG_SLOPE_MB_H (a shrink is a rotation)',
    'sampler_file': 'sample count x measured line size',
    'slope': 'slope under the directory\'s own slope_mb_h input',
}
MB = 1 << 20

V1_GAP = 'samples incomplete: gap {} s'
TEXT = {
    'V2': 'repeated restart: {} x{}', 'V3_stall': 'healthy without progress: {} {}', 'V3_dark': 'alive and unreachable: {}',
    'V4': 'no leader: {}', 'V5': 'spin: {}', 'V6_age': 'snapshot overdue: {}', 'V6_reclaim': 'no reclaim in the window: {}',
    'V7': 'unexplained disk growth: {} {}', 'V8_base': '/dev/shm did not return to baseline',
    'V8_dir': 'leftover driver directory: {}', 'V9': 'residual hold: user {} asset {} {}', 'V10': 'schema rejects: {}',
    'V11': 'gate closed without a recorded action', 'V12': 'history stale outside a recorded window',
}
NO_SAMPLE_SET = 'no sample set'


class Line:
    """One verdict line's outcome: PASS, FAIL (texts), INCONCLUSIVE (texts) or NA (reason)."""

    def __init__(self, name):
        self.name, self.fails, self.gaps, self.na, self.notes = name, [], [], None, []

    def fail(self, text):
        if text not in self.fails:
            self.fails.append(text)

    def gap(self, text):
        if text not in self.gaps:
            self.gaps.append(text)

    @property
    def status(self):
        if self.fails:
            return 'FAIL'
        if self.gaps:
            return 'INCONCLUSIVE'
        return 'NA' if self.na else 'PASS'

    def doc(self):
        d = {'line': self.name, 'status': self.status}
        if self.fails: d['fail'] = self.fails
        if self.gaps: d['inconclusive'] = self.gaps
        if self.na: d['na'] = self.na
        if self.notes: d['notes'] = self.notes
        return d


# ------------------------------------------------------------------ loading

def verify_line(raw):
    """(hash, prev) of one sample line, or raise ValueError: the sampler's chain rule (obs-sampler chain.go)."""
    m = re.search(rb',"hash":"([0-9a-f]{64})"\}$', raw)
    if not m:
        raise ValueError('line does not end with its hash')
    body = raw[:m.start()] + b'}'
    got = hashlib.sha256(body).hexdigest()
    if got != m.group(1).decode():
        raise ValueError(f'hash differs: line says {m.group(1).decode()}, content gives {got}')
    return got, json.loads(body)['prev']


def load_host(path):
    """(records, chain error or None) of one sample file; records stop at the first broken link."""
    records, prev = [], '0' * 64
    for n, raw in enumerate(Path(path).read_bytes().splitlines(), 1):
        if not raw.strip():
            continue
        try:
            h, p = verify_line(raw)
        except ValueError as e:
            return records, f'line {n}: {e}'
        if p != prev:
            return records, f'line {n}: chain broken'
        prev = h
        records.append(json.loads(raw))
    return records, None


def load_sample_set(directory):
    """The sample set as one dict, or raise FileNotFoundError(NO_SAMPLE_SET)."""
    d = Path(directory) if directory else None
    if d is None or not (d / 'sampleset.json').is_file():
        raise FileNotFoundError(NO_SAMPLE_SET)
    doc = json.loads((d / 'sampleset.json').read_text())
    if doc.get('schema') != SCHEMA:
        raise ValueError(f'sampleset.json schema is {doc.get("schema")!r}, not {SCHEMA}')
    hosts, chain = {}, {}
    for host, rel in sorted((doc.get('hosts') or {}).items()):
        records, err = load_host(d / rel)
        hosts[host] = records
        if err:
            chain[host] = err
    actions = []
    if doc.get('actions') and (d / doc['actions']).is_file():
        actions = [json.loads(line) for line in (d / doc['actions']).read_text().splitlines() if line.strip()]
    quiesce = {}
    for point, rel in (doc.get('quiesce') or {}).items():
        quiesce[point] = json.loads((d / rel).read_text()) if (d / rel).is_file() else None
    return {'hosts': hosts, 'chain_errors': chain, 'actions': actions, 'quiesce': quiesce,
            'settings': dict(doc.get('settings') or {}), 'inputs': dict(doc.get('inputs') or {}),
            'declared_quiesce': sorted((doc.get('quiesce') or {}).keys())}


# ------------------------------------------------------------------ series access

def series_value(series, name):
    """A metric's value from one scrape: the plain series, or the sum over its label sets; None when absent."""
    if series is None:
        return None
    if name in series:
        return series[name]
    prefix = name + '{'
    vals = [v for k, v in series.items() if k.startswith(prefix)]
    return sum(vals) if vals else None


def metric(svc, name):
    """A service sample's metric value, or None (no scrape, a failed scrape, or no such series)."""
    m = (svc or {}).get('metrics')
    if not m or m.get('error') or m.get('code') != 200:
        return None
    return series_value(m.get('series'), name)


def down(svc):
    """True when the host says the service is not running (a supervisor read that failed says nothing)."""
    sup = (svc or {}).get('supervisor') or {}
    state = str(sup.get('state') or '').split('/')[0]
    return bool(state) and state not in {'running', 'active', 'unknown'}


def life(svc):
    """(pid, start ticks) while the host says the process lives (supervisor running and the pid alive), else None."""
    if not svc:
        return None
    sup, proc = svc.get('supervisor') or {}, svc.get('proc') or {}
    state = str(sup.get('state') or '')
    running = state.split('/')[0] in {'running', 'active'}
    if not running or not proc.get('alive') or not sup.get('pid'):
        return None
    return (sup['pid'], proc.get('start_ticks'))


class View:
    """The merged samples: a time-ordered list of (ts_ms, host, record) and per-service access."""

    def __init__(self, ss):
        self.ss = ss
        self.settings = dict(SETTINGS, **ss['settings'])
        self.inputs = ss['inputs']
        self.samples = sorted(((r['ts_ms'], h, r) for h, recs in ss['hosts'].items() for r in recs if r.get('type') == 'sample'),
                              key=lambda t: t[0])
        self.starts = {h: [r for r in recs if r.get('type') == 'start'] for h, recs in ss['hosts'].items()}
        self.services = {}      # service -> (host, kind)
        for ts, host, r in self.samples:
            for name, svc in (r.get('services') or {}).items():
                self.services.setdefault(name, (host, svc.get('kind')))
        self.config = {}
        for h, starts in self.starts.items():
            if starts:
                self.config[h] = starts[-1].get('config') or {}
        self.clk = {h: (starts[-1].get('clk_tck') if starts else None) or 100 for h, starts in self.starts.items()}

    def of_kind(self, kind):
        return sorted(n for n, (_, k) in self.services.items() if k == kind)

    def host_samples(self, host):
        cache = self.__dict__.setdefault('_host_cache', {})
        if host not in cache:
            cache[host] = [(ts, r) for ts, h, r in self.samples if h == host]
        return cache[host]

    def track(self, name):
        """[(ts, service sample)] of one service, from its host's samples."""
        cache = self.__dict__.setdefault('_track_cache', {})
        if name not in cache:
            host = self.services[name][0]
            cache[name] = [(ts, (r.get('services') or {}).get(name)) for ts, r in self.host_samples(host)]
        return cache[name]

    def at(self, ts, name):
        """The service's sample at or before ts (the latest one), or None."""
        track = self.track(name)
        times = self.__dict__.setdefault('_times_cache', {}).setdefault(name, [t for t, _ in track])
        i = bisect.bisect_right(times, ts)
        return track[i - 1][1] if i else None

    def actions(self, service, kinds, start, end):
        for a in self.ss['actions']:
            if a.get('service') not in (service, '*') or a.get('action') not in kinds:
                continue
            lo, hi = a.get('ts_ms', 0), a.get('until_ms', a.get('ts_ms', 0))
            if lo <= end and hi >= start:
                yield a

    def window_actions(self, kinds, ts, service='*'):
        """True when an action of these kinds covers ts (an action without until_ms covers one sample period)."""
        period = self.period_ms()
        for a in self.ss['actions']:
            if a.get('action') not in kinds or a.get('service') not in (service, '*'):
                continue
            lo = a.get('ts_ms', 0)
            hi = a.get('until_ms', lo + period)
            if lo - period <= ts <= hi + period:
                return True
        return False

    def period_ms(self):
        for starts in self.starts.values():
            if starts:
                return int((starts[-1].get('settings') or {}).get('OBS_SAMPLE_S', 60)) * 1000
        return 60000


# ------------------------------------------------------------------ the lines

def v1(view, line):
    s = view.settings
    if view.ss['chain_errors']:
        for host, err in view.ss['chain_errors'].items():
            line.gap(f'sample chain broken: {host} {err}')
    if not view.ss['hosts']:
        line.gap(NO_SAMPLE_SET)
    for host in view.ss['hosts']:
        times = [ts for ts, _ in view.host_samples(host)]
        if len(times) < 2:
            line.gap(f'samples incomplete: {host} has {len(times)} samples')
            continue
        worst = max(b - a for a, b in zip(times, times[1:]))
        if worst > s['OBS_MAX_GAP_S'] * 1000:
            line.gap(V1_GAP.format(round(worst / 1000)))
        span = (times[-1] - times[0]) / 1000
        if span < s['OBS_WINDOW_S']:
            line.gap(f'samples incomplete: window {round(span)} s of {s["OBS_WINDOW_S"]} s')
        line.notes.append(f'{host}: {len(times)} samples over {round(span)} s, largest gap {round(worst / 1000)} s')


def v2(view, line):
    period = view.period_ms()
    for name in sorted(view.services):
        track = view.track(name)
        prev, seen_ts, new_lives, unexplained = None, None, 0, 0
        for ts, svc in track:
            cur = life(svc)
            if cur is None:
                continue
            if prev is not None and cur != prev:
                new_lives += 1
                if not any(view.actions(name, {'restart', 'start', 'stop'}, seen_ts - period, ts + period)):
                    unexplained += 1
            prev, seen_ts = cur, ts
        if unexplained > view.settings['OBS_MAX_RESTARTS']:
            line.fail(TEXT['V2'].format(name, unexplained))
        if track and down(track[-1][1]) and not any(view.actions(name, {'stop'}, track[0][0], track[-1][0] + period)):
            line.fail(f'service down at the end: {name}')
        if new_lives:
            line.notes.append(f'{name}: {new_lives} new lives, {unexplained} unexplained')


def _input_value(view, ts, name, rule):
    """The summed input signal of one service at ts, a tuple of the parts (None for an unreadable part)."""
    parts = []
    for how, series, kind in rule['input']:
        if how == 'always':
            parts.append(ts)
            continue
        if how == 'self':
            parts.append(metric(view.at(ts, name), series))
            continue
        others = [n for n in view.of_kind(kind) if not (how == 'max_other' and n == name)]
        vals = [metric(view.at(ts, n), series) for n in others]
        vals = [v for v in vals if v is not None]
        parts.append(None if not vals else (sum(vals) if how == 'sum' else max(vals)))
    return parts


def _work(svc, rule, stall_ms):
    """{counter: value or None}; an age gauge maps to 'fresh' (under the stall bound) or 'old'."""
    out = {}
    for w in rule['work']:
        if w.startswith('age:'):
            v = metric(svc, w[4:])
            out[w[4:]] = None if v is None else ('fresh' if v < stall_ms else 'old')
        else:
            out[w] = metric(svc, w)
    return out


def _paused(view, name, ts):
    return view.window_actions({'pause', 'stop', 'restart'}, ts, name)


def v3(view, line):
    stall = view.settings['OBS_STALL_S'] * 1000
    for name in sorted(view.services):
        kind = view.services[name][1]
        rule = view.kinds.get(kind)
        if rule is None:
            line.gap(f'no work counter for {kind}')
            continue
        last_work = {}
        last_input = None
        pending = None          # (ts the input moved first since the last work, reads seen, readable reads)
        cur_life = None
        flagged = False
        last_while = None
        last_standby = None
        for ts, svc in view.track(name):
            lf = life(svc)
            if lf is None or lf != cur_life:
                cur_life, pending, last_work = lf, None, {}
                last_input = _input_value(view, ts, name, rule)
                if lf is None:
                    continue
            if rule.get('work_from'):
                how, of = rule['work_from']
                vals = [metric(view.at(ts, n), rule['work'][0]) for n in view.of_kind(of)]
                vals = [v for v in vals if v is not None]
                work = {rule['work'][0]: max(vals) if vals else None}
            else:
                work = _work(svc, rule, stall)
            moved = False
            readable = False
            for k, v in work.items():
                if v is None:
                    continue
                readable = True
                if v == 'fresh':
                    moved = True
                elif v != 'old' and k in last_work and v > last_work[k]:
                    moved = True
                if v not in ('fresh', 'old'):
                    last_work[k] = v
            if rule.get('while'):
                w = metric(svc, rule['while'])
                last_while = w if w is not None else last_while
            if rule.get('standby'):
                sb = metric(svc, rule['standby'])
                last_standby = sb if sb is not None else last_standby
            inp = _input_value(view, ts, name, rule)
            input_moved = any(a is not None and b is not None and a != b for a, b in zip(inp, last_input or []))
            if rule['input'][0][0] == 'always':
                input_moved = not _paused(view, name, ts)
            last_input = [a if a is not None else b for a, b in zip(inp, last_input or inp)]
            applies = (not rule.get('while') or (last_while or 0) > 0) and \
                      (not rule.get('standby') or last_standby is None or last_standby > 0)
            if moved or not applies:
                pending = None
                continue
            if input_moved and pending is None:
                pending = [ts, 0, 0]
            if pending is not None:
                pending[1] += 1
                pending[2] += 1 if readable else 0
                if ts - pending[0] >= stall and not flagged:
                    flagged = True
                    if pending[2] == 0 and view.unreadable_as_gap:
                        line.gap(f'samples missing: {name}')       # the planted mistake of a control build only
                    elif pending[2] == 0:
                        line.fail(TEXT['V3_dark'].format(name))
                    else:
                        line.fail(TEXT['V3_stall'].format(name, rule['work'][0].removeprefix('age:')))


def v4(view, line):
    for cluster, (kind, series) in ROLE.items():
        members = view.of_kind(kind)
        if not members:
            line.gap(f'no {kind} sampled: {cluster} leader not judged')
            continue
        bad = 0
        for ts, host, r in view.samples:
            roles = [metric((r.get('services') or {}).get(m), series) for m in members if m in (r.get('services') or {})]
            if not roles:
                continue
            leaders = sum(1 for v in roles if v == LEADER_ROLE)
            if leaders != 1:
                bad += 1
        if bad:
            line.fail(TEXT['V4'].format(cluster))
            line.notes.append(f'{cluster}: {bad} samples without exactly one leader')


def v5(view, line):
    s = view.settings
    for name in sorted(view.services):
        kind = view.services[name][1]
        rule = view.kinds.get(kind)
        if rule is None or kind in s['OBS_SPIN_EXEMPT']:
            continue
        host = view.services[name][0]
        clk = view.clk.get(host, 100)
        spin_since, prev = None, None
        for ts, svc in view.track(name):
            lf = life(svc)
            cpu = ((svc or {}).get('proc') or {}).get('cpu_ticks')
            work = _work(svc, rule, s['OBS_STALL_S'] * 1000)
            if cpu is None:
                # no CPU reading (the process died or was unreadable between two samples): the run of spin evidence
                # ends here, and this sample is never the base of a CPU share
                prev, spin_since = None, None
                continue
            if prev is None or lf is None or lf != prev[1]:
                prev, spin_since = (ts, lf, cpu, work), None
                continue
            dt = (ts - prev[0]) / 1000
            share = (cpu - prev[2]) / clk / dt * 100 if dt > 0 else 0
            moved = any(v == 'fresh' or (v is not None and v != 'old' and prev[3].get(k) not in (None, 'fresh', 'old')
                                         and v > prev[3][k]) for k, v in work.items())
            if share > s['OBS_SPIN_CPU_PCT'] and not moved:
                spin_since = spin_since or prev[0]
                if ts - spin_since >= s['OBS_SPIN_S'] * 1000:
                    line.fail(TEXT['V5'].format(name))
            else:
                spin_since = None
            prev = (ts, lf, cpu, {k: (v if v is not None else prev[3].get(k)) for k, v in work.items()})


def absent(view, line, text):
    """A finding that something did not happen in the window: a FAIL over a complete sample set, else not judged."""
    if view.complete:
        line.fail(text)
    else:
        line.gap(f'not judged on an incomplete sample set: {text}')


def v6(view, line):
    s = view.settings
    bound = s['OBS_SNAPSHOT_AGE_S']
    if bound is None and s['OBS_SNAPSHOT_INTERVAL_S'] is not None:
        bound = 3 * s['OBS_SNAPSHOT_INTERVAL_S']
    if bound is None:
        line.gap('snapshot age not judged: neither OBS_SNAPSHOT_AGE_S nor OBS_SNAPSHOT_INTERVAL_S is set')
    for kind, series in SNAPSHOT_AGE.items():
        for m in view.of_kind(kind):
            seen, overdue = 0, False
            life_start, cur = None, None
            for ts, svc in view.track(m):
                v = metric(svc, series)
                lf = life(svc)
                if lf != cur:
                    cur, life_start = lf, ts
                if lf is None:
                    continue
                if v is None:
                    continue
                seen += 1
                # -1 = no snapshot yet in this life: its age is the life's age in the window
                age = (ts - life_start) / 1000 if v < 0 else v
                if bound is not None and age > bound:
                    overdue = True
            if not seen:
                line.gap(f'snapshot age not read: {m}')
            elif overdue:
                line.fail(TEXT['V6_age'].format(m))
    window_s = (view.samples[-1][0] - view.samples[0][0]) / 1000 if view.samples else 0
    for m in view.of_kind('ME member'):
        vals = [v for v in (metric(svc, ME_RECLAIM) for _, svc in view.track(m)) if v is not None]
        if not vals:
            line.gap(f'reclaim counter not read: {m}')
        elif max(vals) <= vals[0] and window_s < s['OBS_RECLAIM_MIN_WINDOW_S']:
            prunes = [v for v in (metric(svc, 'match_log_prunes_total') for _, svc in view.track(m)) if v is not None]
            line.notes.append(f'{m}: no reclaim in a {round(window_s)} s window, shorter than OBS_RECLAIM_MIN_WINDOW_S '
                              f'{s["OBS_RECLAIM_MIN_WINDOW_S"]} s: not judged (match_log_prunes_total '
                              f'{prunes[0] if prunes else None} -> {prunes[-1] if prunes else None})')
        elif max(vals) <= vals[0]:
            absent(view, line, TEXT['V6_reclaim'].format(m))
    mode = view.inputs.get('snapshot_mode')
    if mode == 'full':
        line.notes.append('core half N/A: full snapshot mode has no core purge metric')
    elif mode == 'shadow':
        holders = [m for m in view.of_kind('core member') + view.of_kind('core-replica')
                   if any(metric(svc, CORE_PURGE) is not None for _, svc in view.track(m))]
        if not holders:
            line.gap(f'core purge position ({CORE_PURGE}) not read on any member')
        for m in holders:
            vals = [v for v in (metric(svc, CORE_PURGE) for _, svc in view.track(m)) if v is not None]
            if max(vals) <= vals[0]:
                absent(view, line, TEXT['V6_reclaim'].format(m))
    else:
        line.gap('core snapshot half neither judged nor N/A: input snapshot_mode is not shadow or full')


def _dir_series(view, host, name):
    return [(ts, ((r.get('dirs') or {}).get(name) or {})) for ts, r in view.host_samples(host)]


def _first_last(points):
    pts = [(ts, v) for ts, v in points if v is not None]
    return (pts[0], pts[-1]) if len(pts) >= 2 else (None, None)


def _service_delta(view, name, series):
    a, b = _first_last([(ts, metric(svc, series)) for ts, svc in view.track(name)])
    return None if a is None else b[1] - a[1]


def _pg_values(view, host, key):
    return [(ts, ((r.get('pg') or {}).get('values') or {}).get(key)) for ts, r in view.host_samples(host)]


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def disk_model(view, host, d, growth_bytes, hours):
    """(allowed growth in bytes, explanation) of one directory, or (None, reason) when the model cannot be computed."""
    s, model = view.settings, d['model']
    svc = d.get('service')

    def need(series, who=svc):
        if not who or who not in view.services:
            return None
        return _service_delta(view, who, series)

    if model == 'core_order_journal':
        n = need('core_order_journal_seq')
        return (None, 'no core_order_journal_seq') if n is None else (n * s['OBS_CORE_JOURNAL_EVENT_B'], f'{n} events')
    if model in ('core_log', 'replica_archive'):
        who = d.get('follows') if model == 'replica_archive' else svc
        n = need('core_log_position', who)
        if n is None:
            return None, 'no core_log_position'
        idle = s['OBS_IDLE_LOG_B_S'] * hours * 3600
        return n + idle, f'log position +{n}, idle term {int(idle)}'
    if model == 'me_log':
        n = need('match_log_position')
        if n is None:
            slope = s['OBS_ME_LOG_SLOPE_MB_H'] * MB * hours
            return slope, 'no match_log_position: slope OBS_ME_LOG_SLOPE_MB_H (a match build before the gauge)'
        r = need(ME_RECLAIM) or 0
        return n - r, f'log position +{n}, reclaimed {r}'
    if model == 'me_settlement_journal':
        n = need('match_engine_next_journal_seq')
        if n is None:
            return None, 'no match_engine_next_journal_seq'
        return n * s['OBS_ME_JOURNAL_RECORD_B'], f'{n} records (driver mode {view.inputs.get("me_driver_mode", "unrecorded")})'
    if model in ('money_db', 'order_db', 'market_db'):
        rows_key, size_key = d.get('rows'), d.get('size')
        if not rows_key or not size_key:
            return None, f'{model} needs rows and size query names'
        a, b = _first_last([(ts, _int(v)) for ts, v in _pg_values(view, host, rows_key)])
        sa, sb = _first_last([(ts, _int(v)) for ts, v in _pg_values(view, host, size_key)])
        if a is None or sb is None:
            return None, f'{rows_key} or {size_key} not read'
        per_row = sb[1] / b[1] if b[1] else 0
        return (b[1] - a[1]) * per_row, f'{b[1] - a[1]} rows x {int(per_row)} B'
    if model in ('pg_wal', 'log_dir', 'slope'):
        key = {'pg_wal': 'OBS_WAL_SLOPE_MB_H', 'log_dir': 'OBS_LOG_SLOPE_MB_H'}.get(model)
        mbh = s[key] if key else d.get('slope_mb_h')
        if mbh is None:
            return None, 'no slope setting'
        return mbh * MB * hours, f'slope {mbh} MB/h'
    if model == 'sampler_file':
        recs = view.host_samples(host)
        selfs = [(ts, (r.get('self') or {}).get('file_bytes')) for ts, r in recs]
        a, b = _first_last(selfs)
        if a is None:
            return None, 'no self size'
        return b[1] - a[1], f'{len(recs)} samples'
    return None, f'unknown model {model}'


def v7(view, line):
    s = view.settings
    slack = s['OBS_GROWTH_SLACK_MB'] * MB
    for host, cfg in sorted(view.config.items()):
        recs = view.host_samples(host)
        if len(recs) < 2:
            continue
        hours = (recs[-1][0] - recs[0][0]) / 3.6e6
        for d in cfg.get('dirs') or []:
            if d['model'] == 'pg_wal':
                pts = [(ts, (r.get('pg') or {}).get('wal_bytes')) for ts, r in recs]
            elif d['model'] in ('money_db', 'order_db', 'market_db'):
                pts = [(ts, ((r.get('pg') or {}).get('sizes') or {}).get(d.get('db'))) for ts, r in recs]
            else:
                pts = [(ts, v.get('bytes') if not v.get('missing') and v.get('error') is None else None)
                       for ts, v in _dir_series(view, host, d['name'])]
            a, b = _first_last(pts)
            if a is None:
                line.gap(f'disk growth not read: {d["name"]}')
                continue
            growth = b[1] - a[1]
            if d['model'] == 'log_dir':
                growth = sum(max(0, y[1] - x[1]) for x, y in zip(pts, pts[1:]) if x[1] is not None and y[1] is not None)
            allowed, why = disk_model(view, host, d, growth, hours)
            if allowed is None:
                line.gap(f'disk model not computable: {d["name"]} ({why})')
                continue
            limit = max(allowed, 0) * (1 + s['OBS_GROWTH_TOL_PCT'] / 100) + slack
            line.notes.append(f'{d["name"]}: grew {growth} B, model {int(allowed)} B ({why})')
            if growth > limit:
                line.fail(TEXT['V7'].format(d['name'], growth))
        for vol in cfg.get('volumes') or []:
            pts = [(ts, ((r.get('volumes') or {}).get(vol) or {})) for ts, r in recs]
            pts = [(ts, v) for ts, v in pts if v.get('used') is not None]
            if len(pts) >= 2 and hours > 0:
                slope = (pts[-1][1]['used'] - pts[0][1]['used']) / hours
                avail = pts[-1][1].get('avail', 0)
                days = round(avail / slope / 24, 1) if slope > 0 else None
                line.notes.append(f'volume {vol}: {int(slope)} B/h, projected days to full {days}')


def v8(view, line):
    s = view.settings
    for host in sorted(view.ss['hosts']):
        recs = view.host_samples(host)
        if len(recs) < 2:
            continue
        mounts = sorted({p for _, r in recs for p in (r.get('shm') or {})})
        for mount in mounts:
            used = [((r.get('shm') or {}).get(mount) or {}).get('used') for _, r in recs]
            used = [u for u in used if u is not None]
            if len(used) >= 2:
                if used[-1] > used[0] + s['OBS_SHM_SLACK_MB'] * MB:
                    line.fail(TEXT['V8_base'])
                line.notes.append(f'{host} {mount}: first {used[0]} B, last {used[-1]} B, max {max(used)} B')
            last = ((recs[-1][1].get('shm') or {}).get(mount) or {}).get('entries') or {}
            for name in sorted(last):
                if any(fnmatch.fnmatch(name, p) for p in TOOL_DRIVER_DIRS):
                    line.fail(TEXT['V8_dir'].format(name))


def _residuals(result):
    """The residual-hold findings of one money-check --json document (core mode lists them in residual_holds)."""
    return [(r.get('userId'), r.get('assetId'), r.get('actual', r.get('remaining')))
            for r in (result or {}).get('residual_holds') or []]


def v9(view, line):
    s = view.settings
    for point in ('Q0', 'Q2'):
        doc = view.ss['quiesce'].get(point)
        if doc is None:
            line.gap(f'no quiesce result: {point}')
            continue
        for u, a, amount in _residuals(doc):
            line.fail(TEXT['V9'].format(u, a, amount))
        if doc.get('violated') and not _residuals(doc):
            line.fail(f'money check violated at {point}: ' + ', '.join(c['name'] for c in doc.get('checks', [])
                                                                       if c.get('status') == 'FAIL'))
        if doc.get('status') in ('UNSTABLE', 'ERROR', 'INDETERMINATE') or doc.get('indeterminate'):
            line.gap(f'money check not exact at {point}: {doc.get("status") or "indeterminate"}')
        if s['OBS_ZERO_HOLD_USERS'] and doc.get('status') not in ('UNSTABLE', 'ERROR'):
            want = sorted(list(r) for r in s['OBS_ZERO_HOLD_USERS'])
            zero = [c for c in doc.get('checks') or [] if c.get('name') == 'zero_holds']
            if not zero:
                line.gap(f'zero-hold check missing at {point}: OBS_ZERO_HOLD_USERS is set and the money check ran '
                         f'without --zero-hold-users')
            elif sorted(list(r) for r in zero[0].get('users') or []) != want:
                line.gap(f'zero-hold check at {point} ran over other users: {zero[0].get("users")}, '
                         f'OBS_ZERO_HOLD_USERS is {want}')
            elif zero[0].get('status') not in ('PASS', 'FAIL'):     # a FAIL is in the residual holds above
                line.gap(f'zero-hold check not judged at {point}: {zero[0].get("status")}')
    stall = s['OBS_STALL_S'] * 1000
    for m in view.of_kind('core member'):
        since = None
        for ts, svc in view.track(m):
            v = metric(svc, RELEASE_BACKLOG)
            if v is None:
                continue
            if v > 0:
                since = since or ts
                if ts - since > stall:
                    line.fail(f'release backlog not drained: {m}')
            else:
                since = None


def v10(view, line):
    worst = 0
    for m in view.of_kind('core member'):
        vals = [v for v in (metric(svc, SCHEMA_REJECTS) for _, svc in view.track(m)) if v is not None]
        if not vals:
            line.gap(f'schema reject counter not read: {m}')
        else:
            worst = max(worst, max(vals))
    if worst > 0:
        line.fail(TEXT['V10'].format(int(worst)))


def v11(view, line):
    seen = False
    for m in view.of_kind('core member'):
        for ts, svc in view.track(m):
            v = metric(svc, GATE)
            # the gate is replicated state: the leader's view is the gate (a restarted follower still replaying shows an
            # older one)
            if v is None or metric(svc, ROLE['core'][1]) != LEADER_ROLE:
                continue
            seen = True
            if v != GATE_OPEN and not view.window_actions({'gate'}, ts):
                line.fail(TEXT['V11'])
    if not seen and view.of_kind('core member'):
        line.gap('order-entry gate not read')
    for b in view.of_kind('ct-bridge'):
        for ts, svc in view.track(b):
            if metric(svc, BRIDGE_HALTED):
                line.fail(f'bridge halted: {b}')
                break


def v12(view, line):
    s = view.settings
    for kind, (series, key) in HISTORY_AGE.items():
        for n in view.of_kind(kind):
            known = False
            for ts, svc in view.track(n):
                v = metric(svc, series)
                if v is None or life(svc) is None:
                    continue
                # -1 is "no heartbeat yet": unknown before the first answer, stale after one
                known = known or v >= 0
                if not known:
                    continue
                if (v < 0 or v > s[key]) and not view.window_actions({'history'}, ts):
                    line.fail(TEXT['V12'])
                    line.notes.append(f'{n}: {series} {v} at {ts}')
                    break


JUDGES = {'V1': v1, 'V2': v2, 'V3': v3, 'V4': v4, 'V5': v5, 'V6': v6, 'V7': v7, 'V8': v8, 'V9': v9, 'V10': v10,
          'V11': v11, 'V12': v12}


def side_print(view):
    """What the verdict prints next to the lines: each service's last /health and /ready, the OMS-named lane series."""
    out = {'services': {}, 'oms_lane': {}, 'oms_lane_note': OMS_LANE_NOTE}
    for name in sorted(view.services):
        track = view.track(name)
        ready_true = sum(1 for _, svc in track if ((svc or {}).get('ready') or {}).get('code') == 200)
        last = track[-1][1] if track else None
        out['services'][name] = {'kind': view.services[name][1], 'ready_200_samples': ready_true, 'samples': len(track),
                                 'last_health': ((last or {}).get('health') or {}).get('code'),
                                 'last_ready': ((last or {}).get('ready') or {}).get('code')}
    for m in view.of_kind('ME member'):
        out['oms_lane'][m] = {k: [v for v in (metric(svc, k) for _, svc in view.track(m)) if v is not None][-1:] for k in OMS_LANE}
    return out


def judge(ss, disabled=(), kinds=None, unreadable_as_gap=False):
    """The verdict over a loaded sample set: {status, lines, failures, inconclusive, side}. ``disabled`` switches lines
    off (the vacuity controls of the unit sets); ``kinds`` replaces the V3 table and ``unreadable_as_gap`` reads an
    unreadable counter as a missing sample: both exist only to build the control verdicts of the drill."""
    view = View(ss)
    view.kinds = KINDS if kinds is None else kinds
    view.unreadable_as_gap = unreadable_as_gap
    first = Line('V1')
    v1(view, first)
    # A line that fails on an absence (no reclaim in the window) is judged only over a complete set
    view.complete = not first.gaps
    lines = []
    for name in LINES:
        line = Line(name)
        if name in disabled:
            line.na = 'disabled'
        else:
            JUDGES[name](view, line)
        lines.append(line)
    failures = [f'{l.name} {t}' for l in lines for t in l.fails]
    gaps = [f'{l.name} {t}' for l in lines for t in l.gaps]
    status = 'FAIL' if failures else 'INCONCLUSIVE' if gaps else 'PASS'
    side = side_print(view)
    # A /ready that was true on a failing service is named
    named = []
    for f in failures:
        for svc, info in side['services'].items():
            if f.endswith(' ' + svc) or f' {svc} ' in f + ' ':
                if info['ready_200_samples']:
                    named.append(f'{svc} answered /ready 200 in {info["ready_200_samples"]} samples')
    side['ready_on_failing'] = sorted(set(named))
    return {'status': status, 'lines': [l.doc() for l in lines], 'failures': failures, 'inconclusive': gaps, 'side': side,
            'settings': view.settings, 'inputs': view.inputs}


def judge_directory(directory, disabled=()):
    try:
        ss = load_sample_set(directory)
    except FileNotFoundError:
        return {'status': 'INCONCLUSIVE', 'failures': [], 'inconclusive': [NO_SAMPLE_SET], 'lines': []}
    return judge(ss, disabled)


def failing_line(verdict, line, text_prefix):
    """True when ``line`` failed (or, for V1, ended inconclusive) with a text starting with text_prefix."""
    for doc in verdict['lines']:
        if doc['line'] == line:
            texts = doc.get('fail', []) + (doc.get('inconclusive', []) if line == 'V1' else [])
            return any(t.startswith(text_prefix) for t in texts)
    return False


# The two control builds of the frozen-bridge run: V3 judges the bridge by the core's log position, or reads an
# unreadable counter as a missing sample. Each must change the run's outcome, with these texts.
BRIDGE_BY_CORE_POSITION = dict(KINDS, **{'ct-bridge': {'work': ['core_log_position'],
                                                      'work_from': ('max', 'core member'),
                                                      'input': [('max', 'match_engine_next_journal_seq', 'ME member')]}})
CONTROL_BRIDGE_VACUOUS = 'verdict line V3 is vacuous for ct-bridge'
CONTROL_READ_AS_GAP = 'frozen process read as a gap'


# ------------------------------------------------------------------ runner entry: demo-observation-24h

SCENARIO = 'demo-observation-24h'


def scenario(sample_set_dir, out_dir):
    """runner.py entry: the verdict over the sample set named by --manifest (its sampleset.json or its directory)."""
    p = Path(sample_set_dir) if sample_set_dir else None
    if p is not None and p.is_file():
        p = p.parent
    verdict = judge_directory(p)
    Path(out_dir, 'verdict.json').write_text(json.dumps(verdict, indent=1) + '\n')
    lines = [{'line': d['line'], 'status': d['status']} for d in verdict['lines']]
    result = {'status': verdict['status'], 'lines': lines, 'assertions': len(lines), 'processed': 1, 'skipped': 0,
              'child_exit_codes': [0], 'scope': f'{SCENARIO} over {p}'}
    if verdict['status'] != 'PASS':
        result['error'] = '; '.join(verdict['failures'] or verdict['inconclusive'])
    return result
