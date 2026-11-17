# SPDX-License-Identifier: Apache-2.0
"""The history projection drills: scenario ids, their dry runs on the projection stand-in, and the evidence they write.

Three scenario ids are registered and dispatched by runner.py on a core manifest that declares the projection roles
(``pj0``, ``pj1``; a projection kind of ``core_contracts.GATEWAY_KINDS``):

* ``projector-me-restart-follow``: under crossing order flow on both gateways, with pj0 writing, a standby copy of it in
  pj1 and the money projector running: (a) kill -9 the ME leader and restart it; (b) kill -9 the core member pj0 is
  attached to and restart it; (c) kill the core leader; (d) SIGKILL pj0 (the standby takes over), restart it; (e) stop
  the attached core member for longer than the source-behind window; (f) SIGKILL the money projector and restart it.
  After each fault the projection reaches the core's head; the projection equals the fixture's oracle; the money oracle
  is exact; after (d) and (f) every core member's replay count is back at its baseline.
* ``projection-byte-equal-replay``: the same flow without (e); pj1 starts on an empty database with a backlog and its
  attached member is killed during the catch-up (C'); then the flow stops and the head is recorded. A = pj0's database,
  B = pj1's, C = pj1 again into an empty database, killed and restarted twice on the way. The canonical dumps of A, B and
  C (projection_dump.py, SHA-256) are equal, the events are dense from 1 to the head, two fills per trade, and the maker
  flag of every fill agrees with the ME journal's taker order.
* ``history-freshness``: pj0 alone. (a) steady flow; (b) SIGSTOP pj0, place and cancel an order, read history and the
  closed order through gw0; (c) SIGCONT; (d) cut the attached core member from the cluster; (e) kill the core leader;
  (f) stop PostgreSQL for a moment; (g) slow the attached member (a random UDP drop on its traffic to pj0, SLOW_DROP_PERCENT;
  the step holds only when pj0's mean probe time per poll reaches SLOW_WITNESS_PERCENT of a baseline taken just before,
  or a probe goes unanswered: Aeron's retransmission hides a modest drop).

Only the dry runs exist yet: on a kind whose pj0 runs ``projector_stub`` (projector_stub.py, the test-only stand-in). On
any other kind the scenario is refused before a container starts (exit non-zero): the drill on the projector binary is
not implemented. A dry run proves the story sizes, the kill windows, the oracle comparison against PostgreSQL, the dump
and hash step, the ``sources.json`` writer, the replay-count probe and its baseline, the member cut and the slow-member
method, and the freeze bound. A line the stand-in or the cut's binaries cannot meet yet is marked ``awaits`` with what
it waits for; it is recorded with its text and does not decide a dry run. Every other line does.

Every step writes the evidence of its precondition to ``sources.json``: before and after the fault, each projection
slot's attached source (for the stand-in: the core leader it followed at its last poll), its archive id and switch
count from its own ``/health``, the recordings it walked, and the probe log. A step whose precondition that record does
not show is INCONCLUSIVE.

Every size, bound and wait is a setting (``SETTINGS``, overridden by an environment variable of the same name), recorded
with the run.
"""
import json
import os
from pathlib import Path
import random
import subprocess
import time
import uuid

from contracts import FP, Inconclusive, Violation
import core_contracts
import core_drills
import gateway_probe
import gateway_scenarios
from gateway_scenarios import GatewayDrill, attempts_as_requests, cancels_from, creates_from, line
import projection_dump

SCENARIOS = ('projector-me-restart-follow', 'projection-byte-equal-replay', 'history-freshness')
# The control texts of the drills' controls (the contract's table); a control run passes only when its line fails with
# this text. The stand-in's beat-always mode is the freshness drill's dry-run control.
CONTROL_TEXT = {
    'projector-me-restart-follow': 'projector did not follow the successor recording',
    'projection-byte-equal-replay': 'projection dump differs',
    'history-freshness': 'stale history served as fresh',
}
ORPHAN_TEXT = 'orphan replay remains on core member'
MISSING_TEXT = 'journalSeq missing in projection'
STALE_LABEL_TEXT = 'stale label missing'
SETTINGS = {
    # the flow: crossing LIMIT pairs on market 1 across gw0 and gw1
    'PROJECTION_USERS': 8, 'PROJECTION_REQUESTS': 1200, 'PROJECTION_RATE': 5, 'PROJECTION_CONCURRENCY': 4,
    'PROJECTION_TAP_S': 3600, 'PROJECTION_LOAD_BOUND_S': 1200,
    # functional drill bounds (never limits of a binary; the measured times are recorded as data)
    'PROJECTOR_CATCHUP_BOUND_S': 60, 'PROJECTOR_TAKEOVER_BOUND_S': 21, 'HISTORY_PROJECTOR_ORPHAN_BOUND_MS': 30000,
    'HISTORY_FRESH_AGE_BOUND_MS': 3000, 'HISTORY_STALE_MS': 5000, 'HISTORY_PROBE_MS': 1000,
    # the projector's source-behind window; (e) holds the attached member down for this plus the margin
    'SOURCE_BEHIND_MS': 5000, 'SOURCE_BEHIND_MARGIN_S': 10,
    # the freshness drill's windows
    'FREEZE_S': 12, 'PG_DOWN_S': 5, 'PARTITION_S': 20, 'MEMBER_REJOIN_BOUND_S': 120, 'SLOW_S': 20, 'SLOW_DROP_PERCENT': 80, 'SLOW_WITNESS_PERCENT': 150, 'SAMPLE_MS': 500,
    # the byte-equal drill: C' starts once the core has emitted this many events, its attached member is killed once
    # the catch-up has applied this many, and C is killed and restarted this many times on its way
    'CPRIME_BACKLOG_EVENTS': 1500, 'CPRIME_KILL_AFTER_EVENTS': 200, 'C_KILLS': 2, 'C_KILL_EVERY_EVENTS': 400,
    'STUB_PAGE_EVENTS': 200,
    'STEP_SETTLE_S': 3, 'POLL_S': 1, 'WATCH_MS': 100, 'ME_RESTART_AFTER_KILL_S': 13,
}
# The money projector's replay stream (core-projector ProjectorConfig.REPLAY_STREAM_ID): the standing reader the replay
# baseline is taken with. The history projector's replay stream joins this list when its binary exists.
MONEY_PROJECTOR_REPLAY_STREAM = 9161
REPLAY_STREAMS = (MONEY_PROJECTOR_REPLAY_STREAM,)
CORE_MEMBERS = ('ae0', 'ae1', 'ae2')
USER_BASE = {'projector-me-restart-follow': 87001, 'projection-byte-equal-replay': 88001, 'history-freshness': 89001}
PAIR_PRICE = 90 * FP
UNIT = FP // 1000


def settings(environ=os.environ):
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
            continue
        if not value.isdigit() or int(value) < 1:
            raise Violation(f'{name} must be a positive integer, got {value!r}')
        out[name] = int(value)
    return out


def is_scenario(name):
    return name in SCENARIOS


def control_of(manifest, name):
    """The control text a projection control kind expects for ``name``, or None. A control kind of another drill is
    refused."""
    spec = core_contracts.GATEWAY_KINDS.get(manifest.get('manifest_kind')) or {}
    control = spec.get('projection_control')
    if control is None:
        return None
    if control != name:
        raise Inconclusive(f'kind {manifest.get("manifest_kind")} is the control of {control}, not of {name}')
    return CONTROL_TEXT[name]


def check_scenario(manifest, name):
    """Before any container starts: an unknown id is refused; a projection scenario needs a manifest that declares the
    projection roles; only the dry run on the stand-in is implemented (any other pj0 artifact is refused, so the
    scenario exits non-zero); a control kind runs only the drill it controls. Returns 'stub'."""
    if not is_scenario(name):
        raise Inconclusive('unknown projection scenario: ' + name)
    if not core_contracts.projection_manifest(manifest):
        raise Inconclusive(f'{name} needs a manifest that declares the projection roles (a projection kind)')
    slots = manifest.get('slot_artifacts') or {}
    if slots.get('pj0') != 'projector_stub' or slots.get('pj1') != 'projector_stub':
        raise Inconclusive(f'{name} on the projector binary is not implemented yet: only the dry run on the stand-in '
                           f'(pj0 and pj1 = projector_stub) runs; this kind stages pj0={slots.get("pj0")}, '
                           f'pj1={slots.get("pj1")}')
    control_of(manifest, name)
    return 'stub'


def scenario(fixture, name, out_dir):
    """runner.py entry for the projection scenario ids."""
    check_scenario(fixture.m, name)
    cls = {'projector-me-restart-follow': MeRestartFollow, 'projection-byte-equal-replay': ByteEqualReplay,
           'history-freshness': HistoryFreshness}[name]
    result = cls(fixture, name, Path(out_dir) / 'drill').run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} dry run on the projection stand-in; the drill on the projector binary is a later slice')


def awaits(holds, detail, text, reason):
    """A line the stand-in or the cut's binaries cannot meet yet: recorded with its text, never deciding a dry run."""
    out = line(holds, detail, text)
    out['awaits'] = reason
    return out


def dry_verdict(lines, control):
    """A control run fails only on the rule it tests: it passes when at least one judged line fails with exactly the
    control text, every judged line that fails has that text, and no judged line is inconclusive; anything else is FAIL.
    Otherwise: INCONCLUSIVE when a judged line's witness is missing, PASS when every judged line holds, else FAIL.
    ``awaits`` lines are listed, not judged."""
    judged = {k: v for k, v in lines.items() if not v.get('awaits')}
    waiting = {k: {'holds': v['holds'], 'text': v.get('text'), 'awaits': v['awaits']} for k, v in lines.items() if v.get('awaits')}
    if control is not None:
        failed = [k for k, v in judged.items() if not v['holds'] and not v.get('inconclusive') and v.get('text') == control]
        other = [k for k, v in judged.items() if not v['holds'] and k not in failed]
        return ('PASS' if failed and not other else 'FAIL'), {
            'control': control, 'failed_lines': failed, 'other_failed_lines': other,
            'observed': {k: v.get('text') for k, v in judged.items() if not v['holds']}}, waiting
    if any(v.get('inconclusive') for v in judged.values()):
        return 'INCONCLUSIVE', None, waiting
    return ('PASS' if all(v['holds'] for v in judged.values()) else 'FAIL'), None, waiting


def stale_bound_s(p):
    """When a frozen projection's heartbeat must read past the stale threshold: HISTORY_STALE_MS plus one probe, plus the
    drill's own sampling step (it sees the age only every SAMPLE_MS)."""
    return (p['HISTORY_STALE_MS'] + p['HISTORY_PROBE_MS'] + p['SAMPLE_MS']) / 1000


def fresh_ages_hold(ages, p):
    """Steady flow: every sampled history answer carries an age at or below HISTORY_FRESH_AGE_BOUND_MS."""
    return bool(ages) and all(a is not None and a <= p['HISTORY_FRESH_AGE_BOUND_MS'] for a in ages)


def slow_witness(baseline, window, p):
    """Whether the slow-member method slowed the projection's reads: the mean probe time per poll inside the window
    against the same mean over a baseline taken just before it (slowed when it reaches SLOW_WITNESS_PERCENT of the
    baseline), or a probe left unanswered inside the window. ``baseline`` and ``window`` are deltas of the projection's
    own counters: {'polls', 'probe_ms', 'unanswered'}. ``slowed`` is None when the baseline has no poll."""
    def mean(d):
        return int(round(d['probe_ms'] / d['polls'])) if d.get('polls') else None
    base, slow = mean(baseline), mean(window)
    out = {'probe_ms_mean': [base, slow], 'polls': [baseline.get('polls'), window.get('polls')],
           'unanswered': [baseline.get('unanswered'), window.get('unanswered')],
           'witness_percent': p['SLOW_WITNESS_PERCENT']}
    if not base:
        out['slowed'] = None
        return out
    out['slowed'] = bool((window.get('unanswered') or 0) > (baseline.get('unanswered') or 0)
                         or (slow is not None and slow * 100 >= base * p['SLOW_WITNESS_PERCENT']))
    return out


def crossing_story(requests, users, seed, unit=UNIT, price=PAIR_PRICE, market=1):
    """The load table: alternating BUY and SELL LIMIT GTC rows at one price between users, so consecutive rows cross and
    trade. Deterministic in ``seed``; the quantity names the row (unique per row), keys are UUIDs."""
    rng = random.Random(seed)
    rows = []
    for i in range(requests):
        key = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        qty = gateway_probe.quantity_of(i, unit)
        body = {'marketId': str(market), 'side': 'BUY' if i % 2 == 0 else 'SELL', 'type': 'LIMIT', 'timeInForce': 'GTC',
                'price': gateway_probe.money(price), 'quantity': gateway_probe.money(qty)}
        rows.append({'i': i, 'key': key, 'user': users[i % len(users)], 'quantity': qty, 'body': body, 'resend': False})
    return rows


# ------------------------------------------------------------------ comparisons (pure)

def final_states(events):
    """order id -> the tap's last event of that order (by sequence)."""
    out = {}
    for e in sorted(events, key=lambda e: e['seq']):
        out[e['order']] = e
    return out


def compare_orders(events, rows):
    """The projection's order rows against the fixture's event oracle: every order the events name is a row, and its
    status, filled, remaining and hold remaining equal the last event's. Returns the differences (at most 20 listed)."""
    want = final_states(events)
    have = {int(r['order_id']): r for r in rows}
    diffs = []
    for order, e in sorted(want.items()):
        r = have.get(order)
        if r is None:
            diffs.append({'order': order, 'missing': True})
            continue
        got = {'status': r['status'], 'filled': int(r['filled_quantity']), 'remaining': int(r['remaining_quantity']),
               'hold_remaining': int(r['hold_remaining'])}
        exp = {'status': e['status'], 'filled': e['filled'], 'remaining': e['remaining'], 'hold_remaining': e['hold_remaining']}
        if got != exp:
            diffs.append({'order': order, 'projection': got, 'oracle': exp})
    extra = sorted(set(have) - set(want))
    return {'orders': len(want), 'rows': len(have), 'differences': len(diffs) + len(extra), 'listed': diffs[:20],
            'extra_rows': extra[:20]}


def compare_fills(events, fills, trades=None):
    """(trade, order) pairs of the events' FILL records with a trade id against the projection's fill rows; every trade
    has two rows; with the ME journal's trades, the maker flag of every row agrees with the trade's maker order."""
    want = {(e['trade'], e['order']) for e in events if e['kind'] == 'FILL' and e['trade'] > 0}
    have = {(int(f['trade_id']), int(f['order_id'])) for f in fills}
    per_trade = {}
    for trade, _ in have:
        per_trade[trade] = per_trade.get(trade, 0) + 1
    not_two = sorted(t for t, n in per_trade.items() if n != 2)
    maker_wrong = []
    if trades is not None:
        makers = {t['trade_id']: t['maker_order'] for t in trades}
        for f in fills:
            trade, order = int(f['trade_id']), int(f['order_id'])
            if trade in makers and (f['maker'] in (True, 't', 'true')) != (order == makers[trade]):
                maker_wrong.append([trade, order])
    return {'oracle_pairs': len(want), 'rows': len(have), 'missing': sorted(want - have)[:20], 'extra': sorted(have - want)[:20],
            'trades': len(per_trade), 'not_two_rows': not_two[:20], 'maker_checked': trades is not None,
            'maker_wrong': maker_wrong[:20], 'equal': want == have and not not_two and not maker_wrong}


def density(seqs, head):
    """The projected sequences against 1..head: (dense, first, last, count, missing sample, above head)."""
    s = sorted(seqs)
    missing = sorted(set(range(1, head + 1)) - set(s))[:20] if head else []
    above = [x for x in s if head is not None and x > head][:20]
    return {'dense': bool(s) and s[0] == 1 and s[-1] == len(s) and not missing, 'first': s[0] if s else None,
            'last': s[-1] if s else None, 'count': len(s), 'head': head, 'missing': missing, 'above_head': above}


def baseline_back(baseline, after):
    """True when every member's replay count on every replay stream is at or below its baseline."""
    for member, b in baseline.items():
        a = after.get(member) or {}
        if 'error' in a or 'error' in b:
            return False
        for stream, n in (b.get('replays') or {}).items():
            if (a.get('replays') or {}).get(stream, 0) > n:
                return False
    return True


def isolation_arguments(manifest, member, action):
    """iptables rules that cut one core member from the other two (UDP both ways, in the member's own namespace); a
    client of the member (a projector, the gateways) keeps its path."""
    if member not in CORE_MEMBERS or action not in ('add', 'delete'):
        raise Violation('a member cut names a core member and add or delete')
    flag = '-A' if action == 'add' else '-D'
    rules = []
    for other in CORE_MEMBERS:
        if other == member:
            continue
        address = manifest['nodes'][other]
        rules.append(['-w', '2', flag, 'INPUT', '-p', 'udp', '-s', address, '-j', 'DROP'])
        rules.append(['-w', '2', flag, 'OUTPUT', '-p', 'udp', '-d', address, '-j', 'DROP'])
    return rules


def slow_arguments(manifest, member, client, action, drop_percent):
    """An iptables rule in ``member``'s namespace that drops a random share of its UDP to ``client`` (the statistic
    match): the member keeps delivering, slower. ``drop_percent`` is a setting (1..99)."""
    if member not in CORE_MEMBERS or action not in ('add', 'delete', 'counters') or not 1 <= drop_percent <= 99:
        raise Violation('a slow-member rule names a core member, add, delete or counters, and a drop percent 1..99')
    if action == 'counters':
        return ['-w', '2', '-L', 'OUTPUT', '-n', '-v', '-x']
    return ['-w', '2', '-A' if action == 'add' else '-D', 'OUTPUT', '-p', 'udp', '-d', manifest['nodes'][client], '-m',
            'statistic', '--mode', 'random', '--probability', f'{drop_percent / 100:.2f}', '-j', 'DROP']


def dropped_packets(listing, client_address):
    """Packets the statistic rule dropped, from ``iptables -L OUTPUT -n -v -x`` output (None when the rule is absent)."""
    for text in (listing or '').splitlines():
        parts = text.split()
        if len(parts) > 8 and parts[2] == 'DROP' and client_address in parts and 'statistic' in parts:
            return int(parts[0])
    return None


# ------------------------------------------------------------------ the drill base

class ProjectionDrill(GatewayDrill):
    """The gateway drill base (fixture boot, the load across gw0 and gw1, the money oracle) plus the projection slots,
    the core's head, the projection's state, sources.json and the replay-count probe."""

    def __init__(self, fixture, name, out_dir):
        super().__init__(fixture, name, out_dir)
        self.p = settings()
        self.control = control_of(fixture.m, name)
        self.sources = []
        self.record.update(projection_settings=self.p, control=self.control, dry_run='stub',
                           stub_mode=(fixture.m['artifacts'].get('projector_stub') or {}).get('mode'))
        fixture.projection_deferred = True       # each drill starts its projection slots itself

    # -------------------------------------------------------------- the core and the projection

    def head(self):
        """The core's newest eventSeq (a head probe on the probe's ADMIN key), or None when no leader answered."""
        meaning, reply = self.f.core('order-events', 'probe-admin', timeout=60, **{'from': 0, 'max': 0})
        return (reply or {}).get('last_seq') if meaning == 'ANSWERED' else None

    def pg_rows(self, database, sql):
        return json.loads(self.f.psql(database, f"SELECT COALESCE(json_agg(t), '[]'::json) FROM ({sql}) t") or '[]')

    def applied(self, database):
        rows = self.pg_rows(database, 'SELECT applied_seq, applied_order_id, halt_reason, '
                                      'EXTRACT(EPOCH FROM clock_timestamp() - beat_at) * 1000 AS beat_age_ms '
                                      'FROM oe_projection_state')
        return rows[0] if rows else None

    def wait_caught_up(self, database, bound_s, head=None):
        """Poll until the projection's applied_seq reaches the core's head as read once at the start (or ``head``): what
        the core had emitted when the wait began, so a moving head under flow never hides a caught-up projection."""
        started = self.clock()
        target = head if head is not None else self.head()
        state = None
        while True:
            state = self.applied(database)
            if target is not None and state and state['applied_seq'] >= target:
                return {'caught_up': True, 'head': target, 'applied': state['applied_seq'],
                        'waited_s': round(self.clock() - started, 3)}
            if self.clock() - started >= bound_s:
                return {'caught_up': False, 'head': target, 'applied': (state or {}).get('applied_seq'),
                        'waited_s': round(self.clock() - started, 3)}
            self.sleep(self.p['POLL_S'])
            if target is None:
                target = self.head()

    def slot_health(self, slots=('pj0', 'pj1')):
        return {s: self.f.projection_health(s) for s in slots if s in self.f.registry['containers']
                and self.f.inspect('container', self.f.registry['containers'][s])['State']['Running']}

    def attached(self, slot='pj0'):
        """The core member a projection slot reports as its source (the stand-in: the leader it followed), or None."""
        return ((self.f.projection_health(slot) or {}).get('source') or {}).get('member')

    def evidence(self, step, phase, extra=None):
        """One sources.json row: every running projection slot's source, archive id, switch count and walked recordings
        from its own /health, and the core's leader."""
        rows = {}
        for slot, h in self.slot_health().items():
            rows[slot] = {k: h.get(k) for k in ('role', 'source', 'archive_id', 'source_switches', 'recordings_walked',
                                                'applied_seq', 'head_seq', 'halt', 'probe_unanswered', 'beats', 'polls',
                                                'last_probe_error', 'last_pg_error')}
            rows[slot]['health_error'] = h.get('error')
        row = {'step': step, 'phase': phase, 'at_ns': time.time_ns(), 'leader': self.f.leader('ae'), 'slots': rows}
        if extra:
            row.update(extra)
        self.sources.append(row)
        (self.out / 'sources.json').write_text(json.dumps(self.sources, indent=1) + '\n')
        return row

    def replay_probe(self):
        return {m: self.f.replay_count(m, REPLAY_STREAMS) for m in CORE_MEMBERS}

    def wait_baseline(self, baseline, bound_ms):
        started = self.clock()
        while True:
            now = self.replay_probe()
            if baseline_back(baseline, now):
                return {'back': True, 'waited_ms': int((self.clock() - started) * 1000), 'probe': now}
            if (self.clock() - started) * 1000 >= bound_ms:
                return {'back': False, 'waited_ms': int((self.clock() - started) * 1000), 'probe': now}
            self.sleep(self.p['POLL_S'])

    def dump(self, database, name, tables=projection_dump.HISTORY_TABLES):
        f = self.f

        def run(sql):
            r = subprocess.run([str(f.pg / 'psql'), '-h', f.gateway, '-p', str(f.pg_port), '-U', 'runtime_fixture', '-d',
                                database, '-v', 'ON_ERROR_STOP=1', '-X', '-q', '-tA', '-c', sql], capture_output=True,
                               timeout=600)
            if r.returncode != 0:
                raise Inconclusive(f'dump of {database}: psql exit {r.returncode}: {r.stderr.decode(errors="replace")[-200:]}')
            return r.stdout
        return projection_dump.dump(run, self.out / 'dumps' / name, tables)

    # -------------------------------------------------------------- the flow and the oracle

    def users(self):
        base = USER_BASE[self.name]
        return list(range(base, base + self.p['PROJECTION_USERS']))

    def start_flow(self, users, name='load'):
        rows = crossing_story(self.p['PROJECTION_REQUESTS'], users, self.f.m['seed'])
        self.s['GW_CONCURRENCY'] = self.p['PROJECTION_CONCURRENCY']
        load = self.start_load(rows, [self.gw('gw0'), self.gw('gw1')], name, self.p['PROJECTION_RATE'])
        self.mark(name + '_started')
        return rows, load

    def finish_flow(self, rows, load, extra_requests=()):
        done = self.wait_done(load, self.p['PROJECTION_LOAD_BOUND_S'])
        attempts = gateway_scenarios._jsonl(load['attempts'])
        self.mark('load_done')
        requests = attempts_as_requests(attempts, rows) + list(extra_requests)
        (self.out / 'requests.json').write_text(json.dumps(requests) + '\n')
        return done, requests

    def oracle(self, requests):
        """The money oracle over the flow (two-observation barrier), then the tap's order events (with the ring-replayed
        gaps the money oracle filled) and the ME journal's trades, read back from the sample it kept."""
        money, order = self.money(creates_from(requests), cancels_from(requests), core_drills.GATE_SEQUENCE)
        sample = json.loads((self.out / 'core-sample.json').read_text())
        trades = [r for r in sample.get('me_journal') or [] if r.get('type') == 'trade']
        return money, order, sample['core_events'], trades

    def projection_lines(self, database, events, trades, head):
        rows = self.pg_rows(database, 'SELECT order_id, status, filled_quantity, remaining_quantity, hold_remaining FROM oe_orders')
        fills = self.pg_rows(database, 'SELECT trade_id, order_id, maker FROM oe_fills')
        seqs = [r['journal_seq'] for r in self.pg_rows(database, 'SELECT journal_seq FROM oe_order_events')]
        orders = compare_orders(events, rows)
        fill = compare_fills(events, fills, trades)
        dense = density(seqs, head)
        self.record.setdefault('projection', {})[database] = {'orders': orders, 'fills': fill, 'density': dense}
        tap_seqs = sorted(e['seq'] for e in events)
        tap_complete = bool(tap_seqs) and tap_seqs[-1] == len(tap_seqs) and tap_seqs[0] == 1
        return {
            'projection_equals_oracle': line(orders['differences'] == 0 and fill['equal'],
                                             {'orders': {k: orders[k] for k in ('orders', 'rows', 'differences')},
                                              'fills': {k: fill[k] for k in ('oracle_pairs', 'rows', 'trades', 'maker_checked')},
                                              'tap_complete': tap_complete},
                                             'projected orders or fills differ from the oracle',
                                             inconclusive=not tap_complete),
            'events_dense_to_head': line(dense['dense'] and dense['last'] == head and not dense['above_head'],
                                         {k: dense[k] for k in ('first', 'last', 'count', 'head', 'missing', 'above_head')},
                                         MISSING_TEXT, inconclusive=head is None),
        }

    def finish(self, lines):
        status, control, waiting = dry_verdict(lines, self.control)
        result = {'status': status, 'lines': lines, 'awaiting': waiting, 'record': self.record}
        if control:
            result['control'] = control
        failing = [v.get('text') or k for k, v in lines.items() if not v['holds'] and not v.get('awaits')]
        if status != 'PASS' or control:
            result['error'] = '; '.join(failing) if failing else None
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'sources.json').write_text(json.dumps(self.sources, indent=1) + '\n')
        return result

    # -------------------------------------------------------------- one fault step

    def step(self, name, fault, database='r01_gateway', hit=None):
        """Evidence before, the fault, evidence after, then the catch-up to the core's head. ``hit`` names the member the
        step must hit (the attached one); the record says whether it did."""
        before = self.evidence(name, 'before')
        witness = fault()
        self.sleep(self.p['STEP_SETTLE_S'])
        after = self.evidence(name, 'after', {'fault': witness})
        caught = self.wait_caught_up(database, self.p['PROJECTOR_CATCHUP_BOUND_S'])
        row = {'fault': witness, 'caught_up': caught, 'before_leader': before['leader'], 'after_leader': after['leader']}
        if hit is not None:
            row['attached_before'] = hit
            row['hit_attached'] = (witness or {}).get('target') == hit
        self.record.setdefault('steps', {})[name] = row
        return row

    def kill_restart(self, role, ready_timeout=180):
        """SIGKILL and restart. An ME member waits ME_RESTART_AFTER_KILL_S first: restarted sooner it finds its archive's
        active mark file and exits (the fixture applies the same wait to a core member itself)."""
        kill = self.f.kill(role)
        if role.startswith('me'):
            self.sleep(self.p['ME_RESTART_AFTER_KILL_S'])
        restart = self.f.restart(role, ready_timeout=ready_timeout)
        return {'target': role, 'kill': kill.get('finished_at'), 'restart_started_at': restart.get('started_at')}


# ------------------------------------------------------------------ projector-me-restart-follow

class MeRestartFollow(ProjectionDrill):
    def run(self):
        f, p = self.f, self.p
        users = self.users()
        f.projection_targets = {'pj1': 'r01_gateway'}        # pj1 is the standby copy of pj0 here
        self.boot(users, p['PROJECTION_TAP_S'])
        f.start_projection_slots(['pj0'])
        self.sleep(p['STEP_SETTLE_S'])
        f.start_projection_slots(['pj1'])
        self.evidence('boot', 'after')
        baseline = self.replay_probe()
        self.record['replay_baseline'] = baseline
        rows, load = self.start_flow(users)
        self.sleep(p['STEP_SETTLE_S'] * 3)
        steps = {}
        me = f.leader('me')
        steps['a'] = self.step('a_me_leader_kill', lambda: self.kill_restart(me) if me else {'skipped': 'no ME leader'})
        head_after_a = self.head()
        attached = self.attached('pj0')
        steps['b'] = self.step('b_attached_member_kill', lambda: self.kill_restart(attached) if attached else
                               {'skipped': 'pj0 reports no source'}, hit=attached)
        leader = f.leader('ae')
        steps['c'] = self.step('c_core_leader_kill', lambda: self.kill_restart(leader) if leader else {'skipped': 'no leader'})
        takeover = {}

        def kill_writer():
            killed = f.kill('pj0')
            started = self.clock()
            while self.clock() - started < p['PROJECTOR_TAKEOVER_BOUND_S']:
                if (f.projection_health('pj1') or {}).get('role') == 'writer':
                    takeover['s'] = round(self.clock() - started, 3)
                    break
                self.sleep(0.5)
            takeover['role'] = (f.projection_health('pj1') or {}).get('role')
            restart = f.restart('pj0', ready_timeout=60)
            return {'target': 'pj0', 'kill': killed.get('finished_at'), 'restart_started_at': restart.get('started_at'),
                    'takeover': dict(takeover)}
        steps['d'] = self.step('d_writer_kill', kill_writer)
        after_d = self.wait_baseline(baseline, p['HISTORY_PROJECTOR_ORPHAN_BOUND_MS'])
        writer = 'pj1' if (f.projection_health('pj1') or {}).get('role') == 'writer' else 'pj0'
        attached = self.attached(writer)
        down_s = p['SOURCE_BEHIND_MS'] / 1000 + p['SOURCE_BEHIND_MARGIN_S']

        def stop_attached():
            if not attached:
                return {'skipped': 'the writer reports no source'}
            stopped = f.stop(attached)
            self.sleep(down_s)
            restart = f.restart(attached, ready_timeout=180)
            return {'target': attached, 'stop_exit': stopped.get('exit_code'), 'down_s': down_s,
                    'restart_started_at': restart.get('started_at')}
        steps['e'] = self.step('e_attached_member_down', stop_attached, hit=attached)
        steps['f'] = self.step('f_money_projector_kill', lambda: self.kill_restart('projector', ready_timeout=120))
        after_f = self.wait_baseline(baseline, p['HISTORY_PROJECTOR_ORPHAN_BOUND_MS'])
        done, requests = self.finish_flow(rows, load)
        final = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'])
        self.evidence('end', 'after')
        money, order, events, trades = self.oracle(requests)
        head = final['head']
        lines = {}
        lines['load_finished'] = line(done, {'requests': len(rows)}, 'load did not finish inside its bound', inconclusive=not done)
        lines['caught_up_after_each_fault'] = line(all(s['caught_up']['caught_up'] for s in steps.values()) and final['caught_up'],
                                                   {k: s['caught_up'] for k, s in steps.items()}, 'projection behind the core head')
        halts = [r for r in self.sources for h in r['slots'].values() if h.get('halt')]
        lines['never_halted'] = line(not halts, {'halts': halts[:5]}, 'projection halted')
        fills_after = self.pg_rows('r01_gateway', f'SELECT count(*) AS n FROM oe_fills WHERE event_seq > {int(head_after_a or 0)}')
        tap_fills_after = sum(1 for e in events if e['kind'] == 'FILL' and e['trade'] > 0 and e['seq'] > (head_after_a or 0))
        lines['fills_after_me_restart_projected'] = line(fills_after[0]['n'] == tap_fills_after and tap_fills_after > 0,
                                                         {'projected': fills_after[0]['n'], 'oracle': tap_fills_after,
                                                          'head_after_me_restart': head_after_a},
                                                         'fills made after the ME restart are not projected',
                                                         inconclusive=tap_fills_after == 0)
        lines.update(self.projection_lines('r01_gateway', events, trades, head))
        lines['money_exact'] = self.money_line(money, order)
        lines['standby_took_over'] = line(takeover.get('s') is not None, {'takeover_s': takeover.get('s'),
                                                                          'bound_s': p['PROJECTOR_TAKEOVER_BOUND_S'],
                                                                          'pj1_role': takeover.get('role')},
                                          'standby did not take over inside its bound')
        lines['replay_baseline_after_writer_kill'] = line(after_d['back'], {k: after_d[k] for k in ('back', 'waited_ms')},
                                                          ORPHAN_TEXT)
        lines['replay_baseline_after_money_projector_kill'] = line(after_f['back'], {k: after_f[k] for k in ('back', 'waited_ms')},
                                                                   ORPHAN_TEXT)
        switches = max((h.get('source_switches') or 0) for r in self.sources for h in r['slots'].values())
        lines['source_switched'] = line(switches >= 1, {'switches': switches}, 'no source switch',
                                        inconclusive=switches == 0)
        hit = [steps[k].get('hit_attached') for k in ('b', 'e')]
        lines['faults_hit_the_attached_member'] = line(all(hit), {'b': steps['b'].get('attached_before'),
                                                                  'e': steps['e'].get('attached_before'), 'hit': hit},
                                                       'a fault missed the attached member', inconclusive=not all(hit))
        lines['follows_successor_recording'] = awaits(
            False, {'stand-in': 'reads the order-event ring over a cluster session; it follows no recording'},
            CONTROL_TEXT[self.name], 'the projector binary (Archive chain following)')
        return self.finish(lines)


# ------------------------------------------------------------------ projection-byte-equal-replay

class ByteEqualReplay(ProjectionDrill):
    def run(self):
        f, p = self.f, self.p
        users = self.users()
        # A smaller page than the stand-in's default, so a catch-up from genesis takes several polls and the kills of C
        # land on the way (recorded with the run)
        f.projection_stub_settings = {'STUB_PAGE_EVENTS': p['STUB_PAGE_EVENTS']}
        self.boot(users, p['PROJECTION_TAP_S'])
        f.start_projection_slots(['pj0'])
        self.evidence('boot', 'after')
        rows, load = self.start_flow(users)
        self.sleep(p['STEP_SETTLE_S'] * 3)
        me = f.leader('me')
        self.step('a_me_leader_kill', lambda: self.kill_restart(me) if me else {'skipped': 'no ME leader'})
        attached = self.attached('pj0')
        self.step('b_attached_member_kill', lambda: self.kill_restart(attached) if attached else
                  {'skipped': 'pj0 reports no source'}, hit=attached)
        leader = f.leader('ae')
        self.step('c_core_leader_kill', lambda: self.kill_restart(leader) if leader else {'skipped': 'no leader'})
        self.step('d_writer_kill', lambda: {'target': 'pj0', 'kill': f.kill('pj0').get('finished_at'),
                                            'restart_started_at': f.restart('pj0', ready_timeout=60).get('started_at')})
        self.step('f_money_projector_kill', lambda: self.kill_restart('projector', ready_timeout=120))
        cprime = self.c_prime()
        done, requests = self.finish_flow(rows, load)
        head = self.head()
        self.record['head_at_end'] = head
        a_state = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'], head=head)
        b_state = self.wait_caught_up('r01_history_b', p['PROJECTOR_CATCHUP_BOUND_S'], head=head)
        self.evidence('end', 'after')
        dumps = {'A': self.dump('r01_gateway', 'A'), 'B': self.dump('r01_history_b', 'B')}
        money_dump = self.dump('r01_money', 'A-money', projection_dump.MONEY_TABLES)
        c = self.c_run(head)
        dumps['C'] = self.dump('r01_history_b', 'C')
        money, order, events, trades = self.oracle(requests)
        lines = {}
        lines['load_finished'] = line(done, {'requests': len(rows)}, 'load did not finish inside its bound', inconclusive=not done)
        lines['all_caught_up'] = line(a_state['caught_up'] and b_state['caught_up'] and c['caught_up']['caught_up'],
                                      {'A': a_state, 'B': b_state, 'C': c['caught_up']}, 'projection behind the core head')
        differ = sorted(set(projection_dump.equal(dumps['A'], dumps['B'])) | set(projection_dump.equal(dumps['A'], dumps['C'])))
        lines['dumps_equal'] = line(not differ, {name: {t: r.get('sha256') for t, r in d.items()} for name, d in dumps.items()}
                                    | {'differ': differ}, CONTROL_TEXT[self.name])
        lines.update(self.projection_lines('r01_gateway', events, trades, head))
        lines['money_exact'] = self.money_line(money, order)
        lines['cprime_beats_after_catch_up'] = line(cprime.get('beat_before_catch_up') is False,
                                                    {k: cprime.get(k) for k in ('kill_landed_before_catch_up', 'beat_before_catch_up',
                                                                                'backlog', 'killed')},
                                                    'second projection beat before it caught up',
                                                    inconclusive=not cprime.get('kill_landed_before_catch_up'))
        lines['c_restarted_on_the_way'] = line(c['kills'] == p['C_KILLS'], {'kills': c['kills'], 'wanted': p['C_KILLS']},
                                               'C was not killed and restarted on its way', inconclusive=c['kills'] < p['C_KILLS'])
        lines['three_different_members'] = awaits(
            False, {'stand-in': 'reads the cluster session; it cannot be pointed at one member\'s archive'},
            'projections were not read from three members', 'the projector binary (one Archive source per projection)')
        lines['money_projection_compared'] = awaits(
            bool(money_dump), {'A': {t: r.get('sha256') for t, r in money_dump.items()}},
            'money projection dump differs', 'a second and third money projection (the money projector hardening slice)')
        lines['gateway_on_rebuilding_database'] = awaits(
            c.get('no_heartbeat_row_before_first_beat') is True, {k: c.get(k) for k in ('no_heartbeat_row_before_first_beat',
                                                                                        'heartbeat_rows_seen')},
            'rebuilding history served as complete', 'gw0 pointed at the second database (the heartbeat view itself is read)')
        return self.finish(lines)

    def c_prime(self):
        """pj1 on an empty database once the core holds the backlog; its attached member killed once during the catch-up."""
        f, p = self.f, self.p
        started = self.clock()
        while (self.head() or 0) < p['CPRIME_BACKLOG_EVENTS'] and self.clock() - started < p['PROJECTION_LOAD_BOUND_S']:
            self.sleep(p['POLL_S'])
        backlog = self.head()
        f.start_projection_slots(['pj1'])
        self.evidence('cprime', 'started', {'backlog': backlog})
        out = {'backlog': backlog, 'killed': None, 'kill_landed_before_catch_up': False, 'beat_before_catch_up': None}
        while self.clock() - started < p['PROJECTION_LOAD_BOUND_S']:
            state = self.applied('r01_history_b') or {}
            if state.get('beat_age_ms') is not None and (state.get('applied_seq') or 0) < (backlog or 0):
                out['beat_before_catch_up'] = True
            if (state.get('applied_seq') or 0) >= p['CPRIME_KILL_AFTER_EVENTS']:
                member = self.attached('pj1')
                head = self.head()
                out['kill_landed_before_catch_up'] = (state.get('applied_seq') or 0) < (head or 0)
                if member:
                    out['killed'] = self.kill_restart(member)
                break
            self.sleep(0.5)
        caught = self.wait_caught_up('r01_history_b', p['PROJECTOR_CATCHUP_BOUND_S'])
        if out['beat_before_catch_up'] is None:
            out['beat_before_catch_up'] = False
        out['caught_up'] = caught
        self.evidence('cprime', 'caught_up', {'caught_up': caught})
        self.record['cprime'] = out
        return out

    def c_run(self, head):
        """C: pj1 again into an empty database, killed and restarted ``C_KILLS`` times on the way; the heartbeat view of
        that database read throughout (no row until the first beat)."""
        f, p = self.f, self.p
        f.stop('pj1')
        f.recreate_projection_database('r01_history_b')
        f.restart('pj1', ready_timeout=60)
        self.evidence('C', 'started')
        kills, seen, rows_before_beat = 0, [], True
        started = self.clock()
        next_kill = p['C_KILL_EVERY_EVENTS']
        while self.clock() - started < p['PROJECTOR_CATCHUP_BOUND_S'] * (p['C_KILLS'] + 2):
            try:
                beat = self.pg_rows('r01_history_b', 'SELECT applied_event_seq FROM gateway_history_heartbeat_v1')
                state = self.applied('r01_history_b') or {}
            except Inconclusive:
                beat, state = None, {}
            applied = state.get('applied_seq') or 0
            if beat:
                seen.append(applied)
                if applied < head:
                    rows_before_beat = False
            if kills < p['C_KILLS'] and applied >= next_kill and applied < head:
                f.kill('pj1')
                f.restart('pj1', ready_timeout=60)
                kills += 1
                next_kill = applied + p['C_KILL_EVERY_EVENTS']
                self.evidence('C', f'kill-{kills}', {'applied': applied})
            if applied >= head:
                break
            self.sleep(0.5)
        caught = self.wait_caught_up('r01_history_b', p['PROJECTOR_CATCHUP_BOUND_S'], head=head)
        self.evidence('C', 'caught_up', {'caught_up': caught})
        out = {'kills': kills, 'caught_up': caught, 'no_heartbeat_row_before_first_beat': rows_before_beat,
               'heartbeat_rows_seen': len(seen)}
        self.record['C'] = out
        return out


# ------------------------------------------------------------------ history-freshness

class HistoryFreshness(ProjectionDrill):
    def history(self, user, path):
        """One GET through gw0 with the user's API key, from the probe container: {status, body, json, at_ns}."""
        return self.call(user, 'GET', path, None, None)

    def call(self, user, method, path, body, key):
        """One request through gw0 with the user's API key (read from the probe's own keys file), from the probe."""
        request = {'url': f'http://{self.gw("gw0")}{path}', 'method': method, 'body': body, 'key': key, 'user': user}
        r = self.f.execute('probe', ['python3', '-I', '-c', HISTORY_CALL], input=json.dumps(request), timeout=30, check=False)
        lines = [l for l in (r.stdout or '').splitlines() if l.startswith('{')]
        out = json.loads(lines[-1]) if lines else {'status': 0, 'error': (r.stderr or '')[-200:]}
        try:
            out['json'] = json.loads(out.get('body') or 'null')
        except ValueError:
            out['json'] = None
        out['at_ns'] = time.time_ns()
        return out

    def as_of(self, answer):
        body = answer.get('json') if isinstance(answer.get('json'), dict) else {}
        return body.get('asOf') if isinstance(body.get('asOf'), dict) else None

    def run(self):
        f, p = self.f, self.p
        self.extra = []
        users = self.users()
        self.boot(users, p['PROJECTION_TAP_S'])
        f.start_projection_slots(['pj0'])
        self.evidence('boot', 'after')
        rows, load = self.start_flow(users)
        user = users[0]
        lines = {}
        # (a) steady flow
        caught = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'])
        samples = []
        for _ in range(5):
            samples.append(self.history(user, '/api/v2/orders/history?limit=5'))
            self.sleep(p['SAMPLE_MS'] / 1000)
        ages = [(self.as_of(s) or {}).get('ageMs') for s in samples]
        cycle = self.stub_cycle_ms()
        self.evidence('a_steady', 'after', {'ages_ms': ages, 'bound_ms': p['HISTORY_FRESH_AGE_BOUND_MS'], 'stub_cycle_ms': cycle})
        lines['a_fresh_age'] = line(caught['caught_up'] and fresh_ages_hold(ages, p),
                                    {'ages_ms': ages, 'bound_ms': p['HISTORY_FRESH_AGE_BOUND_MS'],
                                     'stub_cycle_ms': cycle, 'statuses': [s['status'] for s in samples]},
                                    'history not fresh in steady flow', inconclusive=not caught['caught_up'])
        stale = [(self.as_of(s) or {}).get('stale') for s in samples]
        lines['a_stale_false'] = awaits(all(x is False for x in stale), {'stale': stale}, STALE_LABEL_TEXT,
                                        'the gateway\'s stale label (asOf.stale)')
        # (b) freeze pj0, place and cancel an order, read history and the closed order
        lines.update(self.freeze(user))
        # (d) cut the attached member from the cluster
        lines.update(self.cut_member())
        # (e) kill the core leader
        lines.update(self.leaderless())
        # (f) stop PostgreSQL for a moment
        lines.update(self.pg_down(user))
        # (g) slow the attached member
        lines.update(self.slow_member())
        done, _ = self.finish_flow(rows, load, self.extra)
        lines['load_finished'] = line(done, {'requests': len(rows)}, 'load did not finish inside its bound', inconclusive=not done)
        return self.finish(lines)

    def stub_cycle_ms(self):
        """The stand-in's mean poll cycle (one CoreProbe JVM per poll) from two health reads; None when not measurable."""
        a = self.f.projection_health('pj0')
        self.sleep(5)
        b = self.f.projection_health('pj0')
        polls = (b.get('polls') or 0) - (a.get('polls') or 0)
        return int(5000 / polls) if polls > 0 else None

    def place(self, user, quantity_units):
        body = {'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC',
                'price': gateway_probe.money(gateway_scenarios.REST_PRICE), 'quantity': gateway_probe.money(quantity_units * UNIT)}
        key = str(uuid.uuid4())
        answer = self.call(user, 'POST', '/api/v2/orders', body, key)
        self.extra.append({'method': 'POST', 'path': '/api/v2/orders', 'user': user, 'key': key, 'body': body,
                           'status': answer['status'], 'reply': answer.get('json'), 'sent_ns': answer['at_ns'],
                           'recv_ns': answer['at_ns']})
        return answer

    def cancel(self, user, order):
        answer = self.call(user, 'DELETE', f'/api/v2/orders/{order}', None, None)
        self.extra.append({'method': 'DELETE', 'path': f'/api/v2/orders/{order}', 'user': user, 'key': None,
                           'status': answer['status'], 'reply': answer.get('json'), 'sent_ns': answer['at_ns'],
                           'recv_ns': answer['at_ns']})
        return answer

    def freeze(self, user):
        f, p = self.f, self.p
        out = {}
        before = self.evidence('b_freeze', 'before')
        frozen = f.freeze_main('pj0', duration_s=p['FREEZE_S'])
        frozen_at = self.clock()
        placed = self.place(user, 977)
        order = str((placed.get('json') or {}).get('orderId') or '')
        cancelled = self.cancel(user, order) if order else None
        reads, beat_ages = [], []
        while self.clock() - frozen_at < p['FREEZE_S']:
            reads.append(self.history(user, '/api/v2/orders/history?limit=5'))
            state = self.applied('r01_gateway') or {}
            beat_ages.append([round(self.clock() - frozen_at, 3), state.get('beat_age_ms')])
            self.sleep(p['SAMPLE_MS'] / 1000)
        closed = self.history(user, f'/api/v2/orders/{order}') if order else None
        health = self.f.http('gw0', self.f.m['ports']['gateway_admin'], '/health')
        stale_at = next((t for t, age in beat_ages if age is not None and age > p['HISTORY_STALE_MS']), None)
        self.record['freeze'] = {'frozen': frozen, 'placed': placed.get('status'), 'order': order,
                                 'cancelled': (cancelled or {}).get('status'), 'beat_ages': beat_ages,
                                 'stale_after_s': stale_at, 'closed_order': {k: (closed or {}).get(k) for k in ('status', 'body')}}
        thaw = f.thaw_main('pj0')
        self.evidence('b_freeze', 'after', {'fault': frozen, 'stale_after_s': stale_at})
        out['b_heartbeat_ages_past_stale'] = line(stale_at is not None and stale_at <= stale_bound_s(p),
                                                  {'stale_after_s': stale_at, 'bound_s': stale_bound_s(p), 'freeze_s': p['FREEZE_S'],
                                                   'stale_ms': p['HISTORY_STALE_MS']},
                                                  'heartbeat kept fresh while the projection was frozen',
                                                  inconclusive=stale_at is None and p['FREEZE_S'] * 1000 <= p['HISTORY_STALE_MS'])
        lagging = (closed or {}).get('status')
        out['b_closed_order_lagging_not_404'] = line(lagging == 503, {'status': lagging, 'body': (closed or {}).get('body', '')[:200]},
                                                     'closed order answered 404 while the projection lagged' if lagging == 404
                                                     else 'closed order not answered LAGGING', inconclusive=not order)
        stale = [(self.as_of(r) or {}).get('stale') for r in reads]
        out['b_stale_label'] = awaits(any(x is True for x in stale), {'stale': stale[-5:]}, STALE_LABEL_TEXT,
                                      'the gateway\'s stale label (asOf.stale)')
        hist = None
        try:
            hist = (json.loads(health.get('body') or 'null') or {}).get('history')
        except ValueError:
            pass
        out['b_gateway_health_stale'] = awaits(isinstance(hist, dict) and hist.get('stale') is True, {'history': hist},
                                               STALE_LABEL_TEXT, 'the gateway\'s /health history block')
        # (c) thawed: the order is served
        caught = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'])
        served = self.history(user, f'/api/v2/orders/{order}') if order else None
        out['c_order_served_after_thaw'] = line((served or {}).get('status') == 200 and caught['caught_up'],
                                                {'status': (served or {}).get('status'), 'caught_up': caught, 'thaw': thaw},
                                                'closed order not served after the thaw', inconclusive=not order)
        return out

    def cut_member(self):
        f, p = self.f, self.p
        member = self.attached('pj0')
        if not member:
            return {'d_member_cut': line(False, {}, 'no attached member to cut', inconclusive=True)}
        before = self.evidence('d_cut', 'before', {'member': member})
        beats0 = (f.projection_health('pj0') or {}).get('beats')
        for rule in isolation_arguments(f.m, member, 'add'):
            f.netfilter(member, rule)
        cut_at = self.clock()
        samples = []
        try:
            while self.clock() - cut_at < p['PARTITION_S']:
                h = f.projection_health('pj0')
                survivors = {}
                for other in CORE_MEMBERS:
                    if other != member:
                        try:
                            m = f.metrics(other, f.m['ports']['ae_metrics'])
                            survivors[other] = {'role': m.get('core_cluster_role'), 'commit': m.get('core_log_position')}
                        except Inconclusive:
                            survivors[other] = None
                samples.append({'t': round(self.clock() - cut_at, 3), 'survivors': survivors,
                                'source': (h.get('source') or {}).get('member'), 'applied': h.get('applied_seq'),
                                'head': h.get('head_seq'), 'beats': h.get('beats')})
                self.sleep(p['SAMPLE_MS'] / 1000)
        finally:
            for rule in isolation_arguments(f.m, member, 'delete'):
                f.netfilter(member, rule)
        # The member's rejoin after the heal is recorded, not judged here (it is the core's behaviour, not the
        # projection's); a member that does not rejoin inside MEMBER_REJOIN_BOUND_S is killed and restarted so the
        # drill's later steps run on three members, and the record says so
        rejoin_started = self.clock()
        rejoin = {'bound_s': p['MEMBER_REJOIN_BOUND_S']}
        try:
            f.wait_http(member, f.m['ports']['ae_metrics'], '/ready', timeout=p['MEMBER_REJOIN_BOUND_S'])
            rejoin['ready_s'] = round(self.clock() - rejoin_started, 3)
        except Inconclusive as error:
            rejoin['not_ready'] = str(error)
            rejoin['ready_body'] = f.http(member, f.m['ports']['ae_metrics'], '/ready').get('body', '')[:300]
            rejoin['restarted'] = self.kill_restart(member)
        healed = {'status': 200 if 'ready_s' in rejoin else None}
        after = self.evidence('d_cut', 'after', {'member': member, 'samples': samples[-3:], 'rejoin': rejoin})
        others = [m for s in samples for m, v in s['survivors'].items() if v and v.get('role') == 2.0]
        commits = [max((v or {}).get('commit') or 0 for v in s['survivors'].values()) for s in samples]
        advanced = bool(commits) and commits[-1] > commits[0]
        self.record['cut'] = {'member': member, 'samples': samples, 'healed': healed.get('status'), 'rejoin': rejoin}
        held = [s for s in samples if s['source'] == member and s['head'] is not None and s['applied'] is not None
                and s['head'] > s['applied']]
        return {
            'd_cluster_committed_without_the_cut_member': line(bool(others) and advanced,
                                                               {'member': member, 'leaders_seen': sorted(set(others)),
                                                                'survivor_commit_first_last': [commits[:1], commits[-1:]],
                                                                'rejoin': {k: v for k, v in rejoin.items() if k != 'ready_body'},
                                                                'cut_member_restarted_by_the_drill': 'restarted' in rejoin},
                                                               'the cluster did not go on without the cut member'),
            'd_no_beat_while_attached_to_the_cut_member': awaits(
                bool(held), {'probes_with_head_above_applied_on_cut_member': len(held), 'beats_before': beats0},
                CONTROL_TEXT[self.name], 'the projector binary (an Archive source that can be cut while the session lives)'),
        }

    def leaderless(self):
        """Kill the core leader; one watcher in the probe container polls the survivors' metrics and pj0's /health every
        WATCH_MS until a survivor reports leader, so the window and the beats written inside it are timed in one place."""
        f, p = self.f, self.p
        leader = f.leader('ae')
        if not leader:
            return {'e_no_beat_in_leaderless_window': line(False, {}, 'no core leader', inconclusive=True)}
        survivors = [m for m in CORE_MEMBERS if m != leader]
        plan = {'members': {m: f'http://{f.m["nodes"][m]}:{f.m["ports"]["ae_metrics"]}/metrics' for m in survivors},
                'health': f'http://{f.m["nodes"]["pj0"]}:{f.m["ports"]["projector_admin"]}/health',
                'bound_s': 60, 'watch_ms': p['WATCH_MS']}
        h0 = f.projection_health('pj0') or {}
        killed = f.kill(leader)
        r = f.execute('probe', ['python3', '-I', '-c', WINDOW_WATCH], input=json.dumps(plan), timeout=90, check=False)
        lines = [l for l in (r.stdout or '').splitlines() if l.startswith('{')]
        watch = json.loads(lines[-1]) if lines else {'error': (r.stderr or '')[-200:]}
        restart = f.restart(leader, ready_timeout=180)
        rows = watch.get('rows') or []
        first = rows[0] if rows else {}
        last = rows[-1] if rows else {}
        window = watch.get('window_s')
        beats_in = (last.get('beats') or 0) - (first.get('beats') if first.get('beats') is not None else (h0.get('beats') or 0))
        # a probe unanswered inside the window: one that failed, or one sent and still waiting while no survivor led
        unanswered = (last.get('unanswered') or 0) - (h0.get('probe_unanswered') or 0)
        unanswered += 1 if any(r.get('outstanding') and not r.get('leaders') for r in rows) else 0
        self.record['leaderless'] = {'killed': leader, 'kill': killed.get('finished_at'), 'window_s': window,
                                     'new_leader': watch.get('new_leader'), 'rows': rows[-40:],
                                     'restart': restart.get('started_at'), 'watch_error': watch.get('error')}
        self.evidence('e_leader_kill', 'after', {'window_s': window, 'beats_in_window': beats_in, 'unanswered': unanswered})
        return {'e_no_beat_in_leaderless_window': line(beats_in == 0, {'window_s': window, 'beats_in_window': beats_in,
                                                                       'probes_unanswered_by_window_end': unanswered,
                                                                       'stale_ms': p['HISTORY_STALE_MS'],
                                                                       'window_longer_than_stale': (window or 0) * 1000 > p['HISTORY_STALE_MS']},
                                                       CONTROL_TEXT[self.name],
                                                       inconclusive=window is None or (unanswered < 1 and beats_in == 0))}

    def pg_down(self, user):
        f, p = self.f, self.p
        data = f.root / 'postgres'
        f.command([f.pg / 'pg_ctl', '-D', data, '-m', 'fast', 'stop'], timeout=60)
        f.record_fault({'kind': 'postgres_stop'})
        down_at = self.clock()
        reads, orders = [], []
        while self.clock() - down_at < p['PG_DOWN_S']:
            reads.append(self.history(user, '/api/v2/orders/history?limit=5'))
            orders.append(self.place(user, 911 + len(orders)))
            self.sleep(p['SAMPLE_MS'] / 1000)
        f.command([f.pg / 'pg_ctl', '-D', data, '-l', f.root / 'logs/postgres.log', '-w', 'start'], timeout=60)
        f.registry['pg_pid'] = int((data / 'postmaster.pid').read_text().splitlines()[0]); f.save()
        f.record_fault({'kind': 'postgres_start'})
        statuses = [r['status'] for r in reads]
        codes = [((r.get('json') or {}) if isinstance(r.get('json'), dict) else {}).get('cause') for r in reads]
        placed = [o['status'] for o in orders]
        self.record['pg_down'] = {'history_statuses': statuses, 'causes': codes, 'order_statuses': placed,
                                  'bodies': [r.get('body', '')[:160] for r in reads[:3]]}
        self.evidence('f_pg_down', 'after', {'history_statuses': statuses, 'order_statuses': placed})
        return {
            'f_history_503_while_pg_down': line(bool(statuses) and all(s == 503 for s in statuses), {'statuses': statuses},
                                                'history answered other than 503 while PostgreSQL was down'),
            'f_cause_pg': awaits(bool(codes) and all(c == 'pg' for c in codes), {'causes': codes}, 'history 503 without cause pg',
                                 'the gateway\'s history cause field'),
            'f_order_entry_unaffected': line(bool(placed) and all(s == 201 for s in placed), {'statuses': placed},
                                             'order entry failed while PostgreSQL was down'),
        }

    def counters(self, slot):
        h = self.f.projection_health(slot) or {}
        return {'polls': h.get('polls') or 0, 'probe_ms': h.get('probe_ms_total') or 0,
                'unanswered': h.get('probe_unanswered') or 0, 'beats': h.get('beats') or 0}

    @staticmethod
    def delta(a, b):
        return {k: b[k] - a[k] for k in a}

    def slow_member(self):
        """A baseline of the projection's own probe counters over SLOW_S, then the same span with the slow rule on the
        attached member's traffic to pj0. The method holds only when the rule dropped packets and the projection's reads
        show the slowdown against the baseline (slow_witness)."""
        f, p = self.f, self.p
        member = self.attached('pj0')
        if not member:
            return {'g_slow_member_method': line(False, {}, 'no attached member to slow', inconclusive=True)}
        b0 = self.counters('pj0')
        self.sleep(p['SLOW_S'])
        h0 = self.counters('pj0')
        f.netfilter(member, slow_arguments(f.m, member, 'pj0', 'add', p['SLOW_DROP_PERCENT']))
        try:
            self.sleep(p['SLOW_S'])
            listing = f.netfilter(member, slow_arguments(f.m, member, 'pj0', 'counters', p['SLOW_DROP_PERCENT']))
            h1 = self.counters('pj0')
        finally:
            f.netfilter(member, slow_arguments(f.m, member, 'pj0', 'delete', p['SLOW_DROP_PERCENT']))
        dropped = dropped_packets(listing, f.m['nodes']['pj0'])
        baseline, window = self.delta(b0, h0), self.delta(h0, h1)
        witness = slow_witness(baseline, window, p)
        self.record['slow'] = {'member': member, 'drop_percent': p['SLOW_DROP_PERCENT'], 'seconds': p['SLOW_S'],
                               'dropped_packets': dropped, 'baseline': baseline, 'window': window, 'witness': witness}
        self.evidence('g_slow', 'after', {'slow': self.record['slow']})
        if not dropped:
            method = line(False, self.record['slow'], 'the slow-member rule dropped nothing')
        else:
            method = line(bool(witness['slowed']), self.record['slow'], 'the slow-member method did not slow the member',
                          inconclusive=witness['slowed'] is None)
        return {
            'g_slow_member_method': method,
            'g_switch_and_beats_resume': awaits(False, self.record['slow'], 'attached to a lagging source while another was current',
                                                'the projector binary (a source list to switch to)'),
        }


HISTORY_CALL = ('import json,sys,urllib.request,urllib.error\n'
                'a=json.loads(sys.stdin.read());k=json.load(open("/data/gw-keys.json"))[str(a["user"])]\n'
                'h={"X-API-Key":k}\n'
                'if a.get("key"):h["Idempotency-Key"]=a["key"]\n'
                'd=json.dumps(a["body"]).encode() if a.get("body") is not None else None\n'
                'if d:h["Content-Type"]="application/json"\n'
                'try:\n r=urllib.request.urlopen(urllib.request.Request(a["url"],data=d,headers=h,method=a["method"]),timeout=10)\n'
                ' print(json.dumps({"status":r.status,"body":r.read().decode()}))\n'
                'except urllib.error.HTTPError as e:print(json.dumps({"status":e.code,"body":e.read().decode()}))\n'
                'except Exception as e:print(json.dumps({"status":0,"error":str(e)}))\n')


# The leaderless-window watcher (runs in the probe container): the survivors' role metric and pj0's beat counter, polled
# together until a survivor reports leader (role 2) or the bound
WINDOW_WATCH = ('import json,re,sys,time,urllib.request\n'
                'a=json.loads(sys.stdin.read());t0=time.monotonic();rows=[];new=None\n'
                'def get(u):\n'
                ' try:\n  return urllib.request.urlopen(u,timeout=1).read().decode()\n'
                ' except Exception:\n  return None\n'
                'while time.monotonic()-t0<a["bound_s"]:\n'
                ' roles={m:(lambda x:None if x is None else bool(re.search(r"^core_cluster_role(\\{[^}]*\\})? 2(\\.0)?$",x,re.M)))(get(u)) for m,u in a["members"].items()}\n'
                ' h=get(a["health"]);h=json.loads(h) if h else {}\n'
                ' rows.append({"t":round(time.monotonic()-t0,3),"leaders":[m for m,v in roles.items() if v],"beats":h.get("beats"),"unanswered":h.get("probe_unanswered"),"outstanding":(h.get("last_probe_sent_ns") or 0)>(h.get("last_probe_answered_ns") or 0)})\n'
                ' if rows[-1]["leaders"]:\n  new=rows[-1]["leaders"][0];break\n'
                ' time.sleep(a["watch_ms"]/1000)\n'
                'print(json.dumps({"window_s":rows[-1]["t"] if new else None,"new_leader":new,"rows":rows}))\n')
