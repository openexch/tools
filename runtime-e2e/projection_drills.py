# SPDX-License-Identifier: Apache-2.0
"""The history projection drills: scenario ids, their dry runs on the projection stand-in, and the evidence they write.

Three scenario ids are registered and dispatched by runner.py on a core manifest that declares the projection roles
(``pj0``, ``pj1``; a projection kind of ``core_contracts.GATEWAY_KINDS``):

* ``projector-me-restart-follow``: under crossing order flow on both gateways, with pj0 writing, a standby copy of it in
  pj1 and the money projector running: (a) kill -9 the ME leader and restart it; (b) kill -9 the core member pj0 is
  attached to and restart it; (c) kill the core leader; (d) SIGKILL pj0 (the standby takes over), restart it; (e) stop
  the attached core member for longer than the source-behind window; (f) SIGKILL the money projector and restart it.
  Between (d) and (e), (d2): SIGSTOP the writing copy, the other takes over and must stop the replay the hung copy
  recorded (on an external driver the hung copy's subscription outlives the takeover; ORPHAN_STOP_BOUND_MS), then the
  hung copy is killed and restarted.
  After each fault the projection reaches the core's head; the projection equals the fixture's oracle; the money oracle
  is exact; after (d) and (f) every core member's replay count is back at its baseline.
* ``projection-byte-equal-replay``: the same flow without (e); pj1 starts on an empty database with a backlog and its
  attached member is killed during the catch-up (C'); then the flow stops and the head is recorded. A = pj0's database,
  B = pj1's, C = pj1 again into an empty database, killed and restarted twice on the way. The canonical dumps of A, B and
  C (projection_dump.py, SHA-256) are equal, the events are dense from 1 to the head, two fills per trade, and the maker
  flag of every fill agrees with the ME journal's taker order.
* ``history-freshness``: pj0 alone. (a) steady flow; (b) SIGSTOP pj0, place and cancel an order, read history and the
  closed order through gw0; (c) SIGCONT (a projector that exits 70 on its driver rule after a pause past its driver
  bound is started again, as its supervisor would; any other exit fails); (d) cut the attached core member from the cluster; (e) kill the core leader;
  (f) stop PostgreSQL for a moment; (g) slow the attached member (its UDP to pj0 dropped on pj0's side: on the binary all but one packet in
  SLOW_KEEP_EVERY, on the stand-in a random share, SLOW_DROP_PERCENT;
  the step holds only when pj0's mean probe time per poll reaches SLOW_WITNESS_PERCENT of a baseline taken just before,
  or a probe goes unanswered: Aeron's retransmission hides a modest drop).

Each drill runs on the projector binary (oe-projector of the cut, or a control build of it: a kind of
core_contracts.PROJECTOR_BINARY_KINDS) or, as its dry run, on the stand-in (``projector_stub``, projector_stub.py). Any
other slot plan is refused before a container starts (exit non-zero). On the stand-in, a line it cannot meet is marked
``awaits`` with what it waits for; it is recorded with its text and does not decide a dry run. On the binary every line
is judged, except the money tables of B and C (the fixture runs one money projector: its dump is A's only, recorded).

A line that cannot be judged once another line failed (the oracle comparison of a projection that never reached the
head, say) names that line in ``consequence_of``: it is recorded and judged only when that line holds. A control run
then fails only on the rule it tests.

The binary's own controls (core_contracts.GATEWAY_KINDS pj-nc-*): the pinned-recording build is judged on the successor
text from fault (b) on, and that text is given only to a projection that applied nothing after a fault once the member it
followed started a new journal recording (its archive catalog); any other projection behind the head is ``projection
behind the core head`` (a source left before (b) shows so on (a)). The wall-clock build runs in every projection the
byte-equal drill compares, the dump takes every column a table has beyond its fixed list, and the dumps must still be
equal on the fixed columns alone; the drop build reads PROJ_NC_DROP_SEQ (default 2) in every compared projection.

The orphan check after (d) and (f): no member serves more money-projector replays than the baseline's total, the members
together no more than it; each member at most the history replays the running slots report open on it (their /health,
read at the probe); the members' /dev/shm together at most the baseline total plus SHM_BASELINE_SLACK_BYTES. Every
projector and core container is running at the end and every restart found the drill's own kill or stop.

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
import re
import subprocess
import threading
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
# The projector binary's own defaults the drills compare against (gateway projector/ProjectorSettings.h): its head
# probe cadence (no answered probe across two of them is the unanswered-probe witness of the leaderless window)
BINARY_HEAD_PROBE_MS = 1000
SETTINGS = {
    # the flow: crossing LIMIT pairs on market 1 across gw0 and gw1
    'PROJECTION_USERS': 8, 'PROJECTION_REQUESTS': 1200, 'PROJECTION_RATE': 5, 'PROJECTION_CONCURRENCY': 4,
    'PROJECTION_TAP_S': 3600, 'PROJECTION_LOAD_BOUND_S': 1200,
    # functional drill bounds (never limits of a binary; the measured times are recorded as data)
    'PROJECTOR_CATCHUP_BOUND_S': 60, 'PROJECTOR_TAKEOVER_BOUND_S': 21, 'HISTORY_PROJECTOR_ORPHAN_BOUND_MS': 30000,
    # a projector copy the drill restarts is ready (or answers /health, a standby) inside this bound
    'PROJECTOR_READY_BOUND_S': 60,
    # HISTORY_STALE_MS is the gateway's history stale bound; history-freshness sets it, and the gateway's /health probe
    # cadence HISTORY_GATEWAY_PROBE_MS, on its gateway slots (GATEWAY_HISTORY_STALE_MS, GATEWAY_HISTORY_PROBE_MS,
    # recorded). HISTORY_PROBE_MS is the projector's head probe cadence (its default, not set)
    'HISTORY_FRESH_AGE_BOUND_MS': 3000, 'HISTORY_STALE_MS': 3000, 'HISTORY_PROBE_MS': 1000, 'HISTORY_GATEWAY_PROBE_MS': 2000,
    # the projector's source-behind window; (e) holds the attached member down for this plus the margin
    'SOURCE_BEHIND_MS': 5000, 'SOURCE_BEHIND_MARGIN_S': 10,
    # the freshness drill's windows
    'FREEZE_S': 8, 'FREEZE_LONG_S': 12, 'PG_DOWN_S': 5, 'PARTITION_S': 20, 'MEMBER_REJOIN_BOUND_S': 120, 'SLOW_S': 20, 'SLOW_DROP_PERCENT': 80, 'SLOW_WITNESS_PERCENT': 150, 'SAMPLE_MS': 500,
    # the byte-equal drill: C' starts once the core has emitted this many events, its attached member is killed once
    # the catch-up has applied this many, and C is killed and restarted this many times on its way
    'CPRIME_BACKLOG_EVENTS': 1500, 'CPRIME_KILL_AFTER_EVENTS': 200, 'C_KILLS': 2, 'C_KILL_EVERY_EVENTS': 400,
    'STUB_PAGE_EVENTS': 200,
    'STEP_SETTLE_S': 3, 'POLL_S': 1, 'WATCH_MS': 100, 'WATCH_LEAD_S': 1, 'ME_RESTART_AFTER_KILL_S': 13,
    # the orphan check's /dev/shm part: the three core members' driver bytes together may exceed their baseline total by
    # this much (leadership and member restarts move driver files between members; the replay count is the exact part)
    'SHM_BASELINE_SLACK_BYTES': 64 * 1024 * 1024,
    # (g) on the binary: lag above the baseline's largest in this many consecutive slow samples is a slowdown
    'SLOW_LAG_SAMPLES': 2,
    # (g) on the binary: one packet in SLOW_KEEP_EVERY of the member's UDP to pj0 is let through (the rest dropped on
    # pj0's side, on pj0's replay port only, found over REPLAY_PORT_PROBE_S); an 80% random drop is repaired by Aeron's
    # retransmission faster than the lag shows it
    'SLOW_KEEP_EVERY': 40, 'REPLAY_PORT_PROBE_S': 3,
    # (b) and (c) of the freshness drill: gw0's /health shows stale after HISTORY_STALE_MS plus HISTORY_GATEWAY_PROBE_MS;
    # FREEZE_S lies above that and below the projector's driver bound (PROJECTOR_DRIVER_BOUND_MS, its default driver
    # timeout), so the SIGCONT resumes it: it must still run THAW_EXIT_WAIT_S later. A second freeze of FREEZE_LONG_S
    # lies above the driver bound: on that thaw the projector exits 70 on its driver rule (F3b) or resumes, and an exit
    # is started again as its supervisor would; any other exit fails (c)
    'THAW_EXIT_WAIT_S': 5, 'PROJECTOR_DRIVER_BOUND_MS': 10000,
    # C of the byte-equal drill: pj1 commits this many events per batch while it rebuilds (the rebuild outruns the
    # drill's kills and reads at the binary's default), and gw0's reads before its first beat count once its schema exists
    'C_BATCH_EVENTS': 1, 'C_SCHEMA_BOUND_S': 30,
    # projector-me-restart-follow: the hung writer (d2) and the orphan watch. The member the killed or hung copy read is sampled every
    # ORPHAN_SAMPLE_MS; a recorded replay of the hung copy must be gone ORPHAN_STOP_BOUND_MS after the takeover; a
    # remaining one is watched up to ORPHAN_WATCH_S after the takeover (the archive's own cleanup, recorded). An external
    # driver keeps a stopped client for PJ_DRIVER_CLIENT_LIVENESS_S (the projection slots' staged aeronmd in this drill;
    # the fixture admits only the exact value core_contracts.PROJECTION_DRIVER_LIVENESS_EXEMPT names)
    'ORPHAN_SAMPLE_MS': 250, 'ORPHAN_STOP_BOUND_MS': 10000, 'ORPHAN_WATCH_S': 30, 'PJ_DRIVER_CLIENT_LIVENESS_S': 60,
}
# gw0's history read causes as its metrics name them (gateway_history_reads_total ``cause``) -> the group its /health
# and the contract name (gateway common/src/History.cpp groupOf); an answered read counts as ``ok``
CAUSE_GROUP = {'unconfigured': 'pg', 'absent': 'pg', 'unreachable': 'pg', 'timeout': 'pg', 'bad_row': 'pg', 'error': 'pg',
               'no_heartbeat': 'heartbeat', 'epoch': 'epoch', 'stale': 'stale', 'lagging': 'lagging'}
# The money projector's replay stream (core-projector ProjectorConfig.REPLAY_STREAM_ID): the standing reader the replay
# baseline is taken with. The history projector's replay stream joins this list when its binary exists.
MONEY_PROJECTOR_REPLAY_STREAM = 9161
REPLAY_STREAMS = (MONEY_PROJECTOR_REPLAY_STREAM,)
HISTORY_PROJECTOR_REPLAY_STREAM = int(core_contracts.HISTORY_PROJECTOR_JOURNAL['HISTORY_PROJECTOR_REPLAY_STREAM'])
BINARY_SLOT_ARTIFACTS = {'history_projector', 'history_projector_nc'}
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
    """The control text a projection control kind expects for ``name`` (the kind's ``control_text``, else the drill's),
    or None. A control kind of another drill is refused."""
    spec = core_contracts.GATEWAY_KINDS.get(manifest.get('manifest_kind')) or {}
    control = spec.get('projection_control')
    if control is None:
        return None
    if control != name:
        raise Inconclusive(f'kind {manifest.get("manifest_kind")} is the control of {control}, not of {name}')
    return spec.get('control_text') or CONTROL_TEXT[name]


def check_scenario(manifest, name):
    """Before any container starts: an unknown id is refused; a projection scenario needs a manifest that declares the
    projection roles; pj0 and pj1 both run the projector binary (product or control build: 'binary') or both the
    stand-in ('stub'); any other plan is refused, so the scenario exits non-zero; a control kind runs only the drill it
    controls. Returns the mode."""
    if not is_scenario(name):
        raise Inconclusive('unknown projection scenario: ' + name)
    if not core_contracts.projection_manifest(manifest):
        raise Inconclusive(f'{name} needs a manifest that declares the projection roles (a projection kind)')
    slots = manifest.get('slot_artifacts') or {}
    pair = {slots.get('pj0'), slots.get('pj1')}
    if pair <= BINARY_SLOT_ARTIFACTS and None not in pair:
        mode = 'binary'
    elif pair == {'projector_stub'}:
        mode = 'stub'
    else:
        raise Inconclusive(f'{name} runs on the projector binary (pj0 and pj1 = history_projector or its control build) or '
                           f'as a dry run on the stand-in (both projector_stub); this kind stages pj0={slots.get("pj0")}, '
                           f'pj1={slots.get("pj1")}')
    control_of(manifest, name)
    return mode


def scenario(fixture, name, out_dir):
    """runner.py entry for the projection scenario ids."""
    mode = check_scenario(fixture.m, name)
    cls = {'projector-me-restart-follow': MeRestartFollow, 'projection-byte-equal-replay': ByteEqualReplay,
           'history-freshness': HistoryFreshness}[name]
    result = cls(fixture, name, Path(out_dir) / 'drill').run()
    scope = (f'{name} on the projector binary ({", ".join(sorted(set((fixture.m.get("slot_artifacts") or {}).get(s) for s in ("pj0", "pj1"))))})'
             if mode == 'binary' else f'{name} dry run on the projection stand-in')
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0], scope=scope)


def awaits(holds, detail, text, reason, judged=False, inconclusive=False):
    """A line the stand-in cannot meet: recorded with its text, never deciding a dry run. ``judged`` (the drill runs on
    the projector binary): an ordinary line."""
    out = line(holds, detail, text, inconclusive=inconclusive)
    if not judged:
        out.pop('inconclusive', None)
        out['holds'] = bool(holds)
        if not out['holds'] and text:
            out['text'] = text
        out['awaits'] = reason
    return out


def consequence(out, of):
    """Mark a line as judged only when line ``of`` holds (its own witness needs ``of``'s precondition)."""
    out['consequence_of'] = of
    return out


def dry_verdict(lines, control):
    """A control run fails only on the rule it tests: it passes when at least one judged line fails with exactly the
    control text, every judged line that fails has that text, and no judged line is inconclusive; anything else is FAIL.
    Otherwise: INCONCLUSIVE when a judged line's witness is missing, PASS when every judged line holds, else FAIL.
    ``awaits`` lines are listed, not judged; a line whose ``consequence_of`` line does not hold is listed, not judged."""
    def judged_line(k, v):
        if v.get('awaits'):
            return False
        of = v.get('consequence_of')
        return of is None or of not in lines or lines[of]['holds']
    judged = {k: v for k, v in lines.items() if judged_line(k, v)}
    waiting = {k: {'holds': v['holds'], 'text': v.get('text'), 'awaits': v['awaits']} for k, v in lines.items() if v.get('awaits')}
    waiting.update({k: {'holds': v['holds'], 'text': v.get('text'), 'consequence_of': v['consequence_of']}
                    for k, v in lines.items() if not v.get('awaits') and k not in judged})
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


def freshness_gateway_settings(p):
    """The gateway history settings history-freshness gives its gateway slots: the stale bound and the /health probe
    cadence, so a freeze below the projector's driver bound reads stale on gw0's answers and its /health."""
    values = {'GATEWAY_HISTORY_STALE_MS': p['HISTORY_STALE_MS'], 'GATEWAY_HISTORY_PROBE_MS': p['HISTORY_GATEWAY_PROBE_MS']}
    return {slot: dict(values) for slot in ('gw0', 'gw1')}


def follow_driver_env(p):
    """The projection slots' staged aeronmd settings in projector-me-restart-follow: the client liveness the hung writer
    (d2) is judged under, and the publication unblock timeout above it (the driver refuses one at or below it)."""
    liveness = p['PJ_DRIVER_CLIENT_LIVENESS_S']
    return {'AERON_CLIENT_LIVENESS_TIMEOUT': f'{liveness}s', 'AERON_PUBLICATION_UNBLOCK_TIMEOUT': f'{liveness + 15}s'}


CLIENT_SERVICE_INTERVAL = re.compile(r'exiting 70: service interval exceeded in ns: timeout=(\d+), interval=(\d+)')


def driver_rule_exit(text):
    """An exit 70 on the projector's driver rule: its own line naming F3b (a process pause past the driver bound, or a
    driver that reclaimed its client), or the Aeron client's report of the same rule when it comes first (its conductor
    did not run for longer than the driver timeout it names)."""
    if 'exit 70:' in text and '(F3b)' in text:
        return True
    m = CLIENT_SERVICE_INTERVAL.search(text)
    return bool(m) and int(m.group(2)) > int(m.group(1))


def finished_at_epoch(text):
    """A container's State.FinishedAt (RFC 3339 with nanoseconds, UTC) as epoch seconds; None for docker's zero time."""
    import datetime
    m = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z', text or '')
    if not m or m.group(1).startswith('0001'):
        return None
    whole = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp()
    return whole + (int(m.group(2)) / 10 ** len(m.group(2)) if m.group(2) else 0.0)


def leaderless_rows(rows, death):
    """The watcher's rows from the leader's death on (``death``: epoch seconds, the killed container's FinishedAt; the
    watcher's ``w`` is the same host clock) and the leaderless window: death to the first row a survivor led."""
    if death is None:
        return [], None
    after = [r for r in rows if r.get('w') is not None and r['w'] >= death]
    new = next((r for r in after if r.get('leaders')), None)
    return after, (round(new['w'] - death, 3) if new else None)


def thaw_line(after_thaw, long):
    """(c) after a SIGCONT. Below the driver bound the projector resumes (thaw_branch 'running'); above it it resumes or
    exits 70 on its driver rule and is started again ('restarted'). Any other exit fails."""
    outcome = (after_thaw or {}).get('outcome')
    if not long and outcome == 'restarted':
        return line(False, dict(after_thaw), 'projector exited on a thaw below its driver bound')
    return line(outcome in ('running', 'restarted'), dict(after_thaw or {}), 'projector exited on the thaw for another reason')


def g_switch_verdict(samples, member, left_reasons):
    """(g) on the binary: the projector left the slowed member for BEHIND inside the slow window and a beat was written
    after the switch. A switch with no rise of the BEHIND count between the last baseline sample and the switch sample
    left a member that went silent (its archive session lost), not a slow one: INCONCLUSIVE, with the projector's own
    leave lines (``left_reasons``) as the reason. No switch at all fails."""
    base = [s for s in samples if s['phase'] == 'baseline']
    slow = [s for s in samples if s['phase'] == 'slow']
    at = next((s for s in slow if s['source'] not in (None, member)), None)
    behind_rose = None
    beats_after = None
    if at is not None:
        behind_rose = (at.get('behind') or 0) > ((base[-1].get('behind') or 0) if base else 0)
        later = [s['beat_at_us'] for s in samples if (s['phase'] == 'slow' and s['t'] >= at['t']) or s['phase'] == 'after']
        beats_after = len({b for b in later if b is not None}) > 1
    detail = {'switch_at_s': at['t'] if at else None, 'behind_at_switch': behind_rose, 'beats_after_switch': beats_after,
              'left_reasons': list(left_reasons or [])[-3:]}
    text = 'attached to a lagging source while another was current'
    if at is None:
        return line(False, detail, text)
    if not behind_rose:
        return line(False, detail, 'switch was not BEHIND', inconclusive=True)
    return line(beats_after is True, detail, text)


def fresh_ages_hold(ages, p):
    """Steady flow: every sampled history answer carries an age at or below HISTORY_FRESH_AGE_BOUND_MS."""
    return bool(ages) and all(a is not None and a <= p['HISTORY_FRESH_AGE_BOUND_MS'] for a in ages)


def fresh_label(as_of):
    """A history page's ``asOf.stale``: True or False, ``'missing'`` when the page has asOf without the key (or no asOf
    at all), so a gateway that drops the label fails with the label text, never another."""
    if not isinstance(as_of, dict) or 'stale' not in as_of:
        return 'missing'
    return as_of['stale'] if isinstance(as_of['stale'], bool) else 'missing'


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


def baseline_back(baseline, after, readers=(), shm_slack=None):
    """Whether the core members' replays and /dev/shm are back at the baseline: {'back', 'count_back', 'shm_back',
    'over', 'shm'}.

    A replay publication no reader holds is an orphan. The money projector's stream (one standing reader that may attach
    to another member after a fault): on no member more than the baseline's total over the members, and not more over
    the members together. The history projector's replay stream: on each member at most the replays the running
    projection slots report open on that member, read from their /health at the probe (``readers``: [(member, n)]).
    /dev/shm: the members' bytes together at most their baseline total plus ``shm_slack`` (None: recorded, not judged)."""
    out = {'count_back': True, 'shm_back': True, 'over': []}
    if any('error' in (after.get(m) or {'error': 'absent'}) or 'error' in b for m, b in baseline.items()):
        out.update(count_back=False, shm_back=False, back=False, over=['probe error'])
        return out
    totals = {}
    for b in baseline.values():
        for stream, n in (b.get('replays') or {}).items():
            totals[stream] = totals.get(stream, 0) + n
    history = str(HISTORY_PROJECTOR_REPLAY_STREAM)
    allowed = {}
    for member, n in readers:
        if member is not None:
            allowed[member] = allowed.get(member, 0) + n
    seen = {}
    for member in baseline:
        replays = (after.get(member) or {}).get('replays') or {}
        for stream, n in replays.items():
            seen[stream] = seen.get(stream, 0) + n
            limit = allowed.get(member, 0) if stream == history else totals.get(stream, 0)
            if n > limit:
                out['over'].append({'member': member, 'stream': stream, 'replays': n, 'allowed': limit})
    for stream, n in seen.items():
        if stream != history and n > totals.get(stream, 0):
            out['over'].append({'members': 'all', 'stream': stream, 'replays': n, 'allowed': totals.get(stream, 0)})
    out['count_back'] = not out['over']
    base_shm = sum((b.get('shm_bytes') or 0) for b in baseline.values())
    now_shm = sum(((after.get(m) or {}).get('shm_bytes') or 0) for m in baseline)
    out['shm'] = {'baseline': base_shm, 'now': now_shm, 'slack': shm_slack,
                  'members': {m: [(baseline[m] or {}).get('shm_bytes'), (after.get(m) or {}).get('shm_bytes')] for m in baseline}}
    out['shm_back'] = shm_slack is None or now_shm <= base_shm + shm_slack
    out['back'] = out['count_back'] and out['shm_back']
    return out


def health_stale(health):
    """True when a gw0 /health answer's history block says stale."""
    try:
        hist = (json.loads((health or {}).get('body') or 'null') or {}).get('history')
    except ValueError:
        return False
    return isinstance(hist, dict) and hist.get('stale') is True


def history_reads_by_group(metrics):
    """``gateway_history_reads_total`` summed by what a drill judges: ``busy`` and ``not_found`` by their result, an
    unavailable read by its cause's group (CAUSE_GROUP; an unknown cause by its own name), any other read as ``ok``."""
    out = {}
    for text in (metrics or '').splitlines():
        if not text.startswith('gateway_history_reads_total{'):
            continue
        labels, _, value = text.partition('} ')
        parts = dict(part.split('=', 1) for part in labels[len('gateway_history_reads_total{'):].split(',') if '=' in part)
        result, cause = parts.get('result', '').strip('"'), parts.get('cause', '').strip('"')
        key = result if result in ('busy', 'not_found') else CAUSE_GROUP.get(cause, cause) if result == 'unavailable' else 'ok'
        try:
            out[key] = out.get(key, 0) + int(float(value))
        except ValueError:
            pass
    return out


def replay_readers(health):
    """[(member, open replays)] of the running projection slots from their /health (``slot_health``): the replays a slot
    reports open (``replays_open``), else one for the writer and none for another role."""
    out = []
    for h in (health or {}).values():
        if not isinstance(h, dict) or h.get('error'):
            continue
        member = (h.get('source') or {}).get('member')
        n = h.get('replays_open')
        out.append((member, n if isinstance(n, int) else (1 if h.get('role') == 'writer' else 0)))
    return out


def journal_recordings(state_root, member, stream=int(core_contracts.HISTORY_PROJECTOR_JOURNAL['HISTORY_PROJECTOR_JOURNAL_STREAM'])):
    """The recording ids of the order journal in one core member's archive catalog (host side), sorted."""
    import core_fixture
    archive = Path(state_root) / 'state' / member / 'state' / 'archive'
    return sorted(r for r, d in core_fixture.catalog_descriptors(archive).items() if d.get('stream') == stream)


def successor_verdict(steps, order=('b', 'c', 'd', 'e', 'f')):
    """Which text a projection behind the head after fault (b) on earns. The successor text only when the member the
    projection followed started a new journal recording at that step or an earlier one from (b), and at the first step
    it did not catch up it applied nothing after the fault (stuck at the end of what it followed, not slow); else
    ``projection behind the core head``. Returns {'stuck_step', 'new_recording_at', 'text'} (text None: all caught up).
    ``steps``: name -> {'caught_up': {...}, 'applied_after_fault', 'recordings': {'member', 'before', 'after'}}."""
    new_at = None
    for k in order:
        st = steps.get(k) or {}
        rec = st.get('recordings') or {}
        if new_at is None and rec.get('member') and len(rec.get('after') or []) > len(rec.get('before') or []):
            new_at = k
        if not (st.get('caught_up') or {}).get('caught_up', True):
            stuck = st.get('applied_after_fault') is not None and (st['caught_up'].get('applied') == st['applied_after_fault'])
            text = CONTROL_TEXT['projector-me-restart-follow'] if (new_at is not None and stuck) else 'projection behind the core head'
            return {'stuck_step': k, 'stuck': stuck, 'new_recording_at': new_at, 'text': text}
    return {'stuck_step': None, 'stuck': False, 'new_recording_at': new_at, 'text': None}


def isolation_arguments(manifest, member, action):
    """[(namespace, iptables rule)] that cut one core member from the other two: UDP both ways, each dropped on the
    receiving side (INPUT in the member's namespace from each other member, INPUT in each other member's from the
    member). A dropped send would fail in the sender with EPERM, and the core fails fast on a run of identical send
    errors; a receive drop leaves the sends as they are. A client of the member (a projector, the gateways) keeps its
    path."""
    if member not in CORE_MEMBERS or action not in ('add', 'delete'):
        raise Violation('a member cut names a core member and add or delete')
    flag = '-A' if action == 'add' else '-D'
    rules = []
    for other in CORE_MEMBERS:
        if other == member:
            continue
        rules.append((member, ['-w', '2', flag, 'INPUT', '-p', 'udp', '-s', manifest['nodes'][other], '-j', 'DROP']))
        rules.append((other, ['-w', '2', flag, 'INPUT', '-p', 'udp', '-s', manifest['nodes'][member], '-j', 'DROP']))
    return rules


def slow_arguments(manifest, member, client, action, drop_percent):
    """An iptables rule in ``client``'s namespace that drops a random share of the UDP it receives from ``member`` (the
    statistic match): the member keeps delivering, slower. Dropped on the receiving side: a send dropped in the
    member's own namespace fails there with EPERM, and the core fails fast on a run of identical send errors.
    ``drop_percent`` is a setting (1..99)."""
    if member not in CORE_MEMBERS or action not in ('add', 'delete', 'counters') or not 1 <= drop_percent <= 99:
        raise Violation('a slow-member rule names a core member, add, delete or counters, and a drop percent 1..99')
    if action == 'counters':
        return ['-w', '2', '-L', 'INPUT', '-n', '-v', '-x']
    return ['-w', '2', '-A' if action == 'add' else '-D', 'INPUT', '-p', 'udp', '-s', manifest['nodes'][member], '-m',
            'statistic', '--mode', 'random', '--probability', f'{drop_percent / 100:.2f}', '-j', 'DROP']


def slow_rate_arguments(manifest, member, action, keep_every, replay_port):
    """iptables rules in pj0's namespace that let one of every ``keep_every`` UDP packets from ``member`` to pj0's
    replay port (``replay_port``, found by replay_port) in (the statistic match's nth mode) and drop the rest: a slow
    replay whatever Aeron retransmits (each repair is dropped in the same share). Nothing else from the member is
    touched: its archive control session and the cluster session go on, so the source is slow, not silent. Add or
    delete; the counters listing is slow_arguments(..., 'counters', ...)."""
    if member not in CORE_MEMBERS or action not in ('add', 'delete') or keep_every < 2 or not isinstance(replay_port, int):
        raise Violation('a slow-rate rule names a core member, add or delete, a replay port, and keeps one packet in 2 or more')
    flag = '-A' if action == 'add' else '-D'
    match = ['-p', 'udp', '-s', manifest['nodes'][member], '--dport', str(replay_port)]
    return [['-w', '2', flag, 'INPUT', *match, '-m', 'statistic', '--mode', 'nth', '--every', str(keep_every),
             '--packet', '0', '-j', 'ACCEPT'],
            ['-w', '2', flag, 'INPUT', *match, '-j', 'DROP']]


def udp_ports(proc_net_udp):
    """The local UDP ports bound in a network namespace, from its /proc/net/udp text."""
    ports = set()
    for text in (proc_net_udp or '').splitlines()[1:]:
        parts = text.split()
        if len(parts) > 2 and ':' in parts[1]:
            ports.add(int(parts[1].rsplit(':', 1)[1], 16))
    return sorted(ports)


def port_counts(listing, address):
    """Packets per destination port of the counting rules naming ``address`` (``iptables -L INPUT -n -v -x``)."""
    out = {}
    for text in (listing or '').splitlines():
        parts = text.split()
        port = next((int(x[4:]) for x in parts if x.startswith('dpt:') and x[4:].isdigit()), None)
        if port is not None and address in parts and parts[0].isdigit():
            out[port] = out.get(port, 0) + int(parts[0])
    return out


def dropped_packets(listing, address):
    """Packets the statistic rule dropped, from ``iptables -L INPUT -n -v -x`` output (the rule naming ``address``; None
    when it is absent)."""
    for text in (listing or '').splitlines():
        parts = text.split()
        if len(parts) > 7 and parts[2] == 'DROP' and address in parts:
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
        self.mode = check_scenario(fixture.m, name)
        self.binary = self.mode == 'binary'
        self.sources = []
        self.record.update(projection_settings=self.p, control=self.control, dry_run=None if self.binary else 'stub',
                           projection_mode=self.mode,
                           stub_mode=(fixture.m['artifacts'].get('projector_stub') or {}).get('mode'),
                           projector_defines={s: (fixture.m['artifacts'].get(fixture.m['slot_artifacts'].get(s)) or {}).get('defines')
                                              for s in ('pj0', 'pj1')})
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
                                      'EXTRACT(EPOCH FROM clock_timestamp() - beat_at) * 1000 AS beat_age_ms, '
                                      'floor(EXTRACT(EPOCH FROM beat_at) * 1000000)::bigint AS beat_at_us '
                                      'FROM oe_projection_state')
        return rows[0] if rows else None

    def beat_at_us(self, database='r01_gateway'):
        """The projection's beat_at (database clock, microseconds), straight from the database: a change is a beat
        written, whatever wrote it (the binary's beat rule, or a control build's fence)."""
        f = self.f
        r = subprocess.run([str(f.pg / 'psql'), '-h', f.gateway, '-p', str(f.pg_port), '-U', 'runtime_fixture', '-d', database,
                            '-X', '-q', '-tA', '-c', 'SELECT floor(EXTRACT(EPOCH FROM beat_at) * 1000000)::bigint '
                                                     'FROM oe_projection_state'], capture_output=True, text=True, timeout=10)
        text = (r.stdout or '').strip()
        return int(text) if r.returncode == 0 and text.lstrip('-').isdigit() else None

    def replay_streams(self):
        return REPLAY_STREAMS + ((HISTORY_PROJECTOR_REPLAY_STREAM,) if self.binary else ())

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
                                                'last_probe_error', 'last_pg_error', 'halt_detail', 'replays_open',
                                                'behind', 'leader_avoided', 'replays_started', 'replay_stops',
                                                'stop_requests_answered', 'lag_events', 'sources_state', 'epoch')
                          if k in h or k in ('role', 'source', 'applied_seq', 'head_seq', 'halt')}
            rows[slot]['health_error'] = h.get('error')
        row = {'step': step, 'phase': phase, 'at_ns': time.time_ns(), 'leader': self.f.leader('ae'), 'slots': rows}
        if extra:
            row.update(extra)
        self.sources.append(row)
        (self.out / 'sources.json').write_text(json.dumps(self.sources, indent=1) + '\n')
        return row

    def replay_probe(self):
        return {m: self.f.replay_count(m, self.replay_streams()) for m in CORE_MEMBERS}

    def wait_baseline(self, baseline, bound_ms):
        """Poll the replay-count probe until every member is back at the baseline (baseline_back: the history replays
        each member may serve are read from the running projection slots' /health at the same probe)."""
        started = self.clock()
        while True:
            readers = replay_readers(self.slot_health()) if self.binary else ()
            now = self.replay_probe()
            judged = baseline_back(baseline, now, readers, self.p['SHM_BASELINE_SLACK_BYTES'])
            waited = int((self.clock() - started) * 1000)
            if judged['back'] or waited >= bound_ms:
                return dict(judged, waited_ms=waited, readers=readers, probe=now)
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

    # -------------------------------------------------------------- reads through gw0

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

    def gateway_history_health(self, slot='gw0'):
        """The gateway's /health ``history`` block ({ageMs, stale, cause, eventSeq, probedAgoMs}) or None."""
        health = self.f.http(slot, self.f.m['ports']['gateway_admin'], '/health')
        try:
            hist = (json.loads(health.get('body') or 'null') or {}).get('history')
        except (ValueError, AttributeError):
            return None
        return hist if isinstance(hist, dict) else None

    def history_causes(self):
        """gw0's history reads (its /metrics) by cause group, {} when unreadable (history_reads_by_group)."""
        return history_reads_by_group(self.f.http('gw0', self.f.m['ports']['gateway_admin'], '/metrics').get('body') or '')

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
        failing = [v.get('text') or k for k, v in lines.items() if not v['holds'] and k not in waiting]
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
        followed = ((before['slots'].get('pj0') or {}).get('source') or {}).get('member') if self.binary else None
        recordings = {'member': followed, 'before': journal_recordings(self.f.root, followed) if followed else None}
        witness = fault()
        self.sleep(self.p['STEP_SETTLE_S'])
        after = self.evidence(name, 'after', {'fault': witness})
        applied_after_fault = (self.applied(database) or {}).get('applied_seq')
        caught = self.wait_caught_up(database, self.p['PROJECTOR_CATCHUP_BOUND_S'])
        if followed:
            recordings['after'] = journal_recordings(self.f.root, followed)
        row = {'fault': witness, 'caught_up': caught, 'before_leader': before['leader'], 'after_leader': after['leader'],
               'applied_after_fault': applied_after_fault, 'recordings': recordings,
               'pj0_recording': [((r['slots'].get('pj0') or {}).get('recordings_walked') or {}).get('recording_id')
                                 for r in (before, after)]}
        if hit is not None:
            row['attached_before'] = hit
            row['hit_attached'] = (witness or {}).get('target') == hit
        self.record.setdefault('steps', {})[name] = row
        return row

    def exits_line(self, roles):
        """No container of ``roles`` exited except where the drill stopped it: each is running at the end, and every
        restart the fixture recorded found the exit code of the drill's own kill (137) or stop on that target."""
        f = self.f
        bad, last = [], {}
        for row in f.registry.get('faults') or []:
            target = row.get('target')
            if target not in roles:
                continue
            if row.get('kind') in ('kill', 'stop', 'exit', 'exec_kill'):
                last[target] = row
            elif row.get('kind') in ('restart', 'start'):
                cause = last.pop(target, None)
                code = row.get('exit_code')
                want = {137} if (cause or {}).get('kind') == 'kill' else {(cause or {}).get('exit_code'), 0, 143}
                if cause is None or code not in want:
                    bad.append({'target': target, 'exit_code': code, 'drill_action': (cause or {}).get('kind'),
                                'at_ns': row.get('at_ns')})
        state = {}
        for role in roles:
            cid = f.registry['containers'].get(role)
            if cid is None:
                continue
            s = f.inspect('container', cid)['State']
            state[role] = {'running': s['Running'], 'exit_code': None if s['Running'] else s['ExitCode']}
            if not s['Running']:
                bad.append({'target': role, 'exit_code': s['ExitCode'], 'running': False})
        return line(not bad, {'unexpected': bad[:10], 'state': state}, 'a process exited where the drill did not stop it')

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
        if self.binary:
            # an external driver keeps a stopped client this long (the hung writer of d2); embedded: no effect
            # (the driver refuses an unblock timeout at or below the client liveness: the unblock goes 15 s above it)
            f.projection_aeronmd_env = follow_driver_env(p)
            self.record['projection_aeronmd_env'] = dict(f.projection_aeronmd_env)
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
            member = self.attached('pj0') if self.binary else None
            killed = f.kill('pj0')
            started = self.clock()
            watch = OrphanWatch(self, member, 'pj1', started)
            while self.clock() - started < p['PROJECTOR_TAKEOVER_BOUND_S']:
                role = (f.projection_health('pj1') or {}).get('role')
                watch.sample(role)
                if role == 'writer':
                    takeover['s'] = round(self.clock() - started, 3)
                    break
                self.sleep(0.5)
            takeover['role'] = (f.projection_health('pj1') or {}).get('role')
            if takeover.get('s') is not None:
                watch.after_takeover(takeover['s'])
            self.record['orphan_after_writer_kill'] = watch.summary()
            restart = f.restart('pj0', ready_timeout=p['PROJECTOR_READY_BOUND_S'])
            return {'target': 'pj0', 'kill': killed.get('finished_at'), 'restart_started_at': restart.get('started_at'),
                    'takeover': dict(takeover)}
        steps['d'] = self.step('d_writer_kill', kill_writer)
        after_d = self.wait_baseline(baseline, p['HISTORY_PROJECTOR_ORPHAN_BOUND_MS'])
        hung = self.step('d2_hung_writer', self.hung_writer) if self.binary else None
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
        # On the binary the catch-up after (a) is its own line; from (b) on (the attached member's restart gives its
        # journal a successor recording) a projection behind the head is a projection that did not follow it
        after_b = ('b', 'c', 'd', 'e', 'f')
        early = [k for k in steps if not self.binary or k not in after_b]
        lines['caught_up_after_each_fault'] = line(all(steps[k]['caught_up']['caught_up'] for k in early)
                                                   and (self.binary or final['caught_up']),
                                                   {k: steps[k]['caught_up'] for k in early}, 'projection behind the core head')
        halts = [r for r in self.sources for h in r['slots'].values() if h.get('halt')]
        lines['never_halted'] = line(not halts, {'halts': halts[:5]}, 'projection halted')
        fills_after = self.pg_rows('r01_gateway', f'SELECT count(*) AS n FROM oe_fills WHERE event_seq > {int(head_after_a or 0)}')
        tap_fills_after = sum(1 for e in events if e['kind'] == 'FILL' and e['trade'] > 0 and e['seq'] > (head_after_a or 0))
        if self.binary:
            # the successor text only for a projection stuck after its member started a new journal recording
            # (successor_verdict); any other projection behind the head after (b) is `projection behind the core head`
            followed = {k: steps[k]['caught_up'] for k in after_b}
            verdict = successor_verdict({k: steps[k] for k in after_b})
            if verdict['text'] is None and not final['caught_up']:
                verdict = dict(verdict, stuck_step='final', text='projection behind the core head')
            self.record['successor'] = verdict
            lines['follows_successor_recording'] = line(verdict['text'] is None,
                                                        {'after': followed, 'final': final, 'verdict': verdict,
                                                         'journal_recordings': {k: steps[k]['recordings'] for k in after_b},
                                                         'pj0_recording': {k: steps[k]['pj0_recording'] for k in after_b}},
                                                        verdict['text'] or CONTROL_TEXT[self.name])
        lines['fills_after_me_restart_projected'] = line(fills_after[0]['n'] == tap_fills_after and tap_fills_after > 0,
                                                         {'projected': fills_after[0]['n'], 'oracle': tap_fills_after,
                                                          'head_after_me_restart': head_after_a},
                                                         'fills made after the ME restart are not projected',
                                                         inconclusive=tap_fills_after == 0)
        lines.update(self.projection_lines('r01_gateway', events, trades, head))
        if self.binary:
            for key in ('fills_after_me_restart_projected', 'projection_equals_oracle', 'events_dense_to_head'):
                consequence(lines[key], 'follows_successor_recording')
        lines['money_exact'] = self.money_line(money, order)
        lines['standby_took_over'] = line(takeover.get('s') is not None, {'takeover_s': takeover.get('s'),
                                                                          'bound_s': p['PROJECTOR_TAKEOVER_BOUND_S'],
                                                                          'pj1_role': takeover.get('role')},
                                          'standby did not take over inside its bound')
        for name, after in (('writer_kill', after_d), ('money_projector_kill', after_f)):
            detail = {k: after.get(k) for k in ('back', 'waited_ms', 'over', 'readers')}
            lines['replay_baseline_after_' + name] = line(after['count_back'], detail, ORPHAN_TEXT)
            lines['shm_baseline_after_' + name] = line(after['shm_back'], dict(detail, shm=after.get('shm')), ORPHAN_TEXT)
        if hung is not None:
            lines['orphan_stopped_after_hung_writer'] = self.hung_line(hung['fault'])
        lines['no_unexpected_exit'] = self.exits_line(('pj0', 'pj1', 'projector') + CORE_MEMBERS)
        switches = max((h.get('source_switches') or 0) for r in self.sources for h in r['slots'].values())
        lines['source_switched'] = line(switches >= 1, {'switches': switches}, 'no source switch',
                                        inconclusive=switches == 0)
        hit = [steps[k].get('hit_attached') for k in ('b', 'e')]
        lines['faults_hit_the_attached_member'] = line(all(hit), {'b': steps['b'].get('attached_before'),
                                                                  'e': steps['e'].get('attached_before'), 'hit': hit},
                                                       'a fault missed the attached member', inconclusive=not all(hit))
        if not self.binary:
            lines['follows_successor_recording'] = awaits(
                False, {'stand-in': 'reads the order-event ring over a cluster session; it follows no recording'},
                CONTROL_TEXT[self.name], 'the projector binary (Archive chain following)')
        return self.finish(lines)

    def hung_writer(self):
        """(d2) the writer hung, not dead: SIGSTOP the writing copy (an embedded driver stops with it; an external one keeps
        its client, so its replay stays served, for the driver's client liveness), the standby takes over and stops the
        replay the hung copy recorded. The member it read is sampled from the stop (OrphanWatch); then the hung copy is
        killed and started again (a standby)."""
        f, p = self.f, self.p
        roles = {s: (f.projection_health(s) or {}).get('role') for s in ('pj0', 'pj1')}
        writer = next((s for s, r in roles.items() if r == 'writer'), None)
        if writer is None:
            return {'skipped': 'no writer', 'roles': roles}
        other = 'pj1' if writer == 'pj0' else 'pj0'
        member = self.attached(writer)
        frozen = f.freeze_main(writer, duration_s=p['PROJECTOR_TAKEOVER_BOUND_S'] + p['ORPHAN_WATCH_S'])
        started = self.clock()
        watch = OrphanWatch(self, member, other, started)
        takeover = None
        while self.clock() - started < p['PROJECTOR_TAKEOVER_BOUND_S']:
            role = (f.projection_health(other) or {}).get('role')
            watch.sample(role)
            if role == 'writer':
                takeover = round(self.clock() - started, 3)
                break
            self.sleep(p['ORPHAN_SAMPLE_MS'] / 1000)
        if takeover is not None:
            watch.after_takeover(takeover)
        killed = f.kill(writer)
        restart = f.restart(writer, ready_timeout=p['PROJECTOR_READY_BOUND_S'])
        return {'target': writer, 'standby': other, 'member': member, 'mode': self.f.m['artifacts'][self.f.slot_artifact(writer)]['driver'],
                'sigstop': frozen.get('at_ns'), 'takeover_s': takeover, 'kill': killed.get('finished_at'),
                'restart_started_at': restart.get('started_at'), 'orphan': watch.summary()}

    def hung_line(self, hung):
        """The hung writer's recorded replay is gone ORPHAN_STOP_BOUND_MS after the takeover. Judged only when it was still
        served at the takeover (the archive had not ended it: an external driver); an embedded copy's replay ends with its
        stopped driver and the line records that (holds, not exercised); on an external driver an orphan already gone at
        the takeover leaves the rule untested (INCONCLUSIVE)."""
        p = self.p
        o = (hung or {}).get('orphan') or {}
        detail = {k: (hung or {}).get(k) for k in ('target', 'member', 'mode', 'takeover_s', 'skipped')}
        # the stop rule is judged under the drill's external driver client liveness (the slot's staged aeronmd)
        detail.update(orphan=o, bound_ms=p['ORPHAN_STOP_BOUND_MS'],
                      driver_client_liveness=(self.record.get('projection_aeronmd_env') or {}).get('AERON_CLIENT_LIVENESS_TIMEOUT')
                      if (hung or {}).get('mode') == 'external' else None)
        if not hung or hung.get('skipped') or hung.get('takeover_s') is None or not hung.get('member'):
            return line(False, detail, 'standby did not take over from the hung writer', inconclusive=True)
        if not o.get('present_at_takeover'):
            external = hung.get('mode') == 'external'
            return line(not external, dict(detail, exercised=False), ORPHAN_TEXT, inconclusive=external)
        gone = o.get('gone_after_takeover_ms')
        return line(gone is not None and gone <= p['ORPHAN_STOP_BOUND_MS'], dict(detail, exercised=True), ORPHAN_TEXT)


class OrphanWatch:
    """The history replays one core member serves beyond what the other running copy reports open on it, sampled every
    ORPHAN_SAMPLE_MS from a writer's kill or stop: [t_s, the other copy's role, served, allowed]. ``gone_s`` is the first
    sample from the takeover on with none beyond; after the takeover the watch goes on until then or ORPHAN_WATCH_S."""

    def __init__(self, drill, member, other, started):
        self.d, self.member, self.other, self.started = drill, member, other, started
        self.samples, self.gone_s, self.takeover_s, self.present_at_takeover = [], None, None, None

    def sample(self, role=None):
        if not self.member or not self.d.binary:
            return None
        d = self.d
        health = d.f.projection_health(self.other) or {}
        probe = d.f.replay_count(self.member, (HISTORY_PROJECTOR_REPLAY_STREAM,))
        served = ((probe.get('replays') or {}).get(str(HISTORY_PROJECTOR_REPLAY_STREAM))) if 'error' not in probe else None
        allowed = sum(n for m, n in replay_readers({self.other: health}) if m == self.member)
        t = round(d.clock() - self.started, 3)
        self.samples.append([t, role if role is not None else health.get('role'), served, allowed])
        beyond = served is not None and served > allowed
        # the end of the orphan counts from the takeover on (before it a moment of equality is not an end)
        if served is not None and not beyond and self.gone_s is None and self.takeover_s is not None:
            self.gone_s = t
        return beyond

    def after_takeover(self, takeover_s):
        self.takeover_s = takeover_s
        d, p = self.d, self.d.p
        beyond = self.sample()
        self.present_at_takeover = bool(beyond) and self.gone_s is None
        if not self.present_at_takeover:
            return
        while d.clock() - self.started - takeover_s < p['ORPHAN_WATCH_S']:
            if not self.sample():
                if self.samples[-1][2] is not None:
                    break
            d.sleep(p['ORPHAN_SAMPLE_MS'] / 1000)

    def summary(self):
        gone_after = None
        if self.present_at_takeover and self.samples and self.samples[-1][2] is not None \
                and self.samples[-1][2] <= self.samples[-1][3]:
            gone_after = int((self.samples[-1][0] - self.takeover_s) * 1000)
        return {'member': self.member, 'gone_s': self.gone_s, 'takeover_s': self.takeover_s,
                'present_at_takeover': self.present_at_takeover, 'gone_after_takeover_ms': gone_after,
                'samples': self.samples[-80:]}


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
                                            'restart_started_at': f.restart('pj0', ready_timeout=p['PROJECTOR_READY_BOUND_S']).get('started_at')})
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
        members = {'A': self.attached('pj0'), 'B': self.attached('pj1')}
        c = self.c_run(head, members)
        members['C'] = c.get('member')
        self.record['members'] = members
        dumps['C'] = self.dump('r01_history_b', 'C')
        money, order, events, trades = self.oracle(requests)
        lines = {}
        lines['load_finished'] = line(done, {'requests': len(rows)}, 'load did not finish inside its bound', inconclusive=not done)
        lines['all_caught_up'] = line(a_state['caught_up'] and b_state['caught_up'] and c['caught_up']['caught_up'],
                                      {'A': a_state, 'B': b_state, 'C': c['caught_up']}, 'projection behind the core head')
        differ = sorted(set(projection_dump.equal(dumps['A'], dumps['B'])) | set(projection_dump.equal(dumps['A'], dumps['C'])))
        lines['dumps_equal'] = line(not differ, {name: {t: r.get('sha256') for t, r in d.items()} for name, d in dumps.items()}
                                    | {'differ': differ}, CONTROL_TEXT[self.name])
        # the same tables on their fixed columns alone (a column beyond the list is the only thing allowed to differ in a
        # control that adds one): equal in every run
        fixed = sorted(set(projection_dump.equal(dumps['A'], dumps['B'], fixed=True))
                       | set(projection_dump.equal(dumps['A'], dumps['C'], fixed=True)))
        lines['dumps_equal_on_fixed_columns'] = line(not fixed, {'differ': fixed,
                                                                 'extra_columns': {n: {t: r.get('extra_columns') for t, r in d.items()
                                                                                       if r.get('extra_columns')}
                                                                                   for n, d in dumps.items()}},
                                                     'projection dump differs in its fixed columns')
        lines.update(self.projection_lines('r01_gateway', events, trades, head))
        if self.binary:
            # a projection with a missing journalSeq cannot equal the oracle; its own line names it
            consequence(lines['projection_equals_oracle'], 'events_dense_to_head')
        lines['money_exact'] = self.money_line(money, order)
        lines['cprime_beats_after_catch_up'] = line(cprime.get('beat_before_catch_up') is False,
                                                    {k: cprime.get(k) for k in ('kill_landed_before_catch_up', 'beat_before_catch_up',
                                                                                'backlog', 'killed')},
                                                    'second projection beat before it caught up',
                                                    inconclusive=not cprime.get('kill_landed_before_catch_up'))
        lines['c_restarted_on_the_way'] = line(c['kills'] == p['C_KILLS'], {'kills': c['kills'], 'wanted': p['C_KILLS']},
                                               'C was not killed and restarted on its way', inconclusive=c['kills'] < p['C_KILLS'])
        if self.binary:
            known = [members.get(k) for k in ('A', 'B', 'C')]
            # C reads the one member neither A nor B ended on; when A and B did not leave exactly one, C had none to
            # read alone and the line cannot be judged
            lines['three_different_members'] = line(None not in known and len(set(known)) == 3,
                                                    {'members': members, 'c_configured': c.get('configured_member')},
                                                    'projections were not read from three members',
                                                    inconclusive=None in known or c.get('configured_member') is None)
            d = c.get('gateway') or {}
            causes = d.get('cause_before_beat') or {}
            lines['gateway_on_rebuilding_database'] = line(
                d.get('before_beat_all_503') is True and d.get('fresh_after_beat') is True
                and causes.get('heartbeat', 0) > 0 and not [k for k, v in causes.items() if k != 'heartbeat' and v],
                d, 'rebuilding history served as complete', inconclusive=not d.get('reads_before_beat'))
        else:
            lines['three_different_members'] = awaits(
                False, {'stand-in': 'reads the cluster session; it cannot be pointed at one member\'s archive'},
                'projections were not read from three members', 'the projector binary (one Archive source per projection)')
            lines['gateway_on_rebuilding_database'] = awaits(
                c.get('no_heartbeat_row_before_first_beat') is True, {k: c.get(k) for k in ('no_heartbeat_row_before_first_beat',
                                                                                            'heartbeat_rows_seen')},
                'rebuilding history served as complete', 'gw0 pointed at the second database (the heartbeat view itself is read)')
        # The fixture runs one money projector: its tables are dumped for A only (recorded, never judged)
        lines['money_projection_compared'] = awaits(
            bool(money_dump), {'A': {t: r.get('sha256') for t, r in money_dump.items()}},
            'money projection dump differs', 'a second and third money projection (one money projector in the fixture)')
        return self.finish(lines)

    def wait_schema(self, database, bound_s):
        """Until the projection's heartbeat view answers in ``database`` (the projector applied its schema): {'s', 'rows'}
        or None when it did not inside ``bound_s``."""
        started = self.clock()
        while self.clock() - started < bound_s:
            try:
                rows = self.pg_rows(database, 'SELECT applied_event_seq FROM gateway_history_heartbeat_v1')
                return {'s': round(self.clock() - started, 3), 'rows': len(rows)}
            except (Inconclusive, subprocess.CalledProcessError, ValueError):
                self.sleep(0.05)
        return None

    def c_prime(self):
        """pj1 on an empty database once the core holds the backlog; its attached member killed once during the catch-up."""
        f, p = self.f, self.p
        started = self.clock()
        while (self.head() or 0) < p['CPRIME_BACKLOG_EVENTS'] and self.clock() - started < p['PROJECTION_LOAD_BOUND_S']:
            self.sleep(p['POLL_S'])
        backlog = self.head()
        if self.binary:
            # B reads members other than A's: pj1 lists the two members pj0 is not attached to (it switches between
            # them when its attached one is killed)
            a = self.attached('pj0')
            f.projection_sources = dict(f.projection_sources or {}, pj1=[m for m in CORE_MEMBERS if m != a])
        f.start_projection_slots(['pj1'])
        self.evidence('cprime', 'started', {'backlog': backlog, 'sources': (f.projection_sources or {}).get('pj1')})
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

    def c_run(self, head, members=None):
        """C: pj1 again into an empty database, killed and restarted ``C_KILLS`` times on the way; the heartbeat view of
        that database read throughout (no row until the first beat). On the binary C reads the third member (the one
        neither A nor B ended on) and gw0 is pointed at that database for the run (D)."""
        f, p = self.f, self.p
        member = None
        f.stop('pj1')
        if self.binary:
            used = {m for m in (members or {}).values() if m}
            rest = [m for m in CORE_MEMBERS if m not in used]
            member = rest[0] if len(rest) == 1 else None
            f.projection_sources = dict(f.projection_sources or {}, pj1=[member] if member else list(CORE_MEMBERS))
            f.kill('gw0')
        f.recreate_projection_database('r01_history_b')
        schema = None
        if self.binary:
            # gw0 first, on the empty database, so its reads span pj1's whole rebuild; pj1 commits C_BATCH_EVENTS per
            # batch (its rebuild outruns the kills and the reads at the default batch); then its schema, then the reads
            f.gateway_history_database = dict(f.gateway_history_database or {}, gw0='r01_history_b')
            f.respawn_slot('gw0')
            f.projector_env_overrides = dict(getattr(f, 'projector_env_overrides', None) or {},
                                             pj1={'HISTORY_PROJECTOR_BATCH_EVENTS': p['C_BATCH_EVENTS']})
            self.record['c_projector_settings'] = {'pj1': {'HISTORY_PROJECTOR_BATCH_EVENTS': p['C_BATCH_EVENTS']}}
            f.respawn_slot('pj1')
            schema = self.wait_schema('r01_history_b', p['C_SCHEMA_BOUND_S'])
        else:
            f.restart('pj1', ready_timeout=p['PROJECTOR_READY_BOUND_S'])
        self.evidence('C', 'started', {'member': member, 'schema': schema})
        gateway = {'reads_before_beat': 0, 'statuses_before_beat': [], 'causes': [], 'after_beat': []} if self.binary else None
        # gw0's history reads by cause group (its metrics) at the start and after the last read before the first beat
        reads_at_start = self.history_causes() if self.binary else None
        reads_before_beat = reads_at_start
        user = self.users()[0]
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
            if kills < p['C_KILLS'] and applied >= next_kill and applied < head:
                f.kill('pj1')
                f.restart('pj1', ready_timeout=p['PROJECTOR_READY_BOUND_S'])
                kills += 1
                next_kill = applied + p['C_KILL_EVERY_EVENTS']
                self.evidence('C', f'kill-{kills}', {'applied': applied})
            if gateway is not None:
                answer = self.history(user, '/api/v2/orders/history?limit=5')
                hist = self.gateway_history_health('gw0') or {}
                if not beat and not seen:
                    try:
                        beat_now = self.pg_rows('r01_history_b', 'SELECT applied_event_seq FROM gateway_history_heartbeat_v1')
                    except Inconclusive:
                        beat_now = None
                    if not beat_now:
                        # still no row after the read: the read was answered before the first beat
                        gateway['reads_before_beat'] += 1
                        gateway['statuses_before_beat'].append(answer['status'])
                        gateway['causes'].append(hist.get('cause'))
                        reads_before_beat = self.history_causes()
                elif len(gateway['after_beat']) < 20:
                    gateway['after_beat'].append([answer['status'], (self.as_of(answer) or {}).get('stale')])
            if beat:
                seen.append(applied)
                if applied < head:
                    rows_before_beat = False
            if applied >= head:
                break
            self.sleep(0.5)
        caught = self.wait_caught_up('r01_history_b', p['PROJECTOR_CATCHUP_BOUND_S'], head=head)
        self.evidence('C', 'caught_up', {'caught_up': caught})
        # the member C read: pj1's /health once it reports one (a copy restarted at the head attaches a moment later)
        attached, polled = None, self.clock()
        while self.binary and attached is None and self.clock() - polled < p['PROJECTOR_CATCHUP_BOUND_S']:
            attached = self.attached('pj1')
            if attached is None:
                self.sleep(p['POLL_S'])
        out = {'kills': kills, 'caught_up': caught, 'no_heartbeat_row_before_first_beat': rows_before_beat,
               'heartbeat_rows_seen': len(seen), 'member': attached, 'configured_member': member, 'schema': schema}
        if gateway is not None:
            # D: after the first beat, a fresh page within the catch-up bound
            started = self.clock()
            while not any(st == 200 and stale is False for st, stale in gateway['after_beat']) \
                    and self.clock() - started < p['PROJECTOR_CATCHUP_BOUND_S']:
                answer = self.history(user, '/api/v2/orders/history?limit=5')
                gateway['after_beat'].append([answer['status'], (self.as_of(answer) or {}).get('stale')])
                self.sleep(p['SAMPLE_MS'] / 1000)
            delta = {k: v - (reads_at_start or {}).get(k, 0) for k, v in (reads_before_beat or {}).items()}
            gateway.update(before_beat_all_503=bool(gateway['statuses_before_beat'])
                           and all(st == 503 for st in gateway['statuses_before_beat']),
                           cause_before_beat={k: v for k, v in delta.items() if v},
                           health_causes_before_beat=sorted({c for c in gateway['causes'] if c}),
                           fresh_after_beat=any(st == 200 and stale is False for st, stale in gateway['after_beat']))
            gateway['statuses_before_beat'] = gateway['statuses_before_beat'][-20:]
            gateway['causes'] = gateway['causes'][-20:]
            out['gateway'] = gateway
        self.record['C'] = out
        return out


# ------------------------------------------------------------------ history-freshness

class HistoryFreshness(ProjectionDrill):
    pg_causes_before = pg_causes_after = None

    def run(self):
        f, p = self.f, self.p
        self.extra = []
        users = self.users()
        # the gateway's history stale bound and /health probe cadence for this drill (recorded): a freeze below the
        # projector's driver bound then reads stale on gw0
        f.gateway_env_overrides = freshness_gateway_settings(p)
        self.record['gateway_history_settings'] = f.gateway_env_overrides
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
        lines['a_stale_false'] = awaits(bool(stale) and all(x is False for x in stale), {'stale': stale}, STALE_LABEL_TEXT,
                                        'the gateway\'s stale label (asOf.stale)', judged=self.binary)
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
        closed = health = None
        while self.clock() - frozen_at < p['FREEZE_S']:
            reads.append(self.history(user, '/api/v2/orders/history?limit=5'))
            state = self.applied('r01_gateway') or {}
            beat_ages.append([round(self.clock() - frozen_at, 3), state.get('beat_age_ms')])
            if self.clock() - frozen_at >= stale_bound_s(p) + p['SAMPLE_MS'] / 1000:
                # the closed order once the heartbeat is past stale, and gw0's /health until it shows stale (its history
                # block refreshes at the gateway's own probe cadence), all inside the freeze
                if closed is None and order:
                    closed = self.history(user, f'/api/v2/orders/{order}')
                if not health_stale(health):
                    health = self.f.http('gw0', self.f.m['ports']['gateway_admin'], '/health')
            self.sleep(p['SAMPLE_MS'] / 1000)
        if closed is None and order:
            closed = self.history(user, f'/api/v2/orders/{order}')
        if health is None:
            health = self.f.http('gw0', self.f.m['ports']['gateway_admin'], '/health')
        stale_at = next((t for t, age in beat_ages if age is not None and age > p['HISTORY_STALE_MS']), None)
        self.record['freeze'] = {'frozen': frozen, 'placed': placed.get('status'), 'order': order,
                                 'cancelled': (cancelled or {}).get('status'), 'beat_ages': beat_ages,
                                 'stale_after_s': stale_at, 'closed_order': {k: (closed or {}).get(k) for k in ('status', 'body')}}
        thaw = f.thaw_main('pj0')
        thawed_at = self.clock()
        frozen_for_s = round(thawed_at - frozen_at, 3)
        after_thaw = self.thaw_branch(thawed_at)
        self.record['freeze'].update(frozen_for_s=frozen_for_s, after_thaw=after_thaw)
        self.evidence('b_freeze', 'after', {'fault': frozen, 'stale_after_s': stale_at, 'after_thaw': after_thaw})
        out['c_thaw_resumes_below_the_driver_bound'] = thaw_line(dict(after_thaw, frozen_for_s=frozen_for_s,
                                                                      driver_bound_ms=p['PROJECTOR_DRIVER_BOUND_MS']), long=False)
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
                                      'the gateway\'s stale label (asOf.stale)', judged=self.binary,
                                      inconclusive=stale_at is None)
        hist = None
        try:
            hist = (json.loads(health.get('body') or 'null') or {}).get('history')
        except ValueError:
            pass
        out['b_gateway_health_stale'] = awaits(isinstance(hist, dict) and hist.get('stale') is True, {'history': hist},
                                               STALE_LABEL_TEXT, 'the gateway\'s /health history block', judged=self.binary,
                                               inconclusive=stale_at is None)
        # (c) thawed: the order is served
        caught = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'])
        served = self.history(user, f'/api/v2/orders/{order}') if order else None
        out['c_order_served_after_thaw'] = line((served or {}).get('status') == 200 and caught['caught_up'],
                                                {'status': (served or {}).get('status'), 'caught_up': caught, 'thaw': thaw},
                                                'closed order not served after the thaw', inconclusive=not order)
        # (c) stale false again: history pages read until one is fresh, inside the stale bound after the catch-up
        pages, started = [], self.clock()
        while True:
            page = self.history(user, '/api/v2/orders/history?limit=5')
            pages.append([page['status'], fresh_label(self.as_of(page))])
            if pages[-1][1] in (False, 'missing') or self.clock() - started >= stale_bound_s(p):
                break
            self.sleep(p['SAMPLE_MS'] / 1000)
        label = pages[-1][1]
        out['c_stale_false_after_thaw'] = awaits(pages[-1][0] == 200 and label is False,
                                                 {'pages': pages[-10:], 'bound_s': stale_bound_s(p), 'caught_up': caught['caught_up']},
                                                 STALE_LABEL_TEXT if label == 'missing' else 'history still stale after the thaw',
                                                 'the gateway\'s stale label (asOf.stale)', judged=self.binary,
                                                 inconclusive=not caught['caught_up'])
        out.update(self.long_freeze(user))
        return out

    def long_freeze(self, user):
        """(c) above the driver bound: SIGSTOP pj0 for FREEZE_LONG_S, SIGCONT; it resumes or exits 70 on its driver
        rule (F3b) and is started again; then it catches up and a history page reads fresh again."""
        f, p = self.f, self.p
        frozen = f.freeze_main('pj0', duration_s=p['FREEZE_LONG_S'])
        frozen_at = self.clock()
        self.sleep(p['FREEZE_LONG_S'])
        f.thaw_main('pj0')
        thawed_at = self.clock()
        after_thaw = self.thaw_branch(thawed_at)
        caught = self.wait_caught_up('r01_gateway', p['PROJECTOR_CATCHUP_BOUND_S'])
        page = self.history(user, '/api/v2/orders/history?limit=5')
        label = fresh_label(self.as_of(page))
        detail = dict(after_thaw, frozen_for_s=round(thawed_at - frozen_at, 3), driver_bound_ms=p['PROJECTOR_DRIVER_BOUND_MS'])
        self.record['long_freeze'] = dict(detail, fault=frozen, caught_up=caught, page=[page.get('status'), label])
        self.evidence('c_long_freeze', 'after', {'after_thaw': after_thaw, 'caught_up': caught['caught_up']})
        return {
            'c_long_thaw_exit_only_on_the_driver_rule': thaw_line(detail, long=True),
            'c_long_thaw_fresh_again': awaits(page.get('status') == 200 and label is False and caught['caught_up'],
                                              {'page': [page.get('status'), label], 'caught_up': caught['caught_up']},
                                              STALE_LABEL_TEXT if label == 'missing' else 'history still stale after the thaw',
                                              'the gateway\'s stale label (asOf.stale)', judged=self.binary,
                                              inconclusive=not caught['caught_up'])}

    def thaw_branch(self, thawed_at):
        """After the SIGCONT of pj0: still running after THAW_EXIT_WAIT_S ('running'), or exited 70 on its driver rule
        (driver_rule_exit) and was started again as its supervisor would ('restarted'); any other exit is 'exited' (the
        line fails)."""
        f, p = self.f, self.p
        cid = f.registry['containers']['pj0']
        while self.clock() - thawed_at < p['THAW_EXIT_WAIT_S']:
            state = f.inspect('container', cid)['State']
            if not state['Running']:
                break
            self.sleep(0.25)
        state = f.inspect('container', cid)['State']
        if state['Running']:
            f.close_fault('pj0')
            return {'outcome': 'running'}
        logs = f.command(['docker', 'logs', '--tail', '20', cid], check=False)
        exit_line = next((l for l in reversed((logs.stdout + logs.stderr).splitlines())
                          if 'exit 70:' in l or 'exiting 70:' in l), None)
        out = {'exit_code': state['ExitCode'], 'exit_line': (exit_line or '')[-400:]}
        if state['ExitCode'] != 70 or not exit_line or not driver_rule_exit(exit_line):
            return dict(out, outcome='exited')
        restart = f.restart('pj0', ready_timeout=p['PROJECTOR_READY_BOUND_S'])
        return dict(out, outcome='restarted', restart_started_at=restart.get('started_at'))

    def cut_member(self):
        f, p = self.f, self.p
        member = self.attached('pj0')
        if not member:
            return {'d_member_cut': line(False, {}, 'no attached member to cut', inconclusive=True)}
        before = self.evidence('d_cut', 'before', {'member': member})
        beats0 = (f.projection_health('pj0') or {}).get('beats')
        for target, rule in isolation_arguments(f.m, member, 'add'):
            f.netfilter(target, rule)
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
                                'head': h.get('head_seq'), 'beats': h.get('beats'), 'switches': h.get('source_switches'),
                                'beat_at_us': self.beat_at_us() if self.binary else None})
                self.sleep(p['SAMPLE_MS'] / 1000)
        finally:
            for target, rule in isolation_arguments(f.m, member, 'delete'):
                try:
                    f.netfilter(target, rule)
                except Inconclusive as error:
                    # a member that exited during the cut has no rule left to delete (its exit is recorded below)
                    self.record.setdefault('cut_heal_errors', []).append({'target': target, 'error': str(error)})
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
        if self.binary:
            # no beat written while the projection was held on the cut member: beat_at (the database's, whatever wrote
            # it) does not move between the first and the last such probe; then a switch away and fresh history again
            # a failed database read is no value: fewer than two read values leave the line inconclusive
            beat_at = [s['beat_at_us'] for s in held if s['beat_at_us'] is not None]
            moved = len(set(beat_at)) > 1 if len(beat_at) >= 2 else None
            later = [s for s in samples if held and s['t'] > held[-1]['t']]
            left = any(s['source'] not in (None, member) for s in later) or (
                (samples[-1].get('switches') or 0) > (samples[0].get('switches') or 0) if samples else False)
            fresh = self.history(self.users()[0], '/api/v2/orders/history?limit=5') if left else None
            fresh_label_now = fresh_label(self.as_of(fresh)) if fresh else None
            fresh_ok = bool(fresh) and fresh.get('status') == 200 and fresh_label_now is False
            return {
                'd_cluster_committed_without_the_cut_member': line(bool(others) and advanced,
                                                                   {'member': member, 'leaders_seen': sorted(set(others)),
                                                                    'survivor_commit_first_last': [commits[:1], commits[-1:]],
                                                                    'rejoin': {k: v for k, v in rejoin.items() if k != 'ready_body'},
                                                                    'cut_member_restarted_by_the_drill': 'restarted' in rejoin},
                                                                   'the cluster did not go on without the cut member'),
                'd_no_beat_while_attached_to_the_cut_member': line(
                    moved is False, {'probes_with_head_above_applied_on_cut_member': len(held),
                                     'beat_at_us_first_last': [beat_at[:1], beat_at[-1:]], 'beats_before': beats0},
                    CONTROL_TEXT[self.name], inconclusive=moved is None),
                'd_switch_then_fresh': line(left and fresh_ok, {'left_the_cut_member': left,
                                                                'fresh_read': {k: (fresh or {}).get(k) for k in ('status',)}
                                                                | {'asOf': self.as_of(fresh or {})}},
                                            STALE_LABEL_TEXT if fresh_label_now == 'missing'
                                            else 'attached to a lagging source while another was current', inconclusive=not held),
            }
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
        polled, stop = [], threading.Event()

        def poll_beat_at():
            # the database's beat_at from the host every WATCH_MS while the watcher runs (a change is a beat written),
            # each read stamped with the host clock at its start
            while not stop.is_set():
                at = time.time()
                polled.append([at, self.beat_at_us()])
                stop.wait(p['WATCH_MS'] / 1000)
        poller = threading.Thread(target=poll_beat_at, daemon=True) if self.binary else None
        # the watcher runs from WATCH_LEAD_S before the kill, so the whole window from the leader's death (its
        # container's FinishedAt, on the host clock the watcher's rows carry) to a survivor leading is observed
        held = {}

        def watch_window():
            held['r'] = f.execute('probe', ['python3', '-I', '-c', WINDOW_WATCH], input=json.dumps(plan), timeout=90, check=False)
        watcher = threading.Thread(target=watch_window, daemon=True)
        watcher.start()
        if poller:
            poller.start()
        self.sleep(p['WATCH_LEAD_S'])
        killed = f.kill(leader)
        watcher.join(95)
        stop.set()
        if poller:
            poller.join(5)
        r = held.get('r')
        lines = [l for l in ((r.stdout if r else '') or '').splitlines() if l.startswith('{')]
        watch = json.loads(lines[-1]) if lines else {'error': ((r.stderr if r else 'the watcher did not finish') or '')[-200:]}
        restart = f.restart(leader, ready_timeout=180)
        death = finished_at_epoch(killed.get('finished_at'))
        rows, window = leaderless_rows(watch.get('rows') or [], death)
        first = rows[0] if rows else {}
        last = rows[-1] if rows else {}
        beats_in = (last.get('beats') or 0) - (first.get('beats') if first.get('beats') is not None else (h0.get('beats') or 0))
        # a probe unanswered inside the window: one that failed, or one sent and still waiting while no survivor led
        unanswered = (last.get('unanswered') or 0) - (h0.get('probe_unanswered') or 0)
        unanswered += 1 if any(r.get('outstanding') and not r.get('leaders') for r in rows) else 0
        db_beats = None
        if self.binary:
            # the binary shows no probe counter: no answered probe across the window (answered = offered, refused,
            # pending and dropped beat candidates) while it spans two head probes is its unanswered-probe witness; and
            # a beat is any change of the database's beat_at polled inside the window, whatever wrote it
            answered = [r.get('answered') for r in rows if r.get('answered') is not None]
            unanswered = int(bool(answered) and answered[0] == answered[-1] and (window or 0) * 1000 >= 2 * BINARY_HEAD_PROBE_MS)
            # a read started from the leader's death to the end of the window is inside it (a beat right at its end is
            # never counted in it)
            inside = [b for w, b in polled if death is not None and death <= w <= death + (window or 0) and b is not None]
            db_beats = len(set(inside)) - 1 if inside else None
            beats_in = max(beats_in, db_beats or 0)
        self.record['leaderless'] = {'killed': leader, 'kill': killed.get('finished_at'), 'window_s': window,
                                     'watch_rows_before_death': len(watch.get('rows') or []) - len(rows),
                                     'db_beats_in_window': db_beats,
                                     'beat_at_polled': [[round(w - death, 3) if death else None, b] for w, b in polled][-60:],
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
        self.pg_causes_before = self.history_causes() if self.binary else None
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
        self.pg_causes_after = self.history_causes() if self.binary else None
        statuses = [r['status'] for r in reads]
        codes = [((r.get('json') or {}) if isinstance(r.get('json'), dict) else {}).get('cause') for r in reads]
        placed = [o['status'] for o in orders]
        self.record['pg_down'] = {'history_statuses': statuses, 'causes': codes, 'order_statuses': placed,
                                  'bodies': [r.get('body', '')[:160] for r in reads[:3]]}
        self.evidence('f_pg_down', 'after', {'history_statuses': statuses, 'order_statuses': placed})
        return {
            'f_history_503_while_pg_down': line(bool(statuses) and all(s == 503 for s in statuses), {'statuses': statuses},
                                                'history answered other than 503 while PostgreSQL was down'),
            'f_cause_pg': self.cause_pg_line(codes),
            'f_order_entry_unaffected': line(bool(placed) and all(s == 201 for s in placed), {'statuses': placed},
                                             'order entry failed while PostgreSQL was down'),
        }

    def cause_pg_line(self, codes):
        """(f) cause pg. A 503 body names no cause (the gateway's history contract): on the binary the cause is read
        from gw0's history reads counter by cause, before and after the outage (``gateway_history_reads_total``)."""
        if not self.binary:
            return awaits(bool(codes) and all(c == 'pg' for c in codes), {'causes': codes}, 'history 503 without cause pg',
                          'the gateway\'s history cause field')
        delta = {k: v - (self.pg_causes_before or {}).get(k, 0) for k, v in (self.pg_causes_after or {}).items()}
        delta = {k: v for k, v in delta.items() if v}
        return line(delta.get('pg', 0) > 0, {'reads_by_cause_during_outage': delta}, 'history 503 without cause pg',
                    inconclusive=not self.pg_causes_after)

    def slow_member_binary(self, member):
        """The same baseline and slow spans on the binary, sampled every SAMPLE_MS: its source, BEHIND and switch
        counts, lag in events, and the database's beat_at. (g) holds when it switched away from the slowed member inside
        the window and a beat was written after that switch."""
        f, p = self.f, self.p
        samples = []

        def sample(phase, span):
            started = self.clock()
            while self.clock() - started < span:
                h = f.projection_health('pj0') or {}
                samples.append({'phase': phase, 't': round(self.clock() - started, 3), 'source': (h.get('source') or {}).get('member'),
                                'behind': h.get('behind'), 'switches': h.get('source_switches'), 'lag_events': h.get('lag_events'),
                                'beat_at_us': self.beat_at_us()})
                self.sleep(p['SAMPLE_MS'] / 1000)
        sample('baseline', p['SLOW_S'])
        found = self.replay_port(member)
        if found.get('replay_port') is None:
            self.record['slow'] = {'member': member, 'replay_port': found, 'samples': samples[-90:]}
            return {'g_slow_member_method': line(False, {'replay_port': found}, 'no replay port from the member found',
                                                 inconclusive=True)}
        port = found['replay_port']
        for rule in slow_rate_arguments(f.m, member, 'add', p['SLOW_KEEP_EVERY'], port):
            f.netfilter('pj0', rule)
        try:
            sample('slow', p['SLOW_S'])
            listing = f.netfilter('pj0', slow_arguments(f.m, member, 'pj0', 'counters', p['SLOW_DROP_PERCENT']))
        finally:
            for rule in slow_rate_arguments(f.m, member, 'delete', p['SLOW_KEEP_EVERY'], port):
                f.netfilter('pj0', rule)
        sample('after', p['SLOW_S'])
        dropped = dropped_packets(listing, f.m['nodes'][member])
        witness = slow_witness_binary(samples, member, p['SLOW_LAG_SAMPLES'], dropped)
        switch = g_switch_verdict(samples, member, self.left_lines('pj0'))
        self.record['slow'] = {'member': member, 'keep_every': p['SLOW_KEEP_EVERY'], 'seconds': p['SLOW_S'], 'replay_port': found,
                               'dropped_packets': dropped, 'witness': witness, **switch['detail'], 'samples': samples[-90:]}
        self.evidence('g_slow', 'after', {'slow': {k: v for k, v in self.record['slow'].items() if k != 'samples'}})
        detail = {k: v for k, v in self.record['slow'].items() if k != 'samples'}
        if not dropped:
            method = line(False, detail, 'the slow-member rule dropped nothing')
        else:
            method = line(bool(witness['slowed']), detail, 'the slow-member method did not slow the member',
                          inconclusive=witness['slowed'] is None)
        switch['detail'] = dict(detail, **switch['detail'])
        return {'g_slow_member_method': method, 'g_switch_and_beats_resume': consequence(switch, 'g_slow_member_method')}

    def replay_port(self, member):
        """pj0's port the member's replay arrives on: every UDP port bound in pj0's namespace (but the cluster
        session's response port) gets a counting rule for the member's packets for REPLAY_PORT_PROBE_S under the flow;
        the busiest is the replay (its archive control responses come a few a second). The counts are recorded."""
        f, p = self.f, self.p
        text = f.execute('pj0', ['cat', '/proc/net/udp'], check=False).stdout
        ports = [x for x in udp_ports(text) if x != f.PROJECTOR_RESPONSE_PORT]
        source = f.m['nodes'][member]
        rule = lambda flag, port: ['-w', '2', flag, 'INPUT', '-p', 'udp', '-s', source, '--dport', str(port), '-j', 'ACCEPT']
        added = []
        try:
            for port in ports:
                f.netfilter('pj0', rule('-A', port))
                added.append(port)
            self.sleep(p['REPLAY_PORT_PROBE_S'])
            counts = port_counts(f.netfilter('pj0', ['-w', '2', '-L', 'INPUT', '-n', '-v', '-x']), source)
        finally:
            for port in added:
                f.netfilter('pj0', rule('-D', port))
        busiest = max(counts.items(), key=lambda kv: kv[1], default=(None, 0))
        return {'ports': ports, 'counts': counts, 'replay_port': busiest[0] if busiest[1] > 0 else None,
                'probe_s': p['REPLAY_PORT_PROBE_S']}

    def left_lines(self, slot, tail=400):
        """The projector's own leave lines (``source ... left: <reason>``) from the slot's container log."""
        cid = (self.f.registry.get('containers') or {}).get(slot)
        if not cid:
            return []
        logs = self.f.command(['docker', 'logs', '--tail', str(tail), cid], check=False)
        return [l[-300:] for l in (logs.stdout + logs.stderr).splitlines() if ' left: ' in l]

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
        if self.binary:
            return self.slow_member_binary(member)
        b0 = self.counters('pj0')
        self.sleep(p['SLOW_S'])
        h0 = self.counters('pj0')
        f.netfilter('pj0', slow_arguments(f.m, member, 'pj0', 'add', p['SLOW_DROP_PERCENT']))
        try:
            self.sleep(p['SLOW_S'])
            listing = f.netfilter('pj0', slow_arguments(f.m, member, 'pj0', 'counters', p['SLOW_DROP_PERCENT']))
            h1 = self.counters('pj0')
        finally:
            f.netfilter('pj0', slow_arguments(f.m, member, 'pj0', 'delete', p['SLOW_DROP_PERCENT']))
        dropped = dropped_packets(listing, f.m['nodes'][member])
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


def slow_witness_binary(samples, member, lag_samples=2, dropped=None):
    """The slowdown witness on the projector binary (no probe timing in its /health): inside the slow window its BEHIND
    count rose, or its lag in events stood above the largest of the baseline in ``lag_samples`` consecutive samples
    (one sample above it is noise). Leaving the slowed member while the rule dropped its packets is recorded
    (``left_while_dropping``), never the witness: a member left on its archive's timeout went silent, not slow. The
    switch and the member it left are recorded. ``samples``: [{'phase': 'baseline'|'slow', 'source', 'behind', 'switches',
    'lag_events'}]."""
    base = [s for s in samples if s['phase'] == 'baseline']
    slow = [s for s in samples if s['phase'] == 'slow']
    if not base or not slow:
        return {'slowed': None}
    rose = lambda key: (slow[-1].get(key) or 0) > (base[-1].get(key) or 0)
    left = any(s.get('source') not in (None, member) for s in slow)
    top = max((s.get('lag_events') or 0) for s in base)
    run = longest = 0
    for s in slow:
        run = run + 1 if (s.get('lag_events') or 0) > top else 0
        longest = max(longest, run)
    lag = longest >= lag_samples
    left_on_drops = bool(left and dropped)
    return {'slowed': bool(rose('behind') or lag), 'behind_rose': rose('behind'), 'lag_grew': lag,
            'left_while_dropping': left_on_drops,
            'lag_samples_above_baseline': longest, 'lag_samples_needed': lag_samples, 'baseline_lag_max': top,
            'switches_rose': rose('switches'), 'left_member': left}


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


# The leaderless-window watcher (runs in the probe container, started before the kill): the survivors' role metric and
# pj0's beat counter, polled together with the host clock until a survivor reports leader (role 2) or the bound
WINDOW_WATCH = ('import json,re,sys,time,urllib.request\n'
                'a=json.loads(sys.stdin.read());t0=time.monotonic();rows=[];new=None\n'
                'def get(u):\n'
                ' try:\n  return urllib.request.urlopen(u,timeout=1).read().decode()\n'
                ' except Exception:\n  return None\n'
                'while time.monotonic()-t0<a["bound_s"]:\n'
                ' roles={m:(lambda x:None if x is None else bool(re.search(r"^core_cluster_role(\\{[^}]*\\})? 2(\\.0)?$",x,re.M)))(get(u)) for m,u in a["members"].items()}\n'
                ' h=get(a["health"]);h=json.loads(h) if h else {}\n'
                ' f=(h.get("projector") or {}).get("follow") or {}\n'
                ' ans=sum(f.get(k) or 0 for k in ("beatsOffered","beatsRefused","beatsPending","beatsDropped")) if f else None\n'
                ' rows.append({"t":round(time.monotonic()-t0,3),"w":time.time(),"leaders":[m for m,v in roles.items() if v],"beats":h.get("beats",f.get("beats")),"unanswered":h.get("probe_unanswered"),"answered":ans,"outstanding":(h.get("last_probe_sent_ns") or 0)>(h.get("last_probe_answered_ns") or 0)})\n'
                ' if rows[-1]["leaders"]:\n  new=rows[-1]["leaders"][0];break\n'
                ' time.sleep(a["watch_ms"]/1000)\n'
                'print(json.dumps({"new_leader":new,"rows":rows}))\n')
