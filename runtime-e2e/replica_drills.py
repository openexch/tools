# SPDX-License-Identifier: Apache-2.0
"""The replica drills on the fixture with ``shadow0`` filled: peer loss, member kill -9, the shadow catalog, and their
controls (the tables are ``core_drills.DRILLS`` / ``CONTROLS`` entries with a ``replica`` step).

Every drill is a ``core_drills.DrillRun``: genesis, the tap, the story (a01-mix, 120 s at 100/s unless the drill says
otherwise), the drill's own fault steps, the two-sample barrier and both oracles; PASS only when both oracles PASS and every
line holds. The fault steps use the fixture's allowlisted primitives only (kill, pause, stop, restart, wipe_engine,
wipe_shadows, the hash-pinned netfilter helper through a port kind), and read ``/metrics``, ``/ready``, the members'
archive listings (host side), container exit codes and logs; nothing a drill reads decides replicated state.

A drill establishes its preconditions from the system's own evidence (a member snapshot, ``shadow_pull_total``,
``shadow_replica_supplier_member_id``, the log start of the archive listing) and ends INCONCLUSIVE when it cannot, naming
what is missing. Every bound is a setting (``settings``), recorded with the run; a time value here is a functional guard of
the fixture profile, never acceptance evidence for a rate row. Every member a drill kills is restarted before the barrier
and its restart records ``waited_after_kill_s``. One lag formula, sampled by ``lag_sampler.py`` (one process in the probe
container for the drill's duration).

The pure parts (the settings, the lines, the control verdict) are unit tested in ``test_replica_drills.py``.
"""
import json
import os
import re
import time

from contracts import Inconclusive, Violation
import core_contracts
import core_drills
from core_drills import DrillRun, _iso_ns, _line, control_verdict
import core_fixture
import lag_sampler
import log_channel_fault

# name -> (default, low, high). Ranges are checked at start; a value outside names the setting (Violation).
SETTINGS_SPEC = {
    # leader P_cm -> the replica's ALIGNED at that position; the line's bound adds the kind's backup query interval (the
    # replica learns of a member snapshot only at its next backup query and holds the ALIGNED until it has retrieved it)
    'CATALOG_ALIGNED_BOUND_S': (5, 1, 600),
    # supplier loss: kill -> the backup out of BACKING_UP, a new supplier and applied past the commit at the kill. 30 s:
    # the supplier's liveness timeout (about 3 s), the 12 s cool-down, one backup query and the catch-up; 16 to 28 s
    # measured (a 20 s bound failed one run in four)
    'SUPPLIER_LOSS_RECOVERY_BOUND_S': (30, 1, 600),
    'LAG_SAMPLE_HZ': (10, 1, 100),              # the sampler's target rate (the achieved rate is recorded)
    'SAMPLER_CONTROL_PAUSE_S': (3, 1, 60),              # the sampler control: the replica paused this long
    'SAMPLER_PAUSE_RECOVERY_S': (10, 1, 600),           # ... and back below REPLICA_READY_MAX_LAG_BYTES within this
    'MEMBER_RESTART_READY_BOUND_S': (30, 1, 600),            # a killed member's /ready, measured from docker start
    'REPLICA_RESTART_READY_BOUND_S': (60, 1, 600),  # the restarted replica's /ready, measured from docker start
    'PEERLOSS_PULLS_BEFORE_KILL': (2, 1, 10),             # pulls the peer-loss target counted before the kills
    'PROMOTION_ATTEMPTS': (3, 1, 10),           # leader-loss attempts to see the supplier promoted
    'KILL_HEAL_BOUND_S': (core_fixture.KILL_HEAL_BOUND_S, 1, 3600),   # the fixture's kill heal bound, plus the drill's waits
    'STORY_SECONDS': (120, 10, 600),                # the story under which two member snapshots land
    'STORY_RATE': (100, 1, 1000),                   # CoreProbe sends rate x 1.2
    # Precondition waits: at the bound the drill ends INCONCLUSIVE naming the precondition
    'SNAPSHOT_WAIT_S': (150, 10, 3600),             # a member snapshot (the replica kinds run a 1-minute cadence)
    'PULL_WAIT_S': (300, 10, 3600),                 # PEERLOSS_PULLS_BEFORE_KILL pulls on the target
    'PURGE_WAIT_S': (300, 10, 3600),                # the members' logs start above 0 (or above the stopped replica)
    'SUPPLIER_WAIT_S': (60, 1, 600),                # the replica names a follower as its supplier
    'ALIGNED_WAIT_S': (150, 10, 3600),              # the next ALIGNED after a fault (one cadence plus the compare)
    'LOUD_EXIT_BOUND_S': (180, 10, 3600),           # the halted member's exit (the startup pull waits 60 s by default)
    'REBOOTSTRAP_EXIT_BOUND_S': (300, 10, 3600),    # the replica's exit 3 after its start
    'NOT_TAKEN_BOUND_S': (180, 10, 3600),           # the detector-only control: re-bootstrap not taken
    'NOWITNESS_BOUND_S': (420, 10, 7200),           # SHADOW_WITNESS_ALARM_MS 120 s + cadences + the alarm's poll
    'OBSERVE_FACTOR': (3, 1, 10),                   # recovery waits run to factor x bound, so a control measures by how much
    'MISSED_OBSERVE_S': (30, 1, 600),               # detector-only control: observed this long after the counted refusals
    # the tap ends this long after the drill's last step (its fault steps, the story's end and the pre-barrier) instead of
    # at its worst-case window; the window stays the tap's duration, so a tap that cannot stop early still ends
    'TAP_SETTLE_S': (30, 1, 600),
}
LEADER_ROLE = 2.0
SHADOW_RESTORE_PATHS = {2: 'EQUAL', 3: 'SKIP', 4: 'TAIL'}                  # core_restore_path (SnapshotModeCounters)
RESTORE_NAMES = {0: 'NONE', 1: 'FULL', 2: 'EQUAL', 3: 'SKIP', 4: 'TAIL', 5: 'VIRTUAL_GENESIS'}
REPLICA_RESTORE = {0: 'NONE', 1: 'LOCAL_SHADOW', 2: 'GENESIS', 3: 'PULLED_SHADOW', 4: 'REFUSED'}   # shadow_replica_restore_path
HALT_TEXT = 'FATAL shadow restore'
PULL_TEXT = '(3) pull:'
MISSED_TEXT = 're-bootstrap missed'
RESTART_TEXT = 'CRITICAL replica restart (exit 3)'      # CoreShadowReplicaMain's line for a decided re-bootstrap
# shadow_replica_backup_state (Aeron ClusterBackup.State codes): the backup left BACKING_UP (5) through its reset or a query
BACKUP_QUERY, BACKING_UP, RESET_BACKUP = 0, 5, 6
LEFT_BACKING_UP = {BACKUP_QUERY, RESET_BACKUP}
BACKUP_STATE_NAMES = {0: 'BACKUP_QUERY', 1: 'SNAPSHOT_RETRIEVE', 2: 'LIVE_LOG_RECORD', 3: 'LIVE_LOG_REPLAY',
                      4: 'UPDATE_RECORDING_LOG', 5: 'BACKING_UP', 6: 'RESET_BACKUP', 7: 'DONE', 8: 'CLOSED'}
STORY_CAP = 256                                   # retained requests per user per 15 min (the core's request table)


def settings(env=None):
    """The drill settings: defaults, overridden by an environment variable of the same name, each range-checked."""
    env = os.environ if env is None else env
    out = {}
    for name, (default, low, high) in SETTINGS_SPEC.items():
        raw = env.get(name)
        if raw is None or raw == '':
            out[name] = default
            continue
        try:
            value = float(raw)
        except ValueError:
            raise Violation(f'{name} must be a number, got {raw!r}')
        value = int(value) if value.is_integer() else value
        if not low <= value <= high:
            raise Violation(f'{name} {value} is outside {low}..{high}')
        out[name] = value
    return out


def story_for(spec_story, s):
    """The drill's story with STORY_SECONDS / STORY_RATE applied (the catalog drill keeps its low rate), refused when the
    users could not carry it under the request cap (the run would measure the cap, not the system)."""
    story = dict(spec_story)
    story['seconds'] = s['STORY_SECONDS']
    if story['rate'] == 100:
        story['rate'] = s['STORY_RATE']
    need = story['rate'] * 1.2 * story['seconds'] / STORY_CAP
    if len(story['users']) < need:
        raise Violation(f'STORY_RATE {story["rate"]} x STORY_SECONDS {story["seconds"]} needs >= {int(need) + 1} users under '
                        f'the {STORY_CAP}-request cap; the drill funds {len(story["users"])}')
    return story


def gauge(scrape, name, **labels):
    """One value of a scrape: a bare name, or a labelled one matched with or without quotes around the label values."""
    scrape = scrape or {}
    if not labels:
        if name in scrape:
            return scrape[name]
        hits = [v for k, v in scrape.items() if k.startswith(name + '{')]
        return sum(hits) if hits else None
    want = sorted(f'{k}={v}' for k, v in labels.items())
    for key, value in scrape.items():
        if key.startswith(name + '{') and key.endswith('}'):
            if sorted(key[len(name) + 1:-1].replace('"', '').split(',')) == want:
                return value
    return None


def lag_window(rows, lo_ns, hi_ns):
    return [r['lag_bytes'] for r in rows if r['lag_bytes'] is not None and lo_ns <= r['t_ns'] <= hi_ns]


def pause_analysis(rows, run_start_ns, pause_start_ns, pause_end_ns, recovery_s, threshold):
    """The sampler control: the lag rose above its pre-pause maximum during the pause, and fell back below ``threshold``
    within ``recovery_s`` of the unpause. Returns the witness."""
    before = lag_window(rows, run_start_ns, pause_start_ns)
    during = lag_window(rows, pause_start_ns, pause_end_ns + int(1e9))
    recovered_ns = next((r['t_ns'] for r in rows if r['t_ns'] > pause_end_ns and r['lag_bytes'] is not None
                         and r['lag_bytes'] <= threshold), None)
    return {'pre_max': max(before) if before else None, 'pause_max': max(during) if during else None,
            'samples_before': len(before), 'samples_during': len(during), 'threshold': threshold,
            'recovered_after_s': None if recovered_ns is None else round((recovered_ns - pause_end_ns) / 1e9, 3),
            'recovery_bound_s': recovery_s, 'pause_s': round((pause_end_ns - pause_start_ns) / 1e9, 3)}


# ------------------------------------------------------------------ lines (pure; each can fail)

def rule_removed(counters, endpoint):
    """The deletion of a port rule is asserted on the chain's listing: no DROP line names the port any more."""
    port = 'dpt:' + endpoint.rsplit(':', 1)[1]
    return not any('DROP' in line and re.search(re.escape(port) + r'\b', line) for line in (counters or '').splitlines())


def line_restore_path_shadow(w):
    """Every killed and restarted member restored through a shadow path (EQUAL, SKIP, TAIL), never FULL or virtual
    genesis; on the full-mode kind this line fails with ``restore path FULL on ae<n>`` (the control's RED)."""
    rows = w.get('member_restarts') or []
    if len(rows) != w.get('members_killed', 3):
        return _line(False, f'{len(rows)} member restarts recorded, the drill killed {w.get("members_killed", 3)}',
                     inconclusive=True)
    bad = [r for r in rows if r.get('restore_path') not in SHADOW_RESTORE_PATHS]
    if bad:
        return _line(False, '; '.join(f'restore path {RESTORE_NAMES.get(r.get("restore_path"), r.get("restore_path"))} on '
                                      f'{r["member"]}' for r in bad))
    return _line(True, 'restore paths ' + ', '.join(f'{r["member"]} {RESTORE_NAMES[r["restore_path"]]}' for r in rows))


def line_ready_after_start(w):
    bound = w['settings']['MEMBER_RESTART_READY_BOUND_S']
    rows = w.get('member_restarts') or []
    late = [r for r in rows if r.get('ready_after_start_s') is None or r['ready_after_start_s'] > bound]
    detail = ', '.join(f'{r["member"]} {r.get("ready_after_start_s")} s (after kill waited {r.get("waited_after_kill_s")} s)'
                       for r in rows)
    return _line(bool(rows) and not late, f'/ready from docker start <= {bound} s: {detail}')


def line_supplier_loss_recovery(w):
    """Supplier loss: the killed follower was the supplier; within SUPPLIER_LOSS_RECOVERY_BOUND_S of the kill the backup left
    BACKING_UP (``shadow_replica_backup_state`` RESET_BACKUP or BACKUP_QUERY seen), a new supplier is named and the applied
    position passed the leader's log position at the kill. Recorded, not required (measured on Aeron 1.53.1): the backup
    resets counter (it counts possible-failure events, which a supplier stop does not raise) and the reader re-attach
    counter (the backup extends the same local log recording from the new supplier)."""
    x = w.get('supplier_loss')
    if not x:
        return _line(False, 'no supplier-loss witness', inconclusive=True)
    if x.get('killed') != x.get('supplier_before'):
        return _line(False, f'killed member was not the supplier ({x.get("killed")} vs supplier {x.get("supplier_before")})',
                     inconclusive=True)
    bound = x['bound_s']
    if x.get('recovery_s') is None:
        return _line(False, f'supplier loss recovery not observed within {x.get("observed_s")} s (bound {bound} s): {x}')
    if x['recovery_s'] > bound:
        return _line(False, f'supplier loss recovery {x["recovery_s"]} s above {bound} s')
    states = x.get('states_seen') or []
    parts = (x.get('supplier_after') not in (None, -1, x['killed']), bool(LEFT_BACKING_UP & set(states)),
             x.get('applied_after') is not None and x.get('commit_at_kill') is not None
             and x['applied_after'] > x['commit_at_kill'])
    names = [BACKUP_STATE_NAMES.get(v, v) for v in states]
    return _line(all(parts), f'supplier {x["killed"]} -> {x.get("supplier_after")}, backup states {names}, applied '
                             f'{x.get("applied_after")} past the commit at the kill {x.get("commit_at_kill")} after '
                             f'{x["recovery_s"]} s (bound {bound} s); recorded: resets +{x.get("resets_delta")}, reattach '
                             f'+{x.get("reattach_delta")}')


def line_aligned_after_fault(w):
    """The replica's next ALIGNED after the fault was written and matched the member copy (no oracle mismatch)."""
    x = w.get('aligned_after')
    if not x:
        return _line(False, 'no ALIGNED observed after the fault', inconclusive=True)
    holds = x.get('written') and (x.get('mismatch_delta') or 0) == 0 and (x.get('match_delta') or 0) >= 1
    return _line(holds, f'ALIGNED written after the fault {x.get("written")}, oracle match +{x.get("match_delta")}, '
                        f'mismatch +{x.get("mismatch_delta")} (waited {x.get("waited_s")} s)')


def line_lag_within_term(w):
    lag = w.get('lag') or {}
    if not lag.get('samples_with_lag'):
        return _line(False, 'no lag observed: the sampler read no leader and replica pair', inconclusive=True)
    if not lag.get('max_lag_bytes'):
        return _line(False, 'no lag observed: the load did not reach the replica', inconclusive=True)
    term = lag['term_bytes']
    inside = lag['max_lag_bytes'] <= term
    return _line(inside, f'max lag {lag["max_lag_bytes"]:.0f} B {"<=" if inside else ">"} term {term} B at '
                         f'{lag.get("achieved_hz")} Hz ({lag.get("position")})')


def line_attempt_lag_within_term(w):
    """Leader loss: the lag of every attempt stays inside the term unless the backup went through RESET_BACKUP in that
    attempt (a reset waits out the cool-down while the load grows the log: recorded with the attempt, not bounded)."""
    attempts = w.get('promotion') or []
    lag = w.get('lag') or {}
    if not attempts:
        return _line(False, 'no leader-loss attempt recorded', inconclusive=True)
    if not lag.get('samples_with_lag'):
        return _line(False, 'no lag observed: the sampler read no leader and replica pair', inconclusive=True)
    term = lag['term_bytes']
    rows, over = [], []
    for a in attempts:
        reset = RESET_BACKUP in (a.get('states_seen') or [])
        peak = a.get('max_lag_bytes')
        rows.append(f'attempt {a["attempt"]} max {peak} B' + (' through a backup reset' if reset else ''))
        if not reset and peak is not None and peak > term:
            over.append(a['attempt'])
    if all(a.get('max_lag_bytes') is None for a in attempts):
        return _line(False, 'no lag sample inside any attempt', inconclusive=True)
    return _line(not over, ('; '.join(rows)) + f' (term {term} B' + (f', above it without a reset in attempts {over})'
                                                                   if over else ')'))


def line_sampler_saw_pause(w):
    x = w.get('sampler_pause')
    if not x:
        return _line(False, 'no sampler pause witness', inconclusive=True)
    rose = x.get('pause_max') is not None and (x.get('pre_max') is None or x['pause_max'] > x['pre_max'])
    recovered = x.get('recovered_after_s') is not None and x['recovered_after_s'] <= x['recovery_bound_s']
    if not rose:
        return _line(False, f'sampler saw no lag during a {x.get("pause_s")} s pause: {x}')
    return _line(recovered, f'lag {x.get("pre_max")} -> {x["pause_max"]} B during the pause, back below {x["threshold"]} B '
                            f'after {x.get("recovered_after_s")} s (bound {x["recovery_bound_s"]} s)')


def line_catalog_bound(w):
    rows = w.get('catalog') or []
    if not rows:
        return _line(False, 'snapshot not triggered', inconclusive=True)
    bound = w.get('catalog_bound_s')
    if bound is None:
        return _line(False, 'no catalog bound recorded', inconclusive=True)
    late = [r for r in rows if r.get('catalog_s') is None or r['catalog_s'] > bound]
    return _line(not late, 'leader P_cm -> replica ALIGNED: ' + ', '.join(f'{r["position"]}: {r.get("catalog_s")} s'
                                                                            for r in rows)
                 + f' (bound {bound} s = CATALOG_ALIGNED_BOUND_S {w["settings"]["CATALOG_ALIGNED_BOUND_S"]} s + backup query '
                   f'interval {w.get("query_interval_s")} s, functional)')


def line_promotion_states(w):
    """Every attempt is one of the two named states: (i) the supplier won the election: re-validated within two backup
    query intervals (the backup left BACKING_UP, RESET_BACKUP or BACKUP_QUERY seen, or it already named another supplier),
    then a follower is the supplier again and the applied position passed the leader's log position at the kill within
    the query interval plus the cool-down (recorded, not required: whether supplier_is_leader ever read 1, since with
    the FOLLOWER source the next response already names a follower, and the resets counter); (ii) the other follower won
    (supplier_is_leader stays 0, the resets do not move)."""
    attempts = w.get('promotion') or []
    if not attempts:
        return _line(False, 'no leader-loss attempt recorded', inconclusive=True)
    bad = [a for a in attempts if a.get('state') not in ('i', 'ii')]
    return _line(not bad, '; '.join(f'attempt {a["attempt"]}: {a.get("state")} ({a.get("detail")})' for a in attempts))


def line_promotion_observed(w):
    attempts = w.get('promotion') or []
    if any(a.get('state') == 'i' for a in attempts):
        return _line(True, 'the supplier was promoted and re-validated in attempt '
                           + str(next(a['attempt'] for a in attempts if a.get('state') == 'i')))
    return _line(False, f'promotion not observed in {len(attempts)} attempts', inconclusive=True)


def snapshot_positions(raw):
    """The distinct member snapshot positions a run saw, ascending. The gauge reads -1 before the first snapshot and an
    unreadable leader gives None; neither is a snapshot, so only positive positions count."""
    return sorted({int(p) for p in raw if p is not None and int(p) > 0})


def line_aligned_per_snapshot(w):
    """No member snapshot position without a replica ALIGNED: the ALIGNED writes grew by at least the distinct P_cm the
    run saw, minus the last (its ALIGNED may be in flight at the barrier)."""
    x = w.get('snapshots') or {}
    seen, written = x.get('positions') or [], x.get('aligned_delta')
    if not seen:
        return _line(False, 'snapshot not triggered', inconclusive=True)
    return _line(written is not None and written >= len(seen) - 1,
                 f'{len(seen)} member snapshot positions, replica ALIGNED +{written}')


def line_replica_restart_local(w):
    x = w.get('replica_restart') or {}
    bound = w['settings']['REPLICA_RESTART_READY_BOUND_S']
    if x.get('restore_path') != 1:
        return _line(False, f'restarted replica did not restore from its local shadow: restore path '
                            f'{REPLICA_RESTORE.get(x.get("restore_path"), x.get("restore_path"))}')
    late = x.get('ready_after_start_s') is None or x['ready_after_start_s'] > bound
    return _line(not late and x.get('verified') == 1,
                 f'LOCAL_SHADOW, /ready {x.get("ready_after_start_s")} s from docker start (bound {bound} s), '
                 f'verified {x.get("verified")}')


def line_member_floors_kept(w):
    x = w.get('floors') or {}
    if not x.get('before'):
        return _line(False, 'no member floor read before the fault', inconclusive=True)
    lower = [m for m, v in x['before'].items() if v is not None and (x.get('after') or {}).get(m) is not None
             and x['after'][m] < v]
    return _line(not lower, f'shadow_floor_position before {x["before"]} after {x.get("after")}')


def line_replica_pulled(w):
    x = w.get('replica_wipe') or {}
    if x.get('restore_path') != 3:
        return _line(False, f'wiped replica did not pull a member shadow: restore path '
                            f'{REPLICA_RESTORE.get(x.get("restore_path"), x.get("restore_path"))}')
    return _line(x.get('ready') is True, f'PULLED_SHADOW, ready {x.get("ready")}, leader-source skips '
                                         f'{x.get("skipped_leader")} (sources: {x.get("pull_sources")})')


def line_members_purged(w):
    """The followers' logs (the replica's backup sources) start above the stopped replica's recorded position (the
    re-bootstrap precondition); the leader holds no witness and keeps its log (recorded in ``all_log_starts``)."""
    x = w.get('purge') or {}
    if x.get('replica_stop_position') is None:
        return _line(False, 'no stopped-replica position recorded', inconclusive=True)
    starts = x.get('log_starts') or {}
    above = all(v is not None and v > x['replica_stop_position'] for v in starts.values()) and bool(starts)
    if not above:
        return _line(False, f'no purge below the stopped replica: log starts {starts}, replica stopped at '
                            f'{x["replica_stop_position"]} (waited {x.get("waited_s")} s)')
    return _line(True, f'log starts {starts} above the replica stop position {x["replica_stop_position"]}')


def line_rebootstrap_exit3(w):
    x = w.get('rebootstrap') or {}
    if x.get('exit_code') != 3:
        if x.get('detector_only') and x.get('exit_code') is None:
            reason = (f'{MISSED_TEXT} after {x.get("replay_below_start_max")} counted replay-below-start refusals '
                      f'(observed {x.get("missed_observed_s")} s after the count reached {x.get("refusals_needed")})')
        else:
            reason = f'no exit 3 within {x.get("bound_s")} s'
        return _line(False, f'replica did not exit 3: {reason} (exit {x.get("exit_code")}, '
                            f'replay-below-start {x.get("replay_below_start_max")})')
    need = x.get('replay_failures_setting', 3)
    # the decided restart is read from the replica's own exit line: the process exits right after it counts the
    # re-bootstrap, so a /metrics scrape rarely sees shadow_replica_rebootstrap_total move (recorded, not required)
    return _line((x.get('replay_below_start_max') or 0) >= need and RESTART_TEXT in (x.get('restart_line') or ''),
                 f'exit 3 after replay-below-start {x.get("replay_below_start_max")} (setting {need}), restart line: '
                 f'{str(x.get("restart_line"))[:200]}; recorded: re-bootstrap total seen {x.get("rebootstrap_total_max")}')


def line_rebootstrap_refusals_counted(w):
    """Detector-only control: the detector counted at least the refusals a default replica acts on
    (SHADOW_REBOOTSTRAP_REPLAY_FAILURES 0 counts and never acts; the kit never reports it as not-taken, /ready reads
    503 unverified continuation), and the replica kept running (the restart, the oracle, was missed)."""
    x = w.get('rebootstrap') or {}
    need = x.get('refusals_needed', 3)
    return _line((x.get('replay_below_start_max') or 0) >= need and x.get('exit_code') is None,
                 f'replay-below-start {x.get("replay_below_start_max")} (needed {need}), still running '
                 f'{x.get("exit_code") is None}, not taken {x.get("not_taken_max")}, /ready {x.get("ready_status")} '
                 f'{str(x.get("ready_body"))[:160]}')


def line_second_life_local(w):
    x = w.get('second_life') or {}
    return _line(x.get('restore_path') == 1 and x.get('ready') is True,
                 f'second life restore path {REPLICA_RESTORE.get(x.get("restore_path"), x.get("restore_path"))}, '
                 f'ready {x.get("ready")}')


def line_not_fenced(w):
    fenced = w.get('replica_fenced')
    return _line(fenced == 0, f'shadow_replica_fenced {fenced} at the end')


def line_anchor_rule_any_verified(w):
    rule = w.get('anchor_rule') or {}
    return _line(bool(rule) and all(v == 0 for v in rule.values()),
                 f'shadow_anchor_rule_two_producers per member {rule} (0 = any-verified)')


def line_witness_missing_replica(w):
    x = w.get('witness_missing') or {}
    return _line(bool(x) and all(v == 1 for v in x.values()), f'shadow_floor_witness_missing{{kind=R}} per follower {x}')


def line_disk_grew(w):
    x = w.get('disk') or {}
    before, after = x.get('before') or {}, x.get('after') or {}
    grew = bool(before) and all(after.get(m, 0) > b for m, b in before.items())
    return _line(grew, f'member archive bytes before {before} after {after}')


def line_peerloss_restore(w):
    x = w.get('peerloss') or {}
    if x.get('restore_path') not in SHADOW_RESTORE_PATHS:
        return _line(False, f'restore path {RESTORE_NAMES.get(x.get("restore_path"), x.get("restore_path"))} on '
                            f'{x.get("target")}')
    listing = x.get('listing') or {}
    return _line(x.get('ready') is True and listing.get('contiguous') is True,
                 f'{x.get("target")} {RESTORE_NAMES[x["restore_path"]]}, log from segment {listing.get("log_start_segment")} '
                 f'contiguous {listing.get("contiguous")}')


def line_peerloss_loud_halt(w):
    x = w.get('peerloss') or {}
    if not x.get('log_start_segment'):
        return _line(False, f'log of {x.get("target")} starts at 0: virtual genesis applies, the loud precondition is missing',
                     inconclusive=True)
    holds = (x.get('exit_code') == 1 and HALT_TEXT in (x.get('halt_line') or '') and PULL_TEXT in (x.get('halt_line') or '')
             and not x.get('ready_200_seen') and 5 not in (x.get('restore_paths_seen') or []))
    return _line(holds, f'{x.get("target")} exit {x.get("exit_code")}, ready 200 seen {x.get("ready_200_seen")}, restore paths '
                        f'{x.get("restore_paths_seen")}, halt: {str(x.get("halt_line"))[:240]}')


def line_pull_skip_unchanged(w):
    x = w.get('peerloss') or {}
    ok = x.get('restore_path') in SHADOW_RESTORE_PATHS and x.get('ready') is True and x.get('skipped_leader') == 0
    return _line(ok, f'{x.get("target")} restore path {x.get("restore_path")}, ready {x.get("ready")}, '
                     f'shadow_pull_source_skipped_leader_total {x.get("skipped_leader")}')


def line_filters_removed(w):
    rules = w.get('filters') or []
    return _line(all(r.get('removed') for r in rules),
                 f'{len(rules)} netfilter rules, removed: {[r.get("removed") for r in rules]}')


def untappable_windows(transitions, summary, quorum_loss=None, elections=None):
    """The tap windows a declared quorum loss or a recorded leader election made untappable, or None. A window is a
    dispatch or order-event gap of the tap summary that starts right after a ``session_closed`` note inside the
    quorum-loss interval or inside an election window (``from_ms`` .. ``to_ms``: the leader kill to the new leader
    serving) and is followed by a ``reconnected`` note: the tap's session closed while the cluster had no quorum or no
    leader. The core keeps no history of its egress, so what it emitted meanwhile cannot be tapped late; the
    dispatches the barrier's backfill rebuilds still count, the rest is recorded. A gap after a ``new_leader`` note (the
    session survived) is never declared."""
    intervals = []
    if quorum_loss:
        intervals.append((quorum_loss['from_ms'], quorum_loss['to_ms'],
                          f'quorum loss: {", ".join(quorum_loss.get("killed") or [])} killed, '
                          f'{quorum_loss.get("survivor")} alone'))
    for e in elections or []:
        intervals.append((e['from_ms'], e['to_ms'],
                          f'leader election: {e.get("killed")} killed, {e.get("new_leader")} elected'))
    dispatch_gaps = [list(g) for g in ((summary or {}).get('dispatch') or {}).get('gaps') or []]
    event_gaps = [list(g) for g in ((summary or {}).get('events') or {}).get('gaps') or []]
    out = {'dispatch': [], 'events': [], 'sessions': []}
    causes = []
    for i, note in enumerate(transitions or []):
        if note.get('event') != 'session_closed':
            continue
        at = note.get('at_ms') or 0
        inside = next((w for w in intervals if w[0] <= at <= w[1]), None)
        if inside is None:
            continue
        back = next((t for t in (transitions or [])[i + 1:] if t.get('event') == 'reconnected'), None)
        if back is None:
            continue
        dispatch = [g for g in dispatch_gaps if g[0] == (note.get('last_dispatch_seq') or 0) + 1]
        events = [g for g in event_gaps if g[0] == (note.get('last_event_seq') or 0) + 1]
        out['sessions'].append({'closed_ms': at, 'reconnected_ms': back['at_ms'], 'cause': inside[2]})
        out['dispatch'] += dispatch
        out['events'] += events
        if (dispatch or events) and inside[2] not in causes:
            causes.append(inside[2])
    if not out['dispatch'] and not out['events']:
        return None
    out['reason'] = (f'{"; ".join(causes)}; the tap session closed and reconnected after, and the core keeps no egress '
                     f'history to tap late')
    return out


def untapped_record(order):
    """What a declared untappable window left unjudged, for the drill verdict (None when nothing was declared): the
    reason, the orders recorded unjudged and their count, and the dispatch seqs the tap and the backfill left short."""
    u = (order or {}).get('untappable')
    if not u:
        return None
    unjudged = list(u.get('orders_unjudged') or [])
    return {'reason': (u.get('declared') or {}).get('reason'), 'orders_unjudged': unjudged,
            'orders_unjudged_count': len(unjudged),
            'dispatch_short': sum(int(d.get('short') or 0) for d in u.get('dispatch_short') or [])}


LINES = {name[5:]: fn for name, fn in list(globals().items()) if name.startswith('line_')}
core_drills.LINES.update(LINES)


def replica_control_verdict(money, order, lines, control):
    """A replica control PASSES when both oracles PASS, every line it names FAILS with its text, and every line it keeps
    HOLDS. A named line that fails without its text failed for another reason: the control is FAIL."""
    expect = core_drills.REPLICA_CONTROL_EXPECT[control]
    base = control_verdict(money, order, lines, list(expect['fail']))
    if base['status'] != 'PASS':
        return base
    reasons = list(base['reasons'])
    for name, text in expect['fail'].items():
        if text not in lines[name]['detail']:
            return {'status': 'FAIL', 'reasons': [f'control line {name} failed without its text {text!r}: '
                                                  f'{lines[name]["detail"][:200]}']}
    for name in expect['hold'] + ['fault_cycles']:
        line = lines.get(name)
        if line is None or not line['holds']:
            status = 'INCONCLUSIVE' if line is None or line.get('inconclusive') else 'FAIL'
            return {'status': status, 'reasons': [f'control keeps {name}, which does not hold: '
                                                  f'{(line or {}).get("detail", "not computed")}']}
        reasons.append(f'{name} holds')
    return {'status': 'PASS', 'reasons': reasons}


# ------------------------------------------------------------------ the run

class ReplicaDrillRun(DrillRun):
    def __init__(self, fixture, name, out_dir, variant=None):
        super().__init__(fixture, name, out_dir, variant=variant)
        self.s = settings()
        self.control = self.variant.get('control')
        kind = fixture.m.get('manifest_kind')
        if self.control:
            want = self.variant.get('kind')
            if kind != want:
                raise Inconclusive(f'control {self.control} runs on kind {want}, the manifest is {kind}')
        elif kind not in self.spec['kinds']:
            raise Inconclusive(f'drill {name} runs on kinds {self.spec["kinds"]}, the manifest is {kind}')
        if kind in core_contracts.REPLICA_KINDS and fixture.m['slot_artifacts'].get('shadow0') != 'shadow':
            raise Inconclusive('the replica drills need shadow0 on the shadow artifact')
        spec = dict(self.spec)
        spec['story'] = story_for(spec['story'], self.s)
        if self.control:
            expect = core_drills.REPLICA_CONTROL_EXPECT[self.control]
            spec['lines'] = list(expect['fail']) + list(expect['hold'])
        spec['tap_extra_s'] = self.tap_extra_s(kind)
        self.spec = spec
        self.rw = {}
        self.replica = kind in core_contracts.REPLICA_KINDS
        self.term_bytes = core_contracts.aeron_value(core_fixture.ENGINE_COMMON['TRANSPORT_LOG_TERM_LENGTH'])[1]
        self.sampler = None

    def tap_extra_s(self, kind):
        """The tap must outlast the drill's own steps beyond the story (its waits are settings)."""
        s = self.s
        replica = core_contracts.REPLICA_KINDS.get(kind, {}).get('replica', {})
        query_s = int(replica.get('REPLICA_BACKUP_QUERY_INTERVAL_MS', 60000)) / 1000
        cooldown_s = int(replica.get('REPLICA_BACKUP_COOLDOWN_MS', 12000)) / 1000
        return {'member_kill9': 3 * (core_fixture.AE_RESTART_MIN_AFTER_KILL_S + s['MEMBER_RESTART_READY_BOUND_S']) + s['SNAPSHOT_WAIT_S'],
                'peerloss': s['PULL_WAIT_S'] + 3 * 60 + s['ALIGNED_WAIT_S'],
                'peerloss_loud': s['PULL_WAIT_S'] + s['PURGE_WAIT_S'] + s['LOUD_EXIT_BOUND_S'] + 3 * 60,
                'shadow_catalog': 2 * s['SNAPSHOT_WAIT_S'] + s['SAMPLER_PAUSE_RECOVERY_S']
                + 2 * s['OBSERVE_FACTOR'] * (s['CATALOG_ALIGNED_BOUND_S'] + query_s),
                'supplierloss': s['SUPPLIER_WAIT_S'] + s['OBSERVE_FACTOR'] * s['SUPPLIER_LOSS_RECOVERY_BOUND_S']
                + s['ALIGNED_WAIT_S'],
                'leaderloss_promotion': s['PROMOTION_ATTEMPTS'] * (3 * query_s + cooldown_s + 5 + 60
                                                                       + core_fixture.AE_RESTART_MIN_AFTER_KILL_S
                                                                       + s['MEMBER_RESTART_READY_BOUND_S']),
                'replica_restart': s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'] + s['ALIGNED_WAIT_S'],
                'replica_wipe': s['PURGE_WAIT_S'] + s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S']
                + s['ALIGNED_WAIT_S'],
                # the no-witness wait only on the no-witness control (it waits for the floor alarm instead of a purge)
                'replica_rebootstrap': (s['NOWITNESS_BOUND_S'] if self.variant.get('nowitness') else
                                        s['PURGE_WAIT_S'] + max(s['REBOOTSTRAP_EXIT_BOUND_S'],
                                                                s['NOT_TAKEN_BOUND_S'] + s['MISSED_OBSERVE_S']))
                + s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'] + s['ALIGNED_WAIT_S'],
                }[self.spec['replica']]

    # ---------------------------------------------------------------- reads

    def members(self):
        return [f'ae{i}' for i in range(3)]

    def mm(self, role):
        return self.f.metrics(role, self.f.m['ports']['ae_metrics'])

    def rm(self):
        return self.f.metrics('shadow0', self.f.m['ports']['shadow_metrics'])

    def try_read(self, read):
        try:
            return read()
        except Inconclusive:
            return {}

    def leader(self):
        for role in self.members():
            if gauge(self.try_read(lambda r=role: self.mm(r)), 'core_cluster_role') == LEADER_ROLE:
                return role
        return None

    def snapshot_position(self):
        leader = self.leader()
        return gauge(self.try_read(lambda: self.mm(leader)), 'core_snapshot_last_log_position') if leader else None

    def until(self, probe, bound_s, period_s=0.25):
        """``probe()`` until it returns a truthy value or the bound runs out: (value, elapsed_s); (None, elapsed) at the bound."""
        started = time.monotonic()
        while True:
            value = probe()
            if value:
                return value, round(time.monotonic() - started, 3)
            if time.monotonic() - started >= bound_s:
                return None, round(time.monotonic() - started, 3)
            self.sleep(period_s)

    def need(self, probe, bound_s, text):
        """A precondition the drill establishes from the system's evidence, or INCONCLUSIVE naming it."""
        value, waited = self.until(probe, bound_s)
        if not value:
            raise Inconclusive(f'{text} (waited {waited} s)')
        return value

    def heal_bound(self):
        s = self.s
        return s['KILL_HEAL_BOUND_S'] + max(s['LOUD_EXIT_BOUND_S'], s['REBOOTSTRAP_EXIT_BOUND_S']) \
            + s['OBSERVE_FACTOR'] * max(s['MEMBER_RESTART_READY_BOUND_S'], s['REPLICA_RESTART_READY_BOUND_S'])

    def kill_role(self, role):
        witness = dict(self.f.kill(role, heal_bound_s=self.heal_bound()))
        witness['heal_bound_s'] = self.heal_bound()
        return self.ledger.open('kill', role, witness)

    def restart_role(self, row, ready_timeout=None):
        """Restart a killed role, heal its ledger row and return (witness, ready_after_start_s from docker start)."""
        role = row['target']
        timeout = ready_timeout or self.s['OBSERVE_FACTOR'] * self.s['MEMBER_RESTART_READY_BOUND_S']
        witness = self.f.restart(role, ready_timeout=timeout)
        ready_after = round((time.time_ns() - _iso_ns(witness['started_at'])) / 1e9, 3)
        witness = dict(witness, ready_after_start_s=ready_after)
        if role in core_contracts.ENGINES:
            self.restarted.add(role)
        self.ledger.heal(row, 'restart', witness)
        return witness, ready_after

    def aligned_counts(self):
        r = self.try_read(self.rm)
        return {'aligned': gauge(r, 'shadow_write_total', kind='ALIGNED'), 'match': gauge(r, 'shadow_oracle_match_total'),
                'mismatch': gauge(r, 'shadow_oracle_mismatch_total')}

    def await_aligned(self, before, restarted=False):
        """The replica's next ALIGNED after a fault, and the live oracle's verdict on it. ``restarted``: the replica's
        counters began again at 0, so any write counts."""
        base = {k: (0 if restarted else (v or 0)) for k, v in before.items()}

        def written():
            now = self.aligned_counts()
            return now if (now['aligned'] or 0) > base['aligned'] and (now['match'] or 0) > base['match'] else None
        now, waited = self.until(written, self.s['ALIGNED_WAIT_S'], 1.0)
        last = now or self.aligned_counts()
        self.rw['aligned_after'] = {'written': now is not None, 'waited_s': waited, 'before': before, 'after': last,
                                    'match_delta': (last['match'] or 0) - base['match'],
                                    'mismatch_delta': (last['mismatch'] or 0) - base['mismatch']}

    # ---------------------------------------------------------------- the drill frame

    def wall_ns(self):
        return time.time_ns()

    def wait_tap_end(self):
        """End the tap once the drill's last assertion is decided. ``run`` calls this after the fault steps, the story and
        the pre-barrier, so every line's evidence is in hand: the tap runs ``TAP_SETTLE_S`` more and is then stopped. Its
        duration (the summed worst-case bounds, ``tap_extra_s``) stays the ceiling: a step that waited to its bound only
        moves the decision later, and a tap that ignores the stop file still ends there."""
        tap = self.f.registry['tap']
        worst_ns = tap['started_ns'] + tap['duration_ms'] * 1_000_000
        decided_ns = self.wall_ns()
        settle = self.s['TAP_SETTLE_S']
        record = {'decided_ns': decided_ns, 'worst_case_end_ns': worst_ns, 'settle_s': settle}
        self.rw['tap_end'] = record
        if decided_ns + settle * 1e9 >= worst_ns:
            record['ended'] = 'duration'
            return super().wait_tap_end()
        self.sleep(settle)
        record['stop_written_ns'] = self.f.stop_tap()
        deadline_ns = worst_ns + 23 * 1_000_000_000          # the base frame's wait: the window, 3 s, then 20 s to print
        while True:
            try:
                summary = self.f.read_tap_summary()
            except Inconclusive:
                if self.wall_ns() > deadline_ns:
                    raise
                self.sleep(0.5)
                continue
            record['ended'] = summary.get('summary', {}).get('ended', 'duration')
            record['ended_ns'] = self.wall_ns()
            record['saved_s'] = round((worst_ns - record['ended_ns']) / 1e9, 1)
            return summary

    def faults_replica(self):
        if self.replica:
            self.sampler = self.f.start_lag_sampler(self.s['LAG_SAMPLE_HZ'], self.term_bytes)
            self.rw['sampler'] = {k: str(v) for k, v in self.sampler.items()}
        try:
            getattr(self, 'replica_' + self.spec['replica'])()
        finally:
            if self.sampler is not None:
                try:
                    self.rw['lag'] = self.f.stop_lag_sampler(self.sampler)
                except Inconclusive as error:
                    self.rw['lag'] = {'error': str(error)}
            if self.replica:
                self.rw['replica_fenced'] = gauge(self.try_read(self.rm), 'shadow_replica_fenced')

    def build_sample(self, story, tap, tap_summary, second, pre):
        """The base sample, plus the declared untappable windows of a quorum loss (peer loss) or of the recorded leader
        elections (leader loss): the oracles record what the tap could not see there instead of judging it (O-F5, O3,
        O5, O10)."""
        sample = super().build_sample(story, tap, tap_summary, second, pre)
        if self.rw.get('quorum_loss') or self.rw.get('elections'):
            windows = untappable_windows(tap_summary.get('transitions'), tap_summary.get('summary'),
                                         self.rw.get('quorum_loss'), self.rw.get('elections'))
            self.rw['untappable'] = windows
            if windows:
                sample['declared'] = dict(sample['declared'], untappable=windows)
        return sample

    def witness(self, sample, after):
        w = super().witness(sample, after)
        w.update(self.rw)
        w['settings'] = dict(self.s)
        if 'expect_cycles' in self.rw:
            w['expect_cycles'] = self.rw['expect_cycles']
        return w

    def decide(self, money, order, lines, rows, sample, after):
        if not self.control:
            out = super().decide(money, order, lines, rows, sample, after)
        else:
            saved = self.variant
            self.variant = {k: v for k, v in saved.items() if k != 'control'}
            try:
                out = super().decide(money, order, lines, rows, sample, after)
            finally:
                self.variant = saved
            out.update(replica_control_verdict(money, order, lines, self.control))
            out['variant'] = saved
        out['replica_settings'] = dict(self.s)
        out['manifest_kind'] = self.f.m.get('manifest_kind')
        recorded = untapped_record(order)
        if recorded:
            out['untappable'] = recorded
        return out

    def write_evidence(self, sample, money, order, lines, rows, w, story, tap_summary, result):
        super().write_evidence(sample, money, order, lines, rows, w, story, tap_summary, result)
        (self.out / 'replica.json').write_text(json.dumps({'witness': self.rw, 'settings': self.s}, indent=1, default=str) + '\n')
        if self.sampler is not None and self.sampler['tsv'].is_file():
            (self.out / 'lag.tsv').write_bytes(self.sampler['tsv'].read_bytes())

    # ---------------------------------------------------------------- member kill -9

    def replica_member_kill9(self):
        """Each AE member in turn under the story: kill -9, restart; /ready from docker start and the restore gauge."""
        self.need(lambda: (self.snapshot_position() or 0) > 0, self.s['SNAPSHOT_WAIT_S'],
                  'no member snapshot: a restarted member would have nothing to restore')
        restarts = []
        for role in self.members():
            row = self.kill_role(role)
            witness, ready_after = self.restart_role(row)
            restarts.append({'member': role, 'restore_path': gauge(self.try_read(lambda r=role: self.mm(r)),
                                                                   'core_restore_path'),
                             'ready_after_start_s': ready_after, 'waited_after_kill_s': witness.get('waited_after_kill_s'),
                             'started_at': witness['started_at']})
        self.rw.update(member_restarts=[{k: (int(v) if k == 'restore_path' and v is not None else v) for k, v in r.items()}
                                        for r in restarts], members_killed=3)

    # ---------------------------------------------------------------- peer loss

    def peer_roles(self, both_followers=False):
        """(leader, target, other): the target is a follower that counted PEERLOSS_PULLS_BEFORE_KILL pulls; with
        ``both_followers`` the other follower counted them too (it is then the survivor that serves its copies)."""
        k = self.s['PEERLOSS_PULLS_BEFORE_KILL']

        def pulls(role):
            return gauge(self.try_read(lambda: self.mm(role)), 'shadow_pull_total') or 0

        def pick():
            leader = self.leader()
            if leader is None:
                return None
            for role in self.members():
                if role != leader and pulls(role) >= k:
                    other = next(r for r in self.members() if r not in (leader, role))
                    if not both_followers or pulls(other) >= k:
                        return leader, role, other
            return None
        return self.need(pick, self.s['PULL_WAIT_S'], f'no follower counted {k} pulls before the kill' if not both_followers
                         else f'the two followers did not both count {k} pulls before the kill')

    def replica_peerloss(self):
        """kill -9 the replica and both followers, restart the one that pulled: it restores on its own pulled copy (a
        shadow path) and its log from the restore floor is intact; then the other follower and the replica come back."""
        leader, target, other = self.peer_roles()
        before = self.aligned_counts()
        pulls_before = gauge(self.try_read(lambda: self.mm(target)), 'shadow_pull_total')   # before the kill (it restarts at 0)
        quorum_lost_ms = time.time_ns() // 1_000_000
        rows = {r: self.kill_role(r) for r in ('shadow0', other, target)}
        witness, ready_after = self.restart_role(rows[target], ready_timeout=self.s['OBSERVE_FACTOR'] * self.s['MEMBER_RESTART_READY_BOUND_S'])
        self.rw['quorum_loss'] = {'from_ms': quorum_lost_ms, 'to_ms': time.time_ns() // 1_000_000,
                                  'killed': ['shadow0', other, target], 'survivor': leader}
        scrape = self.try_read(lambda: self.mm(target))
        self.rw['peerloss'] = {'leader': leader, 'target': target, 'other': other, 'ready': True,
                               'restore_path': None if gauge(scrape, 'core_restore_path') is None
                               else int(gauge(scrape, 'core_restore_path')),
                               'ready_after_start_s': ready_after, 'listing': core_fixture.archive_listing(self.f.root, target),
                               'pulls_before': pulls_before, 'pulls_after_restart': gauge(scrape, 'shadow_pull_total')}
        self.restart_role(rows[other])
        self.restart_role(rows['shadow0'], ready_timeout=self.s['OBSERVE_FACTOR'] * self.s['REPLICA_RESTART_READY_BOUND_S'])
        self.await_aligned(before, restarted=True)

    def replica_peerloss_loud(self):
        """The loud variant: the target's shadows wiped, the survivor's archive control port blocked (netfilter port
        kind ``archive``) and the replica down, so the target's stub restore has no shadow to pull: it exits 1 with the
        restore halt text, never serves /ready 200 and never takes virtual genesis (its log does not start at 0). The
        unblocked companion keeps the survivor reachable: the target restores from its copy and the leader-source skip
        counter does not move. The companion's survivor is the other follower (its pulled copies are what the target
        restores from; it is alone and cannot lead, which is what makes it a source) and the leader is killed instead."""
        unblocked = self.variant.get('unblocked', False)
        # the unblocked companion's survivor must hold shadow copies to serve: a follower that pulled, never the leader
        # (a leader neither pulls nor produces, so it has nothing to list); the leader is killed with the replica and the
        # target. The loud variant keeps the leader as the survivor and blocks its archive port.
        leader, target, other = self.peer_roles(both_followers=unblocked)
        survivor, second = (other, leader) if unblocked else (leader, other)
        listing = self.need(lambda: (lambda x: x if (x.get('log_start_segment') or 0) > 0 else None)(
            core_fixture.archive_listing(self.f.root, target)), self.s['PURGE_WAIT_S'],
            f'log of {target} still starts at 0: virtual genesis would apply, the loud precondition is missing')
        x = {'leader': leader, 'target': target, 'other': other, 'survivor': survivor, 'unblocked': unblocked,
             'log_start_segment': listing['log_start_segment'], 'listing_before': listing,
             'replica_archive': 'unreachable: shadow0 is killed (a stopped container has no namespace to filter in)'}
        self.rw['peerloss'] = x
        filters = self.rw.setdefault('filters', [])
        x['pulls_before'] = gauge(self.try_read(lambda: self.mm(target)), 'shadow_pull_total')
        x['survivor_pulls_before'] = gauge(self.try_read(lambda: self.mm(survivor)), 'shadow_pull_total')
        quorum_lost_ms = time.time_ns() // 1_000_000
        rows = {r: self.kill_role(r) for r in ('shadow0', second, target)}
        try:
            if not unblocked:
                filters.append({'target': leader, 'port_kind': 'archive',
                                'add': log_channel_fault.log_filter(self.f, leader, 'add', 'archive'), 'removed': False})
            x['wipe'] = {k: v for k, v in self.f.wipe_shadows(target).items() if k != 'at_ns'}
            if unblocked:
                witness, ready_after = self.restart_role(rows[target],
                                                         ready_timeout=self.s['LOUD_EXIT_BOUND_S'])
                scrape = self.try_read(lambda: self.mm(target))
                x.update(ready=True, ready_after_start_s=ready_after, restore_path=gauge(scrape, 'core_restore_path'),
                         skipped_leader=gauge(scrape, 'shadow_pull_source_skipped_leader_total'))
                if x['restore_path'] is not None:
                    x['restore_path'] = int(x['restore_path'])
            else:
                self.watch_loud_start(target, x)
        finally:
            for rule in filters:
                if not rule['removed']:
                    rule['delete'] = log_channel_fault.log_filter(self.f, rule['target'], 'delete', 'archive')
                    rule['counters_after'] = log_channel_fault.log_filter(self.f, rule['target'], 'counters', 'archive')
                    rule['removed'] = rule_removed(rule['counters_after'], self.f.archive_endpoint(rule['target']))
        self.restart_role(rows[second])
        self.rw['quorum_loss'] = {'from_ms': quorum_lost_ms, 'to_ms': time.time_ns() // 1_000_000,
                                  'killed': ['shadow0', second, target], 'survivor': survivor}
        # the replica first: it always holds an ALIGNED shadow, so the halted target's second start has a source
        self.restart_role(rows['shadow0'], ready_timeout=self.s['OBSERVE_FACTOR'] * self.s['REPLICA_RESTART_READY_BOUND_S'])
        if not unblocked:
            self.restart_role(rows[target], ready_timeout=self.s['LOUD_EXIT_BOUND_S'])

    def watch_loud_start(self, target, x):
        """Start the target without waiting for /ready, watch /ready and the restore gauge until it exits, then read its
        exit code and its halt line."""
        start = self.f.restart(target, wait_ready=False)
        x['started_at'] = start['started_at']
        x['waited_after_kill_s'] = start.get('waited_after_kill_s')
        seen, ready_200 = set(), False
        deadline = time.monotonic() + self.s['LOUD_EXIT_BOUND_S']
        cid = self.f.registry['containers'][target]
        while time.monotonic() < deadline:
            if not self.f.inspect('container', cid)['State']['Running']:
                break
            status, _ = self.f.ready_body(target)
            ready_200 = ready_200 or status == 200
            path = gauge(self.try_read(lambda: self.mm(target)), 'core_restore_path')
            if path is not None:
                seen.add(int(path))
            self.sleep(0.5)
        state = self.f.inspect('container', cid)['State']
        if state['Running']:
            raise Inconclusive(f'{target} neither halted nor became ready within {self.s["LOUD_EXIT_BOUND_S"]} s')
        exited = self.f.wait_exit(target, state['ExitCode'], 1)
        logs = self.f.command(['docker', 'logs', cid], check=False)
        text = (logs.stdout or '') + '\n' + (logs.stderr or '')
        halt = next((l for l in text.splitlines() if HALT_TEXT in l), None)
        x.update(exit_code=state['ExitCode'], exit=exited, ready_200_seen=ready_200, restore_paths_seen=sorted(seen),
                 halt_line=halt)

    # ---------------------------------------------------------------- the shadow catalog and the sampler control

    def lag_rows(self):
        return lag_sampler.read_tsv(self.sampler['tsv']) if self.sampler else []

    def replica_shadow_catalog(self):
        """First the sampler control (the replica paused SAMPLER_CONTROL_PAUSE_S: the lag must rise and recover), then the
        catalog bound on two member snapshots: leader P_cm -> the replica's ALIGNED written at P_cm."""
        s = self.s
        self.sleep(5)                      # a pre-pause lag baseline from the sampler
        pause_start = time.time_ns()
        row = self.pause('shadow0', s['SAMPLER_CONTROL_PAUSE_S'])
        self.sleep(s['SAMPLER_CONTROL_PAUSE_S'])
        self.f.unpause('shadow0')
        pause_end = time.time_ns()
        threshold = int(self.rm_setting('REPLICA_READY_MAX_LAG_BYTES') or self.term_bytes)
        self.sleep(s['SAMPLER_PAUSE_RECOVERY_S'])
        ready, waited = self.until(lambda: self.f.ready_body('shadow0')[0] == 200, s['SAMPLER_PAUSE_RECOVERY_S'])
        self.ledger.heal(row, 'thawed', {'ready': bool(ready), 'waited_s': waited})
        self.f.close_fault('shadow0')
        self.rw['sampler_pause'] = pause_analysis(self.lag_rows(), self.sampler['started_ns'], pause_start, pause_end,
                                                  s['SAMPLER_PAUSE_RECOVERY_S'], threshold)
        query_s = self.rm_setting('REPLICA_BACKUP_QUERY_INTERVAL_MS') / 1000
        bound = s['CATALOG_ALIGNED_BOUND_S'] + query_s
        self.rw.update(catalog_bound_s=bound, query_interval_s=query_s)
        catalog = []
        for _ in range(2):
            leader = self.leader()
            if leader is None:
                break
            last = gauge(self.try_read(lambda: self.mm(leader)), 'core_snapshot_last_log_position') or 0
            written0 = self.aligned_counts()['aligned'] or 0

            def moved():
                p = gauge(self.try_read(lambda: self.mm(leader)), 'core_snapshot_last_log_position')
                return (p, time.time_ns()) if p and p > last else None
            hit = self.until(moved, s['SNAPSHOT_WAIT_S'], 0.1)[0]
            if hit is None:
                break
            position, at_ns = hit

            def listed():
                r = self.try_read(self.rm)
                done = gauge(r, 'shadow_last_position', kind='ALIGNED')
                wrote = (gauge(r, 'shadow_write_total', kind='ALIGNED') or 0) > written0
                return time.time_ns() if wrote and done is not None and done >= position else None
            seen = self.until(listed, s['OBSERVE_FACTOR'] * bound, 0.1)[0]
            catalog.append({'leader': leader, 'position': int(position),
                            'catalog_s': None if seen is None else round((seen - at_ns) / 1e9, 3)})
        self.rw['catalog'] = catalog

    def rm_setting(self, name):
        """A replica setting the drill compares with: the kind's value, else the replica's default (core README)."""
        kind = self.f.m.get('manifest_kind')
        value = core_contracts.REPLICA_KINDS.get(kind, {}).get('replica', {}).get(name)
        if value is not None:
            return int(value)
        if name == 'REPLICA_READY_MAX_LAG_BYTES':
            return self.term_bytes                       # the core's default is the run's TRANSPORT_LOG_TERM_LENGTH
        if name == 'REPLICA_BACKUP_QUERY_INTERVAL_MS':
            return 60000
        if name == 'REPLICA_BACKUP_COOLDOWN_MS':
            return 12000                                 # REPLICA_MEMBER_BACKUP_WINDOW_MS 11000 + 1000
        if name == 'SHADOW_REBOOTSTRAP_REPLAY_FAILURES':
            return 3
        return None

    # ---------------------------------------------------------------- supplier loss

    def supplier(self):
        """The replica's supplier when it names a follower (never the leader, never -1)."""
        r = self.try_read(self.rm)
        sid = gauge(r, 'shadow_replica_supplier_member_id')
        if sid is None or sid < 0:
            return None
        role = f'ae{int(sid)}'
        if role not in self.members() or role == self.leader():
            return None
        return role, r

    def leader_log_position(self):
        """The leader's ``core_log_position``: the lag formula's commit position, read over /metrics."""
        leader = self.leader()
        return gauge(self.try_read(lambda: self.mm(leader)), 'core_log_position') if leader else None

    def replica_supplierloss(self):
        """kill -9 the replica's supplier (a follower): the backup leaves BACKING_UP, names a new supplier and the applied
        position passes the leader's log position at the kill, within SUPPLIER_LOSS_RECOVERY_BOUND_S (observed to
        OBSERVE_FACTOR x the bound so a control measures by how much)."""
        s = self.s
        role, before = self.need(self.supplier, s['SUPPLIER_WAIT_S'], 'the replica names no follower as its supplier')
        aligned = self.aligned_counts()
        commit_at_kill = self.leader_log_position()
        row = self.kill_role(role)
        killed_ns = time.time_ns()
        states = set()

        def recovered():
            r = self.try_read(self.rm)
            state = gauge(r, 'shadow_replica_backup_state')
            if state is not None:
                states.add(int(state))
            sid = gauge(r, 'shadow_replica_supplier_member_id')
            applied = gauge(r, 'shadow_replica_applied_position') or 0
            if (sid is not None and sid >= 0 and f'ae{int(sid)}' != role and LEFT_BACKING_UP & states
                    and commit_at_kill is not None and applied > commit_at_kill):
                return {'at_ns': time.time_ns(), 'supplier_after': f'ae{int(sid)}', 'applied_after': applied}
            return None
        observe = s['OBSERVE_FACTOR'] * s['SUPPLIER_LOSS_RECOVERY_BOUND_S']
        done, waited = self.until(recovered, observe)
        r = self.try_read(self.rm)
        x = {'killed': role, 'supplier_before': role, 'bound_s': s['SUPPLIER_LOSS_RECOVERY_BOUND_S'], 'observed_s': waited,
             'commit_at_kill': commit_at_kill, 'states_seen': sorted(states),
             'recovery_s': None if done is None else round((done['at_ns'] - killed_ns) / 1e9, 3),
             'resets_delta': (gauge(r, 'shadow_replica_backup_resets_total') or 0)
             - (gauge(before, 'shadow_replica_backup_resets_total') or 0),
             'reattach_delta': (gauge(r, 'shadow_replica_reader_reattach_total') or 0)
             - (gauge(before, 'shadow_replica_reader_reattach_total') or 0)}
        if done:
            x.update({k: v for k, v in done.items() if k != 'at_ns'})
        else:
            sid = gauge(r, 'shadow_replica_supplier_member_id')
            x.update(supplier_after=None if sid is None or sid < 0 else f'ae{int(sid)}',
                     applied_after=gauge(r, 'shadow_replica_applied_position'))
        self.rw['supplier_loss'] = x
        if done is not None:
            self.await_aligned(aligned)
        witness, _ = self.restart_role(row)                       # before the barrier: the oracle wants three members
        x['waited_after_kill_s'] = witness.get('waited_after_kill_s')

    # ---------------------------------------------------------------- leader loss and the supplier's promotion

    def replica_leaderloss_promotion(self):
        """Stop the AE leader while the replica follows a follower supplier, at most PROMOTION_ATTEMPTS times, until the
        supplier itself wins the election: state (i) or state (ii) per attempt (line_promotion_states)."""
        s = self.s
        query_s = self.rm_setting('REPLICA_BACKUP_QUERY_INTERVAL_MS') / 1000
        cooldown_s = self.rm_setting('REPLICA_BACKUP_COOLDOWN_MS') / 1000
        attempts, positions = [], set()
        aligned0 = self.aligned_counts()
        for attempt in range(1, s['PROMOTION_ATTEMPTS'] + 1):
            supplier, before = self.need(self.supplier, s['SUPPLIER_WAIT_S'], 'the replica names no follower as its supplier')
            leader = self.leader()
            if leader is None:
                raise Inconclusive('no single AE leader before the leader kill')
            positions.add(self.snapshot_position())
            commit_at_kill = self.leader_log_position()
            started_ns = time.time_ns()
            row = self.kill_role(leader)
            new, election_s = self.wait_leader('ae', leader)
            # the recorded election window: the leader kill to the new leader serving (or the end of the wait)
            self.rw.setdefault('elections', []).append({'from_ms': started_ns // 1_000_000,
                                                        'to_ms': time.time_ns() // 1_000_000,
                                                        'killed': leader, 'new_leader': new})
            entry = {'attempt': attempt, 'killed_leader': leader, 'supplier': supplier, 'new_leader': new,
                     'election_s': election_s, 'query_interval_s': query_s, 'cooldown_s': cooldown_s,
                     'commit_at_kill': commit_at_kill}
            resets0 = gauge(before, 'shadow_replica_backup_resets_total') or 0
            states, saw_leader = set(), [False]

            def read():
                r = self.try_read(self.rm)
                state = gauge(r, 'shadow_replica_backup_state')
                if state is not None:
                    states.add(int(state))
                saw_leader[0] = saw_leader[0] or gauge(r, 'shadow_replica_supplier_is_leader') == 1
                return r
            if new is None:
                entry.update(state=None, detail='no new leader')
            elif new == supplier:
                def revalidated():
                    r = read()
                    sid = gauge(r, 'shadow_replica_supplier_member_id')
                    moved = sid is not None and sid >= 0 and f'ae{int(sid)}' != new
                    return {'evidence': 'backup state' if LEFT_BACKING_UP & states else 'new supplier'} \
                        if LEFT_BACKING_UP & states or moved else None
                hit, waited = self.until(revalidated, 2 * query_s)
                if hit is None:
                    entry.update(state=None, detail=f'promotion re-validation outside {2 * query_s} s: backup states '
                                                    f'{[BACKUP_STATE_NAMES.get(v, v) for v in sorted(states)]}')
                else:
                    def follower_again():
                        r = read()
                        sid = gauge(r, 'shadow_replica_supplier_member_id')
                        applied = gauge(r, 'shadow_replica_applied_position') or 0
                        return f'ae{int(sid)}' if (sid is not None and sid >= 0 and f'ae{int(sid)}' != new
                                                   and gauge(r, 'shadow_replica_supplier_is_leader') == 0
                                                   and commit_at_kill is not None and applied > commit_at_kill) else None
                    nxt, back_s = self.until(follower_again, query_s + cooldown_s + 5)
                    r = self.try_read(self.rm)
                    detail = (f're-validated after {waited} s ({hit["evidence"]}), backup states '
                              f'{[BACKUP_STATE_NAMES.get(v, v) for v in sorted(states)]}; ')
                    detail += (f'supplier {nxt} after {round(waited + back_s, 3)} s' if nxt else
                               f'no follower supplier past the commit at the kill within {query_s + cooldown_s + 5} s')
                    detail += (f'; recorded: supplier_is_leader 1 seen {saw_leader[0]}, resets {resets0} -> '
                               f'{gauge(r, "shadow_replica_backup_resets_total")}')
                    entry.update(state='i' if nxt else None, new_supplier=nxt, detail=detail)
            else:
                deadline = time.monotonic() + query_s
                while time.monotonic() < deadline:
                    read()
                    self.sleep(0.5)
                r = read()
                stays = not saw_leader[0] and (gauge(r, 'shadow_replica_backup_resets_total') or 0) == resets0
                entry.update(state='ii' if stays else None,
                             detail='the other follower won; supplier_is_leader 0, resets unchanged' if stays else
                             f'the other follower won, but supplier_is_leader 1 seen {saw_leader[0]}'
                             f' resets {gauge(r, "shadow_replica_backup_resets_total")} (was {resets0})')
            entry['states_seen'] = sorted(states)
            witness, _ = self.restart_role(row)                   # the dead leader comes back before the next attempt
            entry['waited_after_kill_s'] = witness.get('waited_after_kill_s')
            window = lag_window(self.lag_rows(), started_ns, time.time_ns())
            entry['max_lag_bytes'] = max(window) if window else None
            positions.add(self.snapshot_position())
            attempts.append(entry)
            if entry['state'] == 'i':
                break
        aligned1 = self.aligned_counts()
        self.rw.update(promotion=attempts, expect_cycles=len(attempts),
                       snapshots={'positions': snapshot_positions(positions),
                                  'aligned_delta': None if aligned1['aligned'] is None or aligned0['aligned'] is None
                                  else aligned1['aligned'] - aligned0['aligned']})

    # ---------------------------------------------------------------- the replica: restart, wipe, re-bootstrap

    def floors(self):
        return {m: gauge(self.try_read(lambda r=m: self.mm(r)), 'shadow_floor_position') for m in self.members()}

    def replica_replica_restart(self):
        s = self.s
        self.need(lambda: (self.aligned_counts()['aligned'] or 0) >= 1, s['SNAPSHOT_WAIT_S'],
                  'the replica held no local shadow before the kill')
        floors = self.floors()
        aligned = self.aligned_counts()
        row = self.kill_role('shadow0')
        witness, ready_after = self.restart_role(row, ready_timeout=s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'])
        r = self.try_read(self.rm)
        self.rw['replica_restart'] = {'restore_path': None if gauge(r, 'shadow_replica_restore_path') is None
                                      else int(gauge(r, 'shadow_replica_restore_path')),
                                      'ready_after_start_s': ready_after, 'verified': gauge(r, 'shadow_replica_verified'),
                                      'waited_after_kill_s': witness.get('waited_after_kill_s')}
        self.rw['floors'] = {'before': floors, 'after': self.floors()}
        self.await_aligned(aligned, restarted=True)

    def log_starts(self, members=None):
        return {m: core_fixture.archive_listing(self.f.root, m).get('log_start_segment') for m in (members or self.members())}

    def follower_log_starts(self):
        """The followers' log starts, or None without a single leader. The followers are the replica's backup sources
        (REPLICA_BACKUP_SOURCE=FOLLOWER) and the members whose floors purge; the leader never pulls a shadow, holds no
        witness and keeps its log (recorded, never required)."""
        leader = self.leader()
        if leader is None:
            return None
        return self.log_starts([m for m in self.members() if m != leader])

    def replica_replica_wipe(self):
        s = self.s
        self.need(lambda: (lambda x: bool(x) and all((v or 0) > 0 for v in x.values()))(self.follower_log_starts()),
                  s['PURGE_WAIT_S'],
                  'the followers\' logs still start at 0: a wiped replica would replay from genesis, not pull')
        aligned = self.aligned_counts()
        row = self.kill_role('shadow0')
        wipe = self.f.wipe_engine('shadow0')
        witness, ready_after = self.restart_role(row, ready_timeout=s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'])
        r = self.try_read(self.rm)
        self.rw['replica_wipe'] = {'restore_path': None if gauge(r, 'shadow_replica_restore_path') is None
                                   else int(gauge(r, 'shadow_replica_restore_path')), 'ready': True,
                                   'ready_after_start_s': ready_after, 'wiped_bytes': wipe.get('bytes_removed'),
                                   'skipped_leader': gauge(r, 'shadow_pull_source_skipped_leader_total'),
                                   'pull_sources': {k: v for k, v in r.items() if k.startswith('shadow_pull_')},
                                   'log_starts': self.log_starts(), 'leader': self.leader()}
        self.await_aligned(aligned, restarted=True)

    def archive_bytes(self):
        out = {}
        for m in self.members():
            base = self.f.root / 'state' / m / 'state' / 'archive'
            out[m] = sum(p.stat().st_size for p in base.glob('*.rec')) if base.is_dir() else None
        return out

    def replica_replica_rebootstrap(self):
        """Stop the replica FIRST, then the member snapshots, then the purge (the any-verified rule): the replica's
        restart finds the log pruned past what it holds, refuses the replay three times, re-bootstraps and exits 3; its
        second life restores from the local shadow. The detector-only control never acts (re-bootstrap not taken); the
        no-witness control (default rule) shows why the purge cannot happen with the replica down."""
        s = self.s
        members = self.members()
        self.rw['anchor_rule'] = {m: gauge(self.try_read(lambda r=m: self.mm(r)), 'shadow_anchor_rule_two_producers')
                                  for m in members}
        self.need(lambda: (self.aligned_counts()['aligned'] or 0) >= 1, s['SNAPSHOT_WAIT_S'],
                  'the replica held no local shadow before its stop')
        stop_position = gauge(self.try_read(self.rm), 'shadow_replica_recorded_position')
        disk_before = self.archive_bytes()
        stopped = self.f.stop('shadow0', heal_bound_s=self.heal_bound() + s['PURGE_WAIT_S'] + s['NOWITNESS_BOUND_S'])
        row = self.ledger.open('stop', 'shadow0', stopped)
        purge = {'replica_stop_position': stop_position}
        if self.variant.get('nowitness'):
            def alarm():
                leader = self.leader()
                values = {m: gauge(self.try_read(lambda r=m: self.mm(r)), 'shadow_floor_witness_missing', kind='R')
                          for m in members if m != leader}
                return values if values and all(v == 1 for v in values.values()) else None
            values, waited = self.until(alarm, s['NOWITNESS_BOUND_S'], 2.0)
            leader = self.leader()
            self.rw['witness_missing'] = values or {m: gauge(self.try_read(lambda r=m: self.mm(r)),
                                                             'shadow_floor_witness_missing', kind='R')
                                                    for m in members if m != leader}
            purge.update(log_starts=self.follower_log_starts() or {}, all_log_starts=self.log_starts(),
                         leader=self.leader(), waited_s=waited)
            self.rw['disk'] = {'before': disk_before, 'after': self.archive_bytes()}
            self.rw['purge'] = purge
            witness, _ = self.restart_role(row, ready_timeout=s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'])
            return
        starts, waited = self.until(lambda: (lambda x: x if x and all(v is not None and stop_position is not None
                                                                      and v > stop_position for v in x.values()) else None)(
            self.follower_log_starts()), s['PURGE_WAIT_S'], 2.0)
        purge.update(log_starts=starts or self.follower_log_starts() or {}, all_log_starts=self.log_starts(),
                     leader=self.leader(), waited_s=waited)
        self.rw['purge'] = purge
        if starts is None:
            raise Inconclusive(f'the followers did not purge above the stopped replica\'s position {stop_position} within '
                               f'{s["PURGE_WAIT_S"]} s: {purge["log_starts"]}')
        start = self.f.restart('shadow0', wait_ready=False)
        x = {'started_at': start['started_at'], 'waited_after_stop_s': start.get('waited_after_kill_s'),
             'replay_failures_setting': self.rm_setting('SHADOW_REBOOTSTRAP_REPLAY_FAILURES'),
             'detector_only': bool(self.variant.get('detector_only')),
             # the refusals a default replica acts on (SHADOW_REBOOTSTRAP_REPLAY_FAILURES default 3)
             'refusals_needed': 3}
        self.rw['rebootstrap'] = x
        cid = self.f.registry['containers']['shadow0']
        bound = s['NOT_TAKEN_BOUND_S'] if self.variant.get('detector_only') else s['REBOOTSTRAP_EXIT_BOUND_S']
        x['bound_s'] = bound
        deadline = time.monotonic() + bound
        counted_at = None
        maxima = {'replay_below_start_max': 'shadow_replica_backup_replay_below_start_total',
                  'rebootstrap_total_max': 'shadow_replica_rebootstrap_total',
                  'not_taken_max': 'shadow_replica_rebootstrap_not_taken_total'}
        while time.monotonic() < deadline:
            if not self.f.inspect('container', cid)['State']['Running']:
                break
            r = self.try_read(self.rm)
            for key, name in maxima.items():
                v = gauge(r, name)
                if v is not None:
                    x[key] = max(x.get(key) or 0, v)
            if self.variant.get('detector_only') and (x.get('replay_below_start_max') or 0) >= x['refusals_needed']:
                # the count a default replica acts on is reached: observe MISSED_OBSERVE_S more for an exit 3 that must
                # not come (the detector counts and never acts)
                counted_at = counted_at or time.monotonic()
                if time.monotonic() - counted_at >= s['MISSED_OBSERVE_S']:
                    break
            self.sleep(0.5)
        state = self.f.inspect('container', cid)['State']
        if state['Running']:
            x['exit_code'] = None
            if self.variant.get('detector_only'):
                x['missed_observed_s'] = None if counted_at is None else round(time.monotonic() - counted_at, 3)
                status, body = self.f.ready_body('shadow0')
                x.update(ready_status=status, ready_body=body)
                self.ledger.heal(row, 'missed_observed' if counted_at is not None else 'still_running', dict(x))
                self.f.close_fault('shadow0')
                return
            raise Inconclusive(f'the replica neither exited nor became ready within {bound} s of its start: {x}')
        x['exit'] = self.f.wait_exit('shadow0', state['ExitCode'], 1)
        x['exit_code'] = state['ExitCode']
        logs = self.f.command(['docker', 'logs', cid], check=False)
        x['restart_line'] = next((l for l in ((logs.stdout or '') + '\n' + (logs.stderr or '')).splitlines()
                                  if RESTART_TEXT in l), None)
        aligned = self.aligned_counts()
        witness, ready_after = self.restart_role(row, ready_timeout=s['OBSERVE_FACTOR'] * s['REPLICA_RESTART_READY_BOUND_S'])
        r = self.try_read(self.rm)
        self.rw['second_life'] = {'restore_path': None if gauge(r, 'shadow_replica_restore_path') is None
                                  else int(gauge(r, 'shadow_replica_restore_path')), 'ready': True,
                                  'ready_after_start_s': ready_after, 'waited_after_exit_s': witness.get('waited_after_kill_s')}
        self.await_aligned(aligned, restarted=True)
