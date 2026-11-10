# SPDX-License-Identifier: Apache-2.0
"""Core-topology drills A01 + A02 on fixture v3, and the scheduled drills on fixture v4.

One fresh fixture per run. Every drill: genesis (``CoreFixture.start(plan)``), the tap for the whole run, the seeded
story (``CoreProbe story``), the fault schedule, the observed heals, the UNKNOWN resolution pass
(gated on the heals), the pre-barrier wait (falls through and is recorded), the two-sample barrier,
backfill of the tap, the sample with its declared block, both oracles, the non-vacuity lines and
the O-F rows. PASS only when both oracles PASS and every line and row holds.

Verdicts: FAIL > INCONCLUSIVE > PASS. A product FAIL, a non-vacuity line that does not hold or a lifecycle-faults
window that was not held is FAIL; a fault whose heal was never observed leaves ``declared.fault_open`` true, which the
oracles answer INCONCLUSIVE, so the drill can never PASS on it (``test_fault_open_resets_twice`` and its sibling).

The pure parts (the ledger, the backfill, the lines, the verdicts, the declared block) take recorded witnesses and are
unit tested on recorded and synthesized samples (``test_core_drills.py``); ``DrillRun`` drives a ``CoreFixture``.
"""
from collections import Counter
import json
import os
from pathlib import Path
import re
import time

from contracts import FP, Inconclusive, Violation, fingerprint
import core_contracts
import core_oracle
import core_scenarios
import journal_decode
import order_oracle
from core_fixture import PROBE_AERON_DIR, READY_AFTER_KILL_S
from oracle_model import BARRIER_COLLECTIONS, RELEASE_KIND, TERMINAL, Model, integer, seq_gaps

A01_USERS = list(range(73001, 73041))         # A7: 256 retained requests per user per 15 min; a01 at 100/s needs >= 29
A02_USERS = [74001, 74002, 74003, 74004]
BRIDGES, FORWARDERS = ('bridge0', 'bridge1'), ('fwd0', 'fwd1')
DRIVER_TIMEOUT_S = 5.0                        # FWD_DRIVER_TIMEOUT_MS / BRIDGE_DRIVER_TIMEOUT_MS = 5000
EXIT70_BOUND_S = DRIVER_TIMEOUT_S + 2         # Exit 70 within FWD_DRIVER_TIMEOUT_MS + 2 s
SESSION_TIMEOUT_S = 10.0                      # AEC:135-141, MEC:149-155
NO_LOSS_AFTER_S = SESSION_TIMEOUT_S + 2       # a thawed process with no exit and no reconnect by then kept its sessions
HEAL_BOUND_S = 60
ELECTION_BOUND_S = 30                         # measured 2.7-2.8 s; the bound only stops a hung wait
PRE_BARRIER_S = 60
# With the outcome records dropped no a02 await can complete, so every one of the story's awaits runs its
# full AWAIT_NS (CoreProbe.AWAIT_NS = 30 s, 43 await calls at most). The RED-2 story, its tap and its bounds are sized for that.
RED2_AWAITS = 43
RED2_AWAIT_S = 30
RED2_STORY_EXTRA_S = RED2_AWAITS * RED2_AWAIT_S
BARRIER_S = 90
PARTITION1_DROP_S = 3.0                       # partition phase 1: both forwarders' ME ingress dropped 3 s
PARTITION1_HEAL_BOUND_S = 30                  # phase-1 reads continue after the delete until the ME seq moves
PHASE1_CADENCE_S = 0.2
WATCH_START_SLACK_S = 5                       # the RED-2 bridge watch starts within 5 s of the load start
WATCH_MAX_GAP_S = 10                          # ... and never leaves 10 s between two rows
WINDOW_PAUSE_BUDGET_S = 4.5                   # lifecycle-faults pauses stay under 5 s (sessions stay open)
GATE_SEQUENCE = [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']]
ME_REFUSALS = ['match_ingress_decode_rejects_total', 'match_ingress_unauthorized_total', 'match_durable_invalid_tif_total',
               'match_durable_invalid_sign_total', 'match_durable_invalid_owner_id_total', 'match_durable_capacity_total']
KIND_NAMES = {0: 'CREATE', 1: 'CANCEL', 2: 'AMEND'}
ICEBERG_DISPLAY = 10 * FP                     # CoreProbe a02 moment 1: ICEBERG qty 30, display 10
# The second lifecycle-faults window is the amend that follows a partial fill (replace_open:1, "amend up
# after a partial fill"); the story exposes replace_open:1/2/3.
WINDOW2_HOLD = 'replace_open:1'


def _a01(seconds=60, rate=100):
    return {'script': 'a01-mix', 'seconds': seconds, 'rate': rate, 'users': A01_USERS}


def _a02():
    return {'script': 'a02-lifecycle', 'seconds': 20, 'rate': 40, 'users': A02_USERS}   # about 400 filler orders (6)


# ``cycles``: fault rows that must be opened and healed (twice where the schedule says so).
DRILLS = {
    'lostack': {'story': _a01(), 'faults': 'lostack', 'cycles': 4, 'lines': ['duplicates_delta', 'bridge_branches']},
    'coreleader': {'story': _a01(), 'faults': 'coreleader', 'cycles': 1, 'lines': ['ae_leader_changed', 'resync_t1_both',
                                                                                    'member_caught_up']},
    'meleader': {'story': _a01(), 'faults': 'meleader', 'cycles': 1, 'lines': ['me_leader_changed', 'resync_t2'],
                 'ordering_exception': True},
    'fwdrestart': {'story': _a01(), 'faults': 'fwdrestart', 'cycles': 2, 'lines': ['fwd_restarts']},
    # 'released_outcome' is a recorded MEASUREMENT (witness.released_after_thaw), not a line. Measured on
    # f-s15-fwdpause-2: both thaws take branch A (exit 70, restart), the restarted fwd0 re-offers nothing, so 0 RELEASED
    # copies are attributable to fwd0 after a thaw; the RELEASED repeats the run does journal are the adjacent second copies
    # of every command that two active forwarders deliver (also present with no pause). A line that must hold would fail
    # always; one that counts those repeats cannot fail without its fault.
    'fwdpause': {'story': _a01(seconds=75), 'faults': 'fwdpause', 'cycles': 2, 'lines': ['duplicates_delta', 'pause_branches']},
    'partition': {'story': _a01(), 'faults': 'partition', 'cycles': 4, 'lines': ['partition_phase1', 'partition_phase2'],
                  'netfilter': True},
    'driverkill': {'story': _a01(), 'faults': 'driverkill', 'cycles': 2, 'lines': ['driver_kills'], 'external_only': True},
    'lifecycle': {'story': _a02(), 'faults': 'none', 'cycles': 0, 'lines': ['lifecycle_story']},
    'lifecycle-faults': {'story': dict(_a02(), hold=f'slice1_exhausting_fill,{WINDOW2_HOLD}'), 'faults': 'lifecycle_faults',
                         'cycles': 6, 'lines': ['lifecycle_story', 'window_lines'], 'ordering_exception': True},
}
# The recorded controls ("both oracles PASS, the named line FAILS"); the variant switches one fault off.
CONTROLS = {
    'lostack-pause3': ('lostack', {'pause_s': 3}, ['bridge_branches']),
    'fwdpause-pause3': ('fwdpause', {'pause_s': 3}, ['pause_branches']),
    'fwdrestart-nokill': ('fwdrestart', {'kill': False}, ['fwd_restarts']),
    'partition-nodrop': ('partition', {'drop': False}, ['partition_phase1', 'partition_phase2']),
    'lifecycle-noiceberg': ('lifecycle', {'without': 'iceberg'}, ['lifecycle_story']),
}
# The REDs run an unchanged drill on a manifest that stages the negative build in both slots.
REDS = {
    'red1': {'drill': 'lostack', 'slots': FORWARDERS, 'artifact': 'forwarder_b'},
    'red2': {'drill': 'lifecycle', 'slots': BRIDGES, 'artifact': 'bridge_b'},
    'red2-negctl': {'drill': 'lifecycle', 'slots': BRIDGES, 'artifact': 'bridge_b', 'data_point': True},
}
RED1_TEXT = 'dispatched commands never applied at the ME'                     # OO:222
RED2_TEXTS = {'O4': ['ME leg', 'ME resting legs != live core legs'], 'M5': ['hold remaining'],
              'O5': ['left the live set without a terminal event', 'is terminal in events but still live'],
              'M4': ['which is not live']}


# ------------------------------------------------------------------ metrics helpers (recorded scrapes)


def value(scrape, role, name, default=None):
    """One sample of a scrape row; ``name`` with labels, or the sum over every label set when given bare."""
    row = (scrape or {}).get(role) or {}
    if 'unavailable' in row:
        return default
    if name in row:
        return row[name]
    hits = [v for k, v in row.items() if k.startswith(name + '{')]
    return sum(hits) if hits else default


def delta(before, after, role, name, restarted=False):
    """Counter delta. A restarted process starts its counters at 0, so its delta is the value after the restart."""
    b, a = value(before, role, name, 0), value(after, role, name)
    if a is None:
        return None
    return a if restarted or a < b else a - b


def max_over(scrape, prefix, name):
    values = [value(scrape, f'{prefix}{i}', name) for i in range(3)]
    values = [v for v in values if v is not None]
    return max(values) if values else None


def leader_of(scrape, engine):
    metric = 'core_cluster_role' if engine == 'ae' else 'match_cluster_role'
    leaders = [f'{engine}{i}' for i in range(3) if value(scrape, f'{engine}{i}', metric) == 2.0]
    return leaders[0] if len(leaders) == 1 else None


# ------------------------------------------------------------------ fault ledger


class Ledger:
    """Every deliberate fault is a row; it is closed only by an OBSERVED heal, with the branch actually taken."""

    def __init__(self, clock=time.time_ns):
        self.rows, self.clock = [], clock

    def open(self, kind, target, witness=None):
        row = {'row': len(self.rows) + 1, 'kind': kind, 'target': target, 'opened_ns': self.clock(),
               'witness': witness or {}, 'heal': None}
        self.rows.append(row)
        return row

    def heal(self, row, branch, witness=None):
        if row['heal'] is not None:
            raise Violation(f'fault row {row["row"]} healed twice')
        row['heal'] = {'branch': branch, 'at_ns': self.clock(), 'witness': witness or {}}
        return row

    def skip(self, kind, target, why, witness=None):
        """A control run records the fault it did NOT inject; the row is not a fault and never opens. ``witness``:
        what the control did instead (fwdring-nopause keeps its bracketed reads, the *-n1 controls their stop)."""
        row = {'row': len(self.rows) + 1, 'kind': kind, 'target': target, 'skipped': why, 'opened_ns': None, 'heal': None}
        if witness is not None:
            row['witness'] = witness
        self.rows.append(row)
        return row

    def faults(self):
        return [r for r in self.rows if 'skipped' not in r]

    def open_rows(self):
        return [r for r in self.faults() if r['heal'] is None]

    def fault_open(self):
        return bool(self.open_rows())


def declared_block(ledger, genesis_id, ordering_exception=None, gate_sequence=None, halt=False, order_fault=0):
    """Zero faults, no halt, gate sequence and epochs; ``fault_open`` from the ledger, never assumed.
    The gate sequence, the halt and the order-fault count per drill and life (declared_for)."""
    return {'settle_fault': 0, 'settle_rejected': 0, 'order_fault': order_fault, 'quarantined': 0, 'halt': halt,
            'fault_open': ledger.fault_open(), 'forwarder_absent': False,
            'gate_sequence': GATE_SEQUENCE if gate_sequence is None else gate_sequence,
            'epochs': [genesis_id], 'ordering_exception': ordering_exception}


# ------------------------------------------------------------------ tap backfill


def backfill(tap_rows, pending_entries, me_journal, known_orders, head):
    """Rows for dispatches the tap missed, only inside its gaps against [1, core head] (A11: a missing TAIL is a gap).

    Still pending at the barrier: from ``pending-dump`` with their seq. Already resolved at the ME: the command from its
    first ME outcome, ``seq: null``. A RELEASE_ID dispatch leaves no outcome; it is rebuilt from the ME release record
    entry (commandIdHigh, idLowFloor) only when every RELEASE_ID row the tap DID see maps onto such an entry, i.e. the
    mapping is verified on this run's own data; otherwise its slot stays open and the run is INCONCLUSIVE. With no gap,
    nothing is backfilled: an ME outcome without a dispatch then stays the O3 FAIL it is."""
    tapped = [r for r in tap_rows if r.get('source') != 'backfill']
    seqs = [r['seq'] for r in tapped]
    high = max([head if type(head) is int else 0] + seqs) if seqs or type(head) is int else 0
    gaps = seq_gaps(seqs, 1, high)
    report = {'gaps': gaps, 'release_mapping': None, 'rows': 0}
    if not gaps:
        return [], report

    def in_gap(seq):
        return any(a <= seq <= b for a, b in gaps)

    commands = {(r['id_high'], r['id_low']) for r in tapped if r['kind'] != RELEASE_KIND}
    releases = {(r['id_high'], r['id_low']) for r in tapped if r['kind'] == RELEASE_KIND}
    rows, seen = [], set(seqs)
    for entry in pending_entries or []:
        if entry['seq'] in seen or not in_gap(entry['seq']):
            continue
        seen.add(entry['seq'])
        rows.append(dict(entry, source='backfill', origin='pending'))
        (releases if entry['kind'] == RELEASE_KIND else commands).add((entry['id_high'], entry['id_low']))
    for event in me_journal:
        if event['type'] != 'outcome':
            continue
        key = (event['command_id_high'], event['command_id_low'])
        if key in commands or key[0] not in known_orders:
            continue
        commands.add(key)
        rows.append({'seq': None, 'id_high': key[0], 'id_low': key[1], 'kind': KIND_NAMES.get(key[1] & 3, 'UNKNOWN'),
                     'order': event['order'], 'user': event['user'], 'old_leg': event['old_leg'], 'market': event['market'],
                     'price': event['price'], 'quantity': event['quantity'], 'budget': event.get('budget', 0), 'at_ms': None,
                     'source': 'backfill', 'origin': 'me_outcome'})
    entries = []
    for event in me_journal:
        if event['type'] == 'release':
            entries += [(e['commandIdHigh'], e['idLowFloor']) for e in event.get('releases') or []]
    tapped_releases = {(r['id_high'], r['id_low']) for r in tapped if r['kind'] == RELEASE_KIND}
    verified = bool(tapped_releases) and tapped_releases <= set(entries)
    report['release_mapping'] = 'verified' if verified else 'unverified'
    if verified:
        for key in dict.fromkeys(entries):
            if key in releases or key[0] not in known_orders:
                continue
            releases.add(key)
            rows.append({'seq': None, 'id_high': key[0], 'id_low': key[1], 'kind': RELEASE_KIND, 'order': 0, 'user': 0,   # wire shape
                         'old_leg': 0, 'market': 0, 'price': 0, 'quantity': 0, 'budget': 0, 'at_ms': None,
                         'source': 'backfill', 'origin': 'me_release'})
    report['rows'] = len(rows)
    return rows, report


# ------------------------------------------------------------------ non-vacuity lines, each can fail


def _line(holds, detail, inconclusive=False):
    """``inconclusive``: the line's witness is missing or vacuous (a gap, a window never bracketed): the run can never
    PASS on it and it is not a product FAIL either ("a gap or missing witness is INCONCLUSIVE, never PASS")."""
    line = {'holds': bool(holds) and not inconclusive, 'detail': detail}
    if inconclusive:
        line['inconclusive'] = True
    return line


def _rows(w, kind=None, target=None):
    return [r for r in w['ledger'] if 'skipped' not in r and (kind is None or r['kind'] == kind)
            and (target is None or r['target'] == target)]


def line_fault_cycles(w):
    """The drill opened exactly its ``cycles`` fault rows. Whether each was healed is ``declared.fault_open``: an
    unhealed row makes the run INCONCLUSIVE (verdict), never this line's FAIL and never a PASS."""
    rows = _rows(w)
    healed = [r for r in rows if r['heal'] is not None]
    want = w['expect_cycles']
    return _line(len(rows) == want, f'{len(rows)} fault rows opened ({len(healed)} healed), the drill defines {want}')


def line_duplicates_delta(w):
    before = max_over(w['snaps']['before'], 'me', 'match_durable_duplicates_suppressed_total')
    after = max_over(w['snaps']['after'], 'me', 'match_durable_duplicates_suppressed_total')
    d = None if before is None or after is None else after - before
    return _line(d is not None and d > 0, f'match_durable_duplicates_suppressed_total delta {d}')


def line_bridge_branches(w):
    """lostack: each bridge took branch A (exit 70 observed, restart, /ready 200) or B (/health coreConnected false or
    /ready 503 seen, then bridge_client_sessions_opened_total delta >= 1). A pause that closed nothing is neither."""
    out = {}
    for bridge in BRIDGES:
        rows = _rows(w, 'pause', bridge)
        heal = rows[0]['heal'] if rows else None
        branch = heal and heal['branch']
        hw = (heal or {}).get('witness', {})
        ok = branch == 'A' and hw.get('exit_code') == 70 and hw.get('ready') is True or \
            branch == 'B' and hw.get('saw_down') is True and (hw.get('reconnect_delta') or 0) >= 1
        out[bridge] = {'branch': branch, 'ok': ok}
    return _line(all(v['ok'] for v in out.values()), out)


def line_pause_branches(w):
    """fwdpause, both pauses of fwd0: A = exit 70 within EXIT70_BOUND_S of the thaw, restart, resync after restart > 0;
    B = forwarder_session_reconnect_total delta >= 1 on both clusters and resync delta > 0."""
    rows = _rows(w, 'pause', 'fwd0')
    out = []
    for row in rows:
        heal = row['heal'] or {}
        hw = heal.get('witness', {})
        branch = heal.get('branch')
        if branch == 'A':
            ok = hw.get('exit_code') == 70 and (hw.get('exit_after_thaw_s') or 1e9) <= EXIT70_BOUND_S and (hw.get('resync_delta') or 0) > 0
        elif branch == 'B':
            ok = all((hw.get('reconnect_delta_by_cluster') or {}).get(c, 0) >= 1 for c in ('core', 'me')) and (hw.get('resync_delta') or 0) > 0
        else:
            ok = False
        out.append({'row': row['row'], 'branch': branch, 'ok': ok})
    return _line(len(out) == 2 and all(r['ok'] for r in out), out)


def line_released_outcome(w):
    """At least one leg-less RELEASED (7) repeat journaled AFTER fwd0's thaw for an order that
    was ORDER-released WHILE fwd0 was paused (the ME journal seq read just before the pause and just after the thaw
    brackets both), and the core's release NOOP counter moved. Repeats from outside the pause window do not count."""
    attributed = w.get('released_after_thaw')
    d = delta(w['snaps']['before'], w['snaps']['after'], w['ae_leader_after'] or 'ae0', 'core_release_confirm_stale_total')
    n = sum(attributed or [])
    return _line(attributed is not None and n >= 1 and (d or 0) >= 1,
                 f'RELEASED repeats after the thaw of fwd0 for orders released during its pause {attributed} '
                 f'(all RELEASED repeats in the run {w["released_repeats"]}), core_release_confirm_stale_total delta {d}')


def late_copies_after_thaw(model, ledger_rows):
    """Per pause of fwd0: outcome copies (any result) journaled after the thaw for a command whose FIRST outcome was
    journaled while fwd0 was paused. Only fwd0 can deliver such a copy (fwd1 delivered the first one), so this is the
    count of frames the thawed or restarted fwd0 put on the wire (measurement). None without a bracketed pause."""
    out = []
    for row in ledger_rows:
        w = row.get('witness') or {}
        if row.get('kind') != 'pause' or row.get('target') != 'fwd0':
            continue
        lo, hi = w.get('me_seq_pause'), w.get('me_seq_thaw')
        if lo is None or hi is None:
            return None
        out.append(sum(1 for key, copies in model.outcome_copies.items() if lo < model.first_outcome[key]['journal_seq'] <= hi
                       for c in copies if c['journal_seq'] > hi))
    return out or None


def released_after_thaw(model, ledger_rows):
    """Per pause of fwd0 (rows carrying me_seq_pause / me_seq_thaw): the number of RELEASED repeats journaled after the
    thaw whose order carried an ORDER release journaled between the pause and the thaw. None without a bracketed pause."""
    out = []
    for row in ledger_rows:
        w = row.get('witness') or {}
        if row.get('kind') != 'pause' or row.get('target') != 'fwd0':
            continue
        lo, hi = w.get('me_seq_pause'), w.get('me_seq_thaw')
        if lo is None or hi is None:
            return None
        orders = set()
        for e in model.journal:
            if e['type'] == 'release' and lo < e['journal_seq'] <= hi:
                orders.update(integer(r['commandIdHigh']) for r in e.get('releases') or [] if r.get('scope') == 'ORDER')
        out.append(sum(1 for e in model.released_repeats
                       if e['journal_seq'] > hi and integer(e['command_id_high']) in orders))
    return out or None


def line_ae_leader_changed(w):
    rows = _rows(w, 'kill')
    killed = [r for r in rows if r['target'].startswith('ae') and r['witness'].get('was_leader')]
    new = [r['witness'].get('new_leader') for r in killed]
    return _line(killed and all(n and n != r['target'] for n, r in zip(new, killed)),
                 [{'killed': r['target'], 'new_leader': r['witness'].get('new_leader'),
                   'election_s': r['witness'].get('election_s')} for r in killed])


def line_me_leader_changed(w):
    rows = _rows(w, 'kill')
    killed = [r for r in rows if r['target'].startswith('me') and r['witness'].get('was_leader')]
    return _line(killed and all(r['witness'].get('new_leader') not in (None, r['target']) for r in killed),
                 [{'killed': r['target'], 'new_leader': r['witness'].get('new_leader'),
                   'election_s': r['witness'].get('election_s')} for r in killed])


def _resync(w, reason, fwd):
    name = f'forwarder_resync_total{{reason="{reason}"}}'
    return delta(w['snaps']['before'], w['snaps']['after'], fwd, name, restarted=fwd in w.get('restarted', ()))


def line_resync_t1_both(w):
    d = {fwd: _resync(w, 'T1', fwd) for fwd in FORWARDERS}
    return _line(all((v or 0) > 0 for v in d.values()), d)


def line_resync_t2(w):
    d = {fwd: _resync(w, 'T2', fwd) for fwd in FORWARDERS}
    return _line(any((v or 0) > 0 for v in d.values()), d)


def line_member_caught_up(w):
    """coreleader (a substitution): the restarted AE member is /ready 200 and its commit position
    equals the leader's (the member's money journal archive is not readable from the probe)."""
    positions = w.get('ae_commit_positions') or {}
    rows = [r for r in _rows(w, 'kill') if r['target'].startswith('ae')]
    member = rows[0]['target'] if rows else None
    restarted_ready = bool(rows) and (rows[0]['heal'] or {}).get('witness', {}).get('ready') is True
    leader = w.get('ae_leader_after')
    # An idle AE log still grows about 1.3 KB/s (leader heartbeat entries), so three sequential /ready reads never show
    # equal numbers (first run: 12528576, 12529216, 12529984). The leader is read before and after the member: "equal to the
    # leader's" means the member's position lies inside that window. No slack: every recorded run needed none.
    window = w.get('ae_commit_leader_window') or ([positions[leader]] * 2 if leader in positions else None)
    ok = bool(restarted_ready and member in positions and window and window[0] <= positions[member] <= window[1])
    return _line(ok, {'member': member, 'leader': leader, 'commit': positions, 'leader_window': window})


def line_fwd_restarts(w):
    """fwdrestart: each forwarder exit 137 then /ready 200; resync after its restart > 0; the other forwarder did not
    resync over that window."""
    out = {}
    for fwd in FORWARDERS:
        rows = _rows(w, 'kill', fwd)
        if not rows:
            out[fwd] = {'ok': False, 'why': 'no kill'}
            continue
        hw = (rows[0]['heal'] or {}).get('witness', {})
        ok = rows[0]['witness'].get('exit_code') == 137 and hw.get('ready') is True and (hw.get('resync_after') or 0) > 0 \
            and hw.get('peer_resync_delta') == 0
        out[fwd] = {'ok': ok, 'resync_after': hw.get('resync_after'), 'peer_resync_delta': hw.get('peer_resync_delta')}
    return _line(all(v['ok'] for v in out.values()), out)


def line_partition_phase1(w):
    """ME first-apply gap > 3 s, proven by reads (lower bound) that cover the heal."""
    p = w.get('partition') or {}
    stall = p.get('me_stall_s')
    return _line(stall is not None and stall > PARTITION1_DROP_S,
                 f'ME first-apply gap >= {stall} s (first to last read at the stalled seq; outer bracket {p.get("me_stall_upper_s")} s) while '
                 f'the core head advanced; heal observed {p.get("phase1_heal_observed")}')


def line_partition_phase2(w):
    """A14: the 15 s drop of the AE leader's ingress closes the core session by TIMEOUT: reconnect or new-leader delta > 0."""
    p = (w.get('partition') or {}).get('phase2') or {}
    per = {fwd: (p.get(fwd) or {}) for fwd in FORWARDERS}
    ok = bool(p) and all((v.get('reconnect_core') or 0) + (v.get('new_leader_core') or 0) > 0 for v in per.values())
    return _line(ok, per)


def line_driver_kills(w):
    """driverkill: exit 70 within the bound both times; the second kill hit the driver the first restart started (A4:
    the identity is cnc.dat mtime + container StartedAt; the in-container pid is always 9)."""
    rows = _rows(w, 'exec_kill', 'fwd0')
    exits = [(r['heal'] or {}).get('witness', {}).get('exit', {}) for r in rows]
    ok = len(rows) == 2 and all(e.get('exit_code') == 70 and (e.get('waited_s') or 1e9) <= EXIT70_BOUND_S for e in exits)
    if ok:
        first_new = ((rows[0]['heal'] or {}).get('witness', {}).get('restart') or {}).get('driver', {}).get('new')
        ok = first_new is not None and rows[1]['witness'].get('identity_before') == first_new
    return _line(ok, [{'exit': e, 'identity_before': r['witness'].get('identity_before')} for r, e in zip(rows, exits)])


def lifecycle_counts(sample):
    """Lifecycle line: the story summary read from the core's own events and the tap (never from the story's claims)."""
    model = Model(sample)
    events = sample['core_events']
    terminal = {}
    for e in events:
        if e['status'] in {'FILLED', 'CANCELLED', 'REJECTED', 'EXPIRED'}:
            terminal.setdefault(e['order'], e)
    market1 = {oid: c for oid, c in model.orders.items() if c['market'] == 1}
    icebergs = [oid for oid, c in market1.items() if c['type'] == 'ICEBERG']
    slices = sum(sum(1 for r in model.tap.values() if r['order'] == oid and r['kind'] == 'CREATE') for oid in icebergs)
    replaced = sum(1 for e in events if e['kind'] == 'REPLACED' and e['order'] in market1)
    def ends(tif, status, filled):
        return sum(1 for oid, c in market1.items() if c['tif'] == tif and c['type'] == 'LIMIT'
                   and (terminal.get(oid) or {}).get('status') == status and filled((terminal.get(oid) or {}).get('filled', 0)))
    stops = [oid for oid, c in market1.items() if c['type'] == 'STOP_LOSS']
    return {'slices_refilled': max(slices - len(icebergs), 0), 'replace_windows': replaced,
            'ioc_partial': ends('IOC', 'EXPIRED', lambda f: f > 0), 'fok_kill': ends('FOK', 'EXPIRED', lambda f: f == 0),
            'fok_fill': ends('FOK', 'FILLED', lambda f: True),
            'stop_trigger': sum(1 for e in events if e['kind'] == 'TRIGGERED' and e['order'] in stops),
            'gtd_expiry': ends('GTD', 'EXPIRED', lambda f: True)}


LIFECYCLE_EXPECTED = {'slices_refilled': 2, 'replace_windows': 3, 'ioc_partial': 1, 'fok_kill': 1, 'fok_fill': 1,
                      'stop_trigger': 1, 'gtd_expiry': 1}


def line_lifecycle_story(w):
    counts = w['lifecycle_counts']
    return _line(counts == LIFECYCLE_EXPECTED, {'observed': counts, 'expected': LIFECYCLE_EXPECTED})


def line_window_lines(w):
    """lifecycle-faults: both windows held (bridges paused < 5 s, the ME journaled the records before the kill,
    the kill observed, the bridges thawed) and the core closed each window once after the new term."""
    windows = w.get('windows') or {}
    counts = w['lifecycle_counts']
    out = {}
    for name in ('slice1', 'replace'):
        win = windows.get(name) or {}
        out[name] = {'held': win.get('held') is True, 'killed': win.get('killed'), 'pause_s': win.get('pause_s'),
                     'journal': win.get('journal')}
    closed = w.get('window_closures') or {}
    ok = all(v['held'] and v['killed'] for v in out.values()) and closed.get('slice1') == 1 \
        and closed.get('replace_replaced') == 1 and closed.get('replace_terminals') == 1
    return _line(ok, {'windows': out, 'closures': closed, 'counts': counts})


LINES = {name[5:]: fn for name, fn in globals().items() if name.startswith('line_')}


def window_closures(sample, windows):
    """Window 1 closed once: the iceberg parent has exactly one terminal event. Window 2: the amended order exactly one
    REPLACED event and one terminal."""
    events = sample['core_events']
    out = {}
    parent = (windows.get('slice1') or {}).get('order')
    if parent is not None:
        out['slice1'] = sum(1 for e in events if e['order'] == parent and e['status'] in {'FILLED', 'CANCELLED', 'EXPIRED', 'REJECTED'})
    amended = (windows.get('replace') or {}).get('order')
    if amended is not None:
        out['replace_replaced'] = sum(1 for e in events if e['order'] == amended and e['kind'] == 'REPLACED')
        out['replace_terminals'] = sum(1 for e in events if e['order'] == amended
                                       and e['status'] in {'FILLED', 'CANCELLED', 'EXPIRED', 'REJECTED'})
    return out




# ================================================================== scheduled drills on fixture v4
#
# Settings, never acceptance limits tied to one machine: every one is recorded with every run (SETTINGS).

A03_CAPACITY = 2000                           # H:577-580; the ME accepts 2000 at FRESH
A03_PAUSE_S = 2.5                             # fwd1's window pause, below WINDOW_PAUSE_BUDGET_S
A03_SIGNALS = 'a03-signals'                   # The probe /data dir the fixture writes capacity_closed / capacity_open in
FWDRING_PAUSE_S = 2.5
IOC_BURST_FILE = 'ioc-burst'                  # --ioc-burst-on, enabled for fwdring line 12
A05_USERS = list(range(75001, 75081))         # 80 users for 90 s at 100/s
A04_LIFE2_USERS = list(range(76001, 76041))   # 40 fresh ids in life 2
EDK_USERS = list(range(77001, 77081))
A04_HALT_PHASE_S = 60                         # life-1 tap beyond the story: freeze, regenesis('me'), fence, halt, halt-time funding
                                              # measured: the halt ~5 s and the funding done ~12 s after the ME restart
                                              # (polite stops 0.2-0.3 s),
                                              # then 640 s idle on 420; the default is 60 s, a setting (SETTINGS)
SETTINGS = {
    'A05_P999_SLACK_MS': 20,                  # swap p99.9 <= baseline p99.9 + slack; default 20 ms (the replacement's session setup costs 16-28 ms on the 1-CPU ME; raised from 10 on 2026-11-05)
    'A05_DUP_EDGE_SLACK': 10,                 # the in-flight count at the window edges; measured duplicates - dispatches = -1
    'A05_SETTLE_LAG_SLACK': 40,               # [E] trades; measured a lag of 10-36 trades
    'SWAP_WINDOW_MIN_S': 1.0,                 # measured swap windows of 1.45-1.49 s
    'SURVIVOR_MAX_GAP_S': 1.0,                # inside a ~1.5 s window a 2 s gap could never show
    'SERVED_MAX_GAP_S': 2.0,                  # cluster_served
    'SAMPLER_PERIOD_S': 1.0,                  # the 1 s sampler
    'A05_SAMPLER_PERIOD_S': 0.25,             # the swap windows need several rows
    'READY_AFTER_KILL_S': READY_AFTER_KILL_S,
    'DRIVER_DEATH_BOUND_S': 18,               # Aeron client driver timeout 10 s + 5 s grace + 3 s
    'CNC_TIMEOUT_BOUND_S': 35,                # 30 s cnc wait (TC:73) + 5 s, measured from the engine's own wait start (its
                                              # "Driver mode EXTERNAL: connecting" log line), never from the container spawn
    'A04_HALT_PHASE_S': A04_HALT_PHASE_S,     # the life-1 tap's extra seconds for the halt phase
    'EARLY_RESTART_AFTER_S': 0.8,             # a04-earlyrestart: bridge0 restarted this long after its kill (within 1 s)
    'EARLY_PEER_PAUSE_BUDGET_S': WINDOW_PAUSE_BUDGET_S,   # a04-earlyrestart: bridge1's freeze stays under the session budget
    'A05_N1_HOLD_S': 5.0,                     # the N = 1 controls hold the single slot down this long before the replacement
                                              # (a 1.1 s window left the n1 controls within their slack)
    'TICK_SETTLE_S': 1.0,                     # A06: ticks fwd0 offered before SIGKILL commit within this time after the kill
    'ENGINE_SHUTDOWN_TIMEOUT_S': 4.0,         # the engines' ENGINE_SHUTDOWN_TIMEOUT_MS default (cluster-kit EngineLifecycle:49);
                                              # the fixture sets no override. Measured SIGTERM -> 143 in 0.17-0.29 s
    'ENGINE_STOP_SLACK_S': 1.0,               # docker kill + docker stop round trip on top of the shutdown timeout
    'ENGINE_STOP_EXIT': 143,                  # SIGTERM exits with the signal's status
    'FENCE_BOUND_S': 15,                      # fenced_forwarders (measured 3.7 s, F8_EPOCH)
    'BRIDGE_HALT_BOUND_S': 30,                # A04 (measured 6.7 and 9.7 s)
    'COLD_RESTART_LEAD': 300,                 # cold_restart_skips: the peer passed the ME seq at the kill + 300
    'COLD_RESTART_BOUND_S': 30,
    'FWDRING_PAUSE_S': FWDRING_PAUSE_S, 'A03_PAUSE_S': A03_PAUSE_S, 'A03_CAPACITY': A03_CAPACITY,
}
PROGRESS = 'match_engine_next_journal_seq'    # ME progress: the journal sequence; match_orders_submitted_total does not move
GATE_REASON_ME_CAPACITY = 16                  # core_order_entry_gate_reasons is a mask 1 << code (ME_CAPACITY 4)
SOURCE_SCHEMA = 3                             # BMR:420 bridge_halt_reason 3; core_feed_latch_reason 3
GATE_A03 = GATE_SEQUENCE + [['SUSPENDED', 'ME_CAPACITY'], ['OPEN', 'ADMIN']]
GATE_A04_HALT = GATE_SEQUENCE + [['SUSPENDED', 'BRIDGE_HALT']]
RED_A03_TEXT = "gate transitions [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN'], ['SUSPENDED', 'ME_CAPACITY']] != declared"
RED_A04_TEXT = "gate transitions [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']] != declared"


def _drill_story(seconds, users, **more):
    return dict({'script': 'a01-mix', 'seconds': seconds, 'rate': 100, 'users': users}, **more)


# ``cycles``: the fault rows each run opens and heals.
DRILLS.update({
    'a03-lifetime': {'schedule_v4': True, 'faults': 'a03', 'cycles': 3, 'ledger_capacity': A03_CAPACITY,
                     'story': {'script': 'a03-fill', 'rate': 100, 'fill_s': 30, 'reopen_s': 10, 'marker_timeout_s': 60,
                               'users': A01_USERS},
                     'lines': ['capacity_cycle', 'release_once', 'release_resent', 'reopen_admits']},
    'a04-regenesis': {'schedule_v4': True, 'faults': 'a04', 'cycles': 1, 'story': _drill_story(40, A01_USERS), 'life2_users': A04_LIFE2_USERS,
                      'tap_extra_setting': 'A04_HALT_PHASE_S',
                      'lines': ['halt_local', 'open_refused', 'money_while_halted', 'fenced_forwarders', 'engine_polite_stop']},
    'a04-one-bridge-halt': {'schedule_v4': True, 'faults': 'one_bridge_halt', 'cycles': 1, 'story': _drill_story(60, A01_USERS),
                            'lines': ['cold_restart_skips', 'bridge_never_halted']},
    'a05-fwd-upgrade': {'schedule_v4': True, 'faults': 'a05', 'swap': 'fwd', 'how': 'stop', 'cycles': 2, 'story': _drill_story(90, A05_USERS),
                        'lines': ['build_witness', 'no_delay', 'survivor_delivered', 'dup_outcomes']},
    'a05-fwd-kill': {'schedule_v4': True, 'faults': 'a05', 'swap': 'fwd', 'how': 'kill', 'cycles': 2, 'story': _drill_story(90, A05_USERS),
                     'lines': ['build_witness', 'no_delay', 'survivor_delivered', 'dup_outcomes', 'ready_after_kill']},
    'a05-bridge-upgrade': {'schedule_v4': True, 'faults': 'a05', 'swap': 'bridge', 'how': 'stop', 'cycles': 2,
                           'story': _drill_story(90, A05_USERS), 'lines': ['build_witness', 'settle_no_gap', 'bridge_never_halted']},
    # A05-keep, one forwarder and one bridge replaced with keep_state=True (the unit restart shape)
    'a05-keep': {'schedule_v4': True, 'faults': 'a05', 'swap': 'both', 'how': 'stop', 'keep_state': True, 'cycles': 2,
                 'story': _drill_story(90, A05_USERS), 'lines': ['build_witness', 'no_delay', 'settle_no_gap', 'keep_state']},
    'a06-two-forwarders-ticks': {'schedule_v4': True, 'faults': 'a06', 'cycles': 1, 'story': _drill_story(60, A01_USERS),
                                 'lines': ['tick_conservation', 'tick_stale_positive', 'tick_end_state', 'tick_invalid_zero',
                                           'tick_survivor']},
    'a01-fwdring': {'schedule_v4': True, 'faults': 'fwdring', 'cycles': 2,
                    'story': _drill_story(75, A01_USERS, ioc_burst_on='/data/' + IOC_BURST_FILE),
                    'lines': ['ring_outlived_thaw', 'released_after_thaw']},
    'c13-enginedriverkill': {'schedule_v4': True, 'faults': 'edk', 'cycles': 3, 'story': _drill_story(120, EDK_USERS),
                             'lines': ['driver_death_loud', 'cluster_served']},
})
# The ten recorded controls of the drills (edk-cnctimeout has its own boot, run_cnc_timeout; a05-fwd-badproto is
# dropped)
CONTROLS.update({
    'a03-cap100k': ('a03-lifetime', {'ledger_capacity': 100_000}, ['capacity_cycle', 'reopen_admits']),
    'a03-nokill': ('a03-lifetime', {'hold': False}, ['release_resent']),
    'a04-noregen': ('a04-regenesis', {'regen': False}, ['open_refused', 'money_while_halted', 'fenced_forwarders']),
    'a04-earlyrestart': ('a04-one-bridge-halt', {'early': True}, ['cold_restart_skips']),
    'a05-fwd-upgrade-n1': ('a05-fwd-upgrade', {'n1': True}, ['no_delay', 'survivor_delivered', 'dup_outcomes']),
    'a05-bridge-upgrade-n1': ('a05-bridge-upgrade', {'n1': True}, ['settle_no_gap']),
    'a06-n1': ('a06-two-forwarders-ticks', {}, ['tick_stale_positive', 'tick_survivor']),
    'fwdring-pause15': ('a01-fwdring', {'pause_s': 15}, ['ring_outlived_thaw', 'released_after_thaw']),
    'fwdring-nopause': ('a01-fwdring', {'pause': False}, ['ring_outlived_thaw', 'released_after_thaw']),
    'edk-nokill': ('c13-enginedriverkill', {'kill': False}, ['driver_death_loud', 'cluster_served']),
})
REDS.update({
    'red-a03': {'drill': 'a03-lifetime', 'slots': FORWARDERS, 'artifact': 'forwarder_b'},     # s16-red-a03.json
    'red-a04': {'drill': 'a04-regenesis', 'slots': BRIDGES, 'artifact': 'bridge_b'},          # s16-red-a04.json, life 1
})


def story_seconds(story):
    """Nominal wall seconds of a story: a03-fill has phases, not seconds=."""
    if story['script'] == 'a03-fill':
        return story['fill_s'] + story['marker_timeout_s'] + story['reopen_s']
    return story['seconds']


def funding_script(story):
    """CoreProbe funding knows a01-mix and a02-lifecycle; a03-fill trades in the a01 bands (CP planA03)."""
    return 'a01-mix' if story['script'] == 'a03-fill' else story['script']


def declared_for(drill, variant, life):
    """Section 7 per drill and life. The controls that switch the close or the halt off declare the two-step sequence
    ("the control declares the two-step sequence so the oracles PASS")."""
    variant = variant or {}
    if drill == 'a03-lifetime' and variant.get('hold', True) and variant.get('ledger_capacity', A03_CAPACITY) <= A03_CAPACITY:
        return {'gate_sequence': GATE_A03, 'halt': False, 'order_fault': 0}
    if drill == 'a04-regenesis' and life == 1 and variant.get('regen', True):
        return {'gate_sequence': GATE_A04_HALT, 'halt': True, 'order_fault': 1}
    return {'gate_sequence': GATE_SEQUENCE, 'halt': False, 'order_fault': 0}


# ------------------------------------------------------------------ latency table


def percentile(values, q):
    """Nearest rank: the smallest value with at least q of the values at or below it."""
    ordered = sorted(values)
    if not ordered:
        return None
    rank = max(1, -(-int(round(q * 10000)) * len(ordered) // 10000))
    return ordered[min(rank, len(ordered)) - 1]


def lat_summary(values):
    return {'count': len(values), 'p50': percentile(values, 0.5), 'p99': percentile(values, 0.99),
            'p99.9': percentile(values, 0.999), 'max': max(values) if values else None}


def latency_table(dispatch_rows, me_journal):
    """Per command id: the dispatch's cluster ms (the tap row's at_ms is the egress header timestamp, the cluster time of
    the log entry that minted the dispatch, CP:2183-2191, 2398-2400) to the ME's first record-3 ``timestamp`` (ME cluster
    ms, one host). RELEASE_ID rows repeat a create's id after its outcome and are excluded (they made an earlier run's
    41 percent negative differences); backfilled rows (seq null) have no dispatch time."""
    first = {}
    for e in me_journal:
        if e['type'] == 'outcome' and e.get('timestamp') is not None:
            first.setdefault((e['command_id_high'], e['command_id_low']), e['timestamp'])
    table = []
    for row in dispatch_rows:
        if row.get('kind') == RELEASE_KIND or row.get('seq') is None or row.get('at_ms') is None:
            continue
        key = (row['id_high'], row['id_low'])
        if key in first:
            table.append({'seq': row['seq'], 'id': list(key), 'dispatch_ms': row['at_ms'], 'first_apply_ms': first[key],
                          'ms': first[key] - row['at_ms']})
    return table


def window_summaries(table, windows):
    """``windows``: {name: [(lo_ms, hi_ms), ...]} half-open on the dispatch ms; a summary per name over the union."""
    out = {}
    for name, spans in windows.items():
        out[name] = lat_summary([r['ms'] for r in table if any(lo <= r['dispatch_ms'] < hi for lo, hi in spans)])
    return out


# ------------------------------------------------------------------ sampler rows (the 1 s sampler)


def s_value(row, who, name):
    """A value of one sampler row: ``who`` is a role, or 'ae' / 'me' for that engine's leader in the same row."""
    roles = (row or {}).get('roles') or {}
    if who in ('ae', 'me'):
        who = leader_of(roles, who)
        if who is None:
            return None
    return value(roles, who, name)


def series(samples, who, name):
    """[(t, value)] of the rows that answered; t is the read's midpoint (wall s)."""
    out = []
    for row in samples or []:
        v = s_value(row, who, name)
        if v is not None:
            out.append(((row['t0'] + row['t1']) / 2, v))
    return out


def progress(points, lo, hi, inside=False):
    """Inside [lo, hi] (wall s): the times the value rose against the row before, and the longest span between lo, those
    rises and hi. Returns (rises, max_gap_s, rows_in_window). ``inside``: the first row in the window is the reference,
    so a rise that happened before lo (read by the first row inside) is not counted (A06 tick_survivor)."""
    rises, prev, n = [], None, 0
    for t, v in points:
        if t > hi:
            break
        if t < lo and inside:
            continue
        if t >= lo:
            n += 1
            if prev is not None and v > prev:
                rises.append(t)
        prev = v
    marks = [lo] + rises + [hi]
    gap = max(b - a for a, b in zip(marks, marks[1:]))
    return rises, round(gap, 3), n


def at_or_before(points, t):
    hits = [v for tt, v in points if tt <= t]
    return hits[-1] if hits else None


def release_entries(me_journal):
    return [(e['journal_seq'], r) for e in me_journal if e['type'] == 'release' for r in e.get('releases') or []]


def parse_book(text):
    """``T1MeDriver book`` lines: ``BOOK market=1 version=V bid=B ask=A ...`` or ``BOOK market=2 none`` (a06.log)."""
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'BOOK market=(\d+) (.*)$', line.strip())
        if not m:
            continue
        rest = m.group(2)
        if rest.strip() == 'none':
            out[int(m.group(1))] = None
            continue
        kv = dict(re.findall(r'(\w+)=(-?\d+)', rest))
        out[int(m.group(1))] = {'version': int(kv['version']), 'bid': int(kv['bid']), 'ask': int(kv['ask'])}
    return out


# ------------------------------------------------------------------ lines of the scheduled drills


def line_capacity_cycle(w):
    """A03: the AE leader's estimate peaks >= 0.8 c and later reads <= 0.6 c; the tap shows [SUSPENDED, ME_CAPACITY]
    then [OPEN, ADMIN]; gate reasons bit ME_CAPACITY (16) seen in a sample. The ME ledger gauge is evidence only."""
    c = w['capacity']
    est = series(w['samples'], 'ae', 'core_me_capacity_estimate')
    values = [v for _, v in est]
    if not values:          # An empty sampler series is a missing witness, never a FAIL
        return _line(False, {'why': 'no sampler row answered core_me_capacity_estimate on the AE leader', 'capacity': c},
                     inconclusive=True)
    peak = max(values) if values else None
    i = values.index(peak) if values else None
    later = min(values[i:]) if values else None
    gate = [[a['state'], a['reason']] for a in w['admission'] if a['market'] == 0]
    compact = [s for n, s in enumerate(gate) if n == 0 or s != gate[n - 1]]
    closed = ['SUSPENDED', 'ME_CAPACITY'] in compact
    reopened = closed and ['OPEN', 'ADMIN'] in compact[compact.index(['SUSPENDED', 'ME_CAPACITY']):]
    bit = any(int(v) & GATE_REASON_ME_CAPACITY for _, v in series(w['samples'], 'ae', 'core_order_entry_gate_reasons'))
    ledger = [v for _, v in series(w['samples'], 'me', 'match_command_ledger_size')]
    holds = peak is not None and peak >= 0.8 * c and later <= 0.6 * c and closed and reopened and bit
    detail = {'capacity': c, 'estimate_peak': peak, 'estimate_after_peak_min': later, 'tap_closed': closed,
              'tap_reopened': reopened, 'reasons_bit_seen': bit, 'me_ledger_peak': max(ledger) if ledger else None,
              'samples': len(values)}
    if not closed:
        detail['why'] = 'no close observed'
    return _line(holds, detail)


def line_release_once(w):
    """A03 (the drain is the forwarder swap, no cancel wave): the record-4 entries free at least what
    the ME ledger held at its peak (and every ORDER-terminal id), no (command, floor, scope) is removed by two entries,
    match_durable_capacity_total delta 0. The count of removed == 0 entries is recorded against
    core_release_confirm_stale_total (a measurement, [E, DR])."""
    entries = release_entries(w['me_journal'])
    removed = Counter((r['commandIdHigh'], r['idLowFloor'], r.get('scope')) for _, r in entries if (r.get('removed') or 0) >= 1)
    twice = [k for k, n in removed.items() if n > 1]
    total = sum(r.get('removed') or 0 for _, r in entries)
    ledger = [v for _, v in series(w['samples'], 'me', 'match_command_ledger_size')]
    if not ledger:          # The need is the ledger's peak; without a sampler row it is unjudgeable
        return _line(False, {'why': 'no sampler row answered match_command_ledger_size on the ME leader'}, inconclusive=True)
    peak = max(ledger)
    need = max(int(peak), w.get('order_terminals') or 0)
    before = max_over(w['snaps']['before'], 'me', 'match_durable_capacity_total') or 0
    after = max_over(w['snaps']['after'], 'me', 'match_durable_capacity_total')
    capacity = None if after is None else after - before
    detail = {'entries': len(entries), 'removed_total': total, 'need': need, 'ledger_peak': peak, 'removed_twice': twice[:5],
              'noop_entries': sum(1 for _, r in entries if not r.get('removed')), 'capacity_delta': capacity}
    if not entries or total < need:
        return _line(False, f'no release journaled for {need - total} of {need} ledger entries: {detail}')
    return _line(not twice and capacity == 0, detail)


def line_release_resent(w):
    """A03 (H:307 "the interrupted release is re-sent and applied once"): the RELEASE_ID dispatches the core minted while
    both forwarders held releases back (tap seq <= the dispatch head at the swap) each have exactly one record-4 entry
    with removed >= 1, journaled after the swap (ME journal seq read just before it). No swap witness or no release in
    the window: INCONCLUSIVE, never PASS."""
    hold = w.get('hold')
    if not hold or hold.get('swap_me_seq') is None or hold.get('swap_dispatch_seq') is None:
        return _line(False, 'no swap witnessed (hold window not bracketed)', inconclusive=True)
    held = {(r['id_high'], r['id_low']) for r in w['tap_dispatch']
            if r.get('kind') == RELEASE_KIND and r.get('seq') is not None and r['seq'] <= hold['swap_dispatch_seq']}
    if not held:
        return _line(False, 'no release in the window', inconclusive=True)
    by_key = {}
    for seq, r in release_entries(w['me_journal']):
        by_key.setdefault((r['commandIdHigh'], r['idLowFloor']), []).append((seq, r.get('removed') or 0))
    bad = []
    for key in sorted(held):
        applied = [seq for seq, n in by_key.get(key, []) if n >= 1]
        if len(applied) != 1 or applied[0] < hold['swap_me_seq']:       # swap_me_seq is the NEXT journal seq (me_seq)
            bad.append({'id': list(key), 'applied_at': applied})
    return _line(not bad, {'held': len(held), 'not_applied_once_after_the_swap': bad[:5], 'bad': len(bad),
                           'swap_me_seq': hold['swap_me_seq'], 'backlog_at_swap': hold.get('backlog_at_swap')})


def line_reopen_admits(w):
    a03 = w.get('a03') or {}
    hold = w.get('hold') or {}
    ok = (a03.get('reopen_acked') or 0) > 0 and a03.get('opened') is True and hold.get('kill_in_closed_window') is True \
        and hold.get('restarted') is True
    return _line(ok, {'a03': a03, 'kill_in_closed_window': hold.get('kill_in_closed_window'), 'restarted': hold.get('restarted')})


def line_halt_local(w):
    """A04 life 1: both bridges halt SOURCE_SCHEMA (stale epoch prefix, BDM:462-469) bound to g1 with /health 503; the
    core latched SOURCE_SCHEMA bound to g1; nothing refused."""
    g1 = w['g1']
    out = {}
    for b in BRIDGES:
        status, body = w['bridge_health'].get(b) or (None, {})
        reason = value(w['halt_scrape'], b, 'bridge_halt_reason')
        out[b] = {'metric': reason, 'status': status, 'haltReason': (body or {}).get('haltReason'),
                  'meEpoch': (body or {}).get('meEpoch')}
    ae = leader_of(w['halt_scrape'], 'ae')
    latch = value(w['halt_scrape'], ae, 'core_feed_latch_reason') if ae else None
    core = w['core']
    ok = all(v['metric'] == SOURCE_SCHEMA and v['status'] == 503 and v['haltReason'] == 'SOURCE_SCHEMA' and v['meEpoch'] == g1
             for v in out.values()) and core.get('feed_halted') is True and core.get('halt_reason') == 'SOURCE_SCHEMA' \
        and core.get('bound_me_epoch') == g1 and latch == SOURCE_SCHEMA and w.get('settle_rejected') == 0
    return _line(ok, {'bridges': out, 'core': core, 'latch_reason': latch, 'settle_rejected': w.get('settle_rejected')})


def line_open_refused(w):
    """The ADMIN OPEN during the halt is refused AND life 2's genesis OPEN is observed. A life-2 OPEN not yet
    observed (life 2 not run: the provisional life-1 write, a life-1-only run) is never a PASS: INCONCLUSIVE when the
    refusal held, FAIL when it did not."""
    gate = w.get('open_gate') or {}
    replies = ((gate.get('reply') or {}).get('replies') or [{}])
    refused = gate.get('meaning') == 'REFUSED' and replies[-1].get('result') == 'REJECTED'
    life2 = w.get('life2_gate_open')
    detail = {'meaning': gate.get('meaning'), 'reply': replies[-1], 'life2_gate_open': life2}
    if refused and life2 is None:
        return _line(False, dict(detail, why='life 2 genesis OPEN not observed'), inconclusive=True)
    return _line(refused and life2 is True, detail)


def line_money_while_halted(w):
    rows = w.get('halt_funding') or []
    ok_rows = [r for r in rows if r.get('outcome') == 'ACK' and r.get('gate') == 'SUSPENDED']
    deposits = sum(1 for r in ok_rows if r['kind'] == 'deposit')
    withdraws = sum(1 for r in ok_rows if r['kind'] == 'withdraw')
    reply = (w.get('halt_create') or {}).get('reply') or {}
    ok = deposits >= 4 and withdraws >= 2 and reply.get('outcome') == 'REJECT' and reply.get('reason') == 'GATE_CLOSED'
    return _line(ok, {'deposits_while_closed': deposits, 'withdraws_while_closed': withdraws, 'create': reply})


def line_fenced_forwarders(w):
    bound = SETTINGS['FENCE_BOUND_S']
    fence = w.get('fence') or {}
    ok = all((fence.get(f) or {}).get('exit_code') == 78 and (fence[f].get('after_first_me_start_s') is not None)
             and fence[f]['after_first_me_start_s'] <= bound for f in FORWARDERS)
    return _line(ok, {'fence': fence, 'bound_s': bound})


def line_second_life_exact(w):
    """``epochs`` are the ME epochs OBSERVED in life 2's journal (every record), never the harness's declaration;
    life 2 must carry records and every one must be of g2."""
    life2 = w.get('life2')
    if not life2:
        return _line(False, 'life 2 was not judged', inconclusive=True)
    if not life2.get('epochs'):
        return _line(False, {'why': 'no ME epoch observed in the life-2 journal', **{k: life2.get(k) for k in ('g2', 'epochs')}},
                     inconclusive=True)
    ok = life2['money']['status'] == 'PASS' and life2['order']['status'] == 'PASS' and life2['epochs'] == [life2['g2']] \
        and life2['bound_me_epoch'] == life2['g2'] and life2['last_applied_trade_id'] == life2['max_epoch2_trade']
    return _line(ok, {k: (v['status'] if isinstance(v, dict) and 'status' in v else v) for k, v in life2.items()})


def line_cold_restart_skips(w):
    """A04 one-bridge-halt. The claim is about bridge0's FIRST forward after the restart: it
    is the core cursor at bridge0's sync + 1, and every record it re-read at or below that cursor is skipped. The witness
    is bridge0's first /health right after its /ready (``health_first``): ``cursor`` is C of the sync's report (the next
    periodic report comes 10 s later, ct BridgeDomain.cpp:1623, BridgeSettings.h:21) and ``start_cursor`` is that value.
      (a) backlog = start_cursor - ME seq at the kill >= COLD_RESTART_LEAD: the peer had delivered the backlog before
          bridge0 synced (the control a04-earlyrestart freezes the peer, so this clause FAILs there);
      (b) bridge_skipped_total >= start_cursor: the cold re-read skipped every record at or below the cursor, so by the
          forward rule (ct BridgeDomain.cpp:482-516; last = C at the sync, :1609) its first forward was start_cursor + 1;
      (c) health_first: last >= start_cursor and expected == last + 1, STREAMING.
    A run read the cursor at STREAMING under load and compared expected with it (9871 vs 10153): a report's C is not the
    bridge's live position, so that comparison failed a GREEN run."""
    c = w.get('cold') or {}
    first = c.get('health_first') or {}
    if c.get('me_seq_at_kill') is None or first.get('cursor') is None or first.get('last') is None:
        return _line(False, {'why': 'kill or restart not bracketed (no ME seq at the kill or no first /health)', **c},
                     inconclusive=True)
    lead = SETTINGS['COLD_RESTART_LEAD']
    start = first['cursor']
    backlog = start - c['me_seq_at_kill']
    skipped = c.get('skipped_delta') or 0
    delivered = backlog >= lead
    skipped_all = skipped >= start and skipped >= backlog
    streaming = first['last'] >= start and first.get('expected') == first['last'] + 1 and first.get('state') == 'STREAMING'
    detail = dict(c, start_cursor=start, backlog=backlog, lead=lead,
                  clauses={'peer_delivered_backlog': delivered, 'skipped_to_cursor': skipped_all, 'streaming_from_cursor': streaming})
    if not delivered:
        detail['why'] = (f'the peer had not delivered the backlog when bridge0 synced: start cursor {start} is '
                         f'{backlog} past the kill seq, under the lead {lead}; bridge0 forwarded '
                         f'{first["last"] - start} records from {start + 1} itself')
    return _line(delivered and skipped_all and streaming, detail)


def line_bridge_never_halted(w):
    rows = [(s_value(r, 'bridge0', 'bridge_halted'), s_value(r, 'bridge1', 'bridge_halted')) for r in w.get('samples') or []]
    seen = [r for r in rows if r != (None, None)]
    halted = [r for r in seen if any(v not in (None, 0.0) for v in r)]
    if not seen:
        return _line(False, {'why': 'no sampler row answered bridge_halted', 'rows': 0}, inconclusive=True)
    return _line(not halted, {'rows': len(seen), 'halted_rows': len(halted)})


def _t0_s(w):
    return w['t0_s'] if 't0_s' in w else w['t0_ms'] / 1000


def line_build_witness(w):
    """Both swaps happened, each witnessed by /health.build: before the swap the slot answers what the swapped-out binary
    reports, after it what the swapped-in binary reports (core_contracts.health_build_expected: the source sha, or none for
    the pinned build A, ct 2be3a19, which has no build field), the bytes differ and the swapped-in one is the manifest's build B
    (``b_source_sha``). The reverse kind (cut -> build A) is judged by the same rule."""
    swaps = w.get('swaps') or []
    out = []
    for s in swaps:
        old, new = s['replace']['old'], s['replace']['new']
        out.append({'slot': s['slot'], 'pre_build': s.get('pre_build'), 'build': s['replace'].get('build_health'),
                    'old_sha256': old['sha256'], 'new_sha256': new['sha256'],
                    'want_pre_build': core_contracts.health_build_expected(old),
                    'want_build': core_contracts.health_build_expected(new), 'new_source_sha': new.get('source_sha')})
    ok = len(out) == 2 and all(o['pre_build'] == o['want_pre_build'] and o['build'] == o['want_build']
                               and o['pre_build'] != o['build'] and o['old_sha256'] != o['new_sha256']
                               and o['new_source_sha'] == w['b_source_sha'] for o in out)
    return _line(ok, {'swaps': out, 'b_source_sha': w.get('b_source_sha')})


def _swap_spans_ms(w):
    t0 = w['t0_ms']
    return [(t0 + s['start_s'] * 1000, t0 + s['ready_s'] * 1000) for s in w.get('swaps') or []]


def line_no_delay(w):
    """p99.9 over the union of both swap windows <= baseline [10 s, 30 s) p99.9 + A05_P999_SLACK_MS; every window's
    summary recorded. An empty window is a gap: INCONCLUSIVE."""
    t0 = w['t0_ms']
    slack = (w.get('settings') or SETTINGS)['A05_P999_SLACK_MS']
    spans = _swap_spans_ms(w)
    windows = {'baseline': [(t0 + 10_000, t0 + 30_000)], 'swap': spans, 'after': [(t0 + 60_000, t0 + 90_000)]}
    for n, span in enumerate(spans, start=1):
        windows[f'swap{n}'] = [span]
    out = window_summaries(w['latency'], windows)
    if not spans or out['baseline']['count'] == 0 or out['swap']['count'] == 0:
        return _line(False, {'why': 'a latency window has no row', 'windows': out}, inconclusive=True)
    ok = out['swap']['p99.9'] <= out['baseline']['p99.9'] + slack
    return _line(ok, {'rule': 'p99.9(swap) <= p99.9(baseline) + slack', 'slack_ms': slack, 'windows': out})


def line_survivor_delivered(w):
    """During each swap window the ME progress (journal seq on the ME leader) keeps rising with no gap above
    SURVIVOR_MAX_GAP_S; a window shorter than SWAP_WINDOW_MIN_S is vacuous: INCONCLUSIVE."""
    s = w.get('settings') or SETTINGS
    t0 = _t0_s(w)
    points = series(w['samples'], 'me', PROGRESS)
    out, vacuous = [], False
    for swap in w.get('swaps') or []:
        lo, hi = t0 + swap['start_s'], t0 + swap['ready_s']
        rises, gap, n = progress(points, lo, hi)
        if hi - lo < s['SWAP_WINDOW_MIN_S'] or n == 0:
            vacuous = True
        out.append({'slot': swap['slot'], 'window_s': round(hi - lo, 3), 'rows': n, 'rises': len(rises), 'max_gap_s': gap})
    if not out:
        return _line(False, 'no swap window', inconclusive=True)
    if vacuous:
        return _line(False, {'why': 'a swap window is shorter than SWAP_WINDOW_MIN_S or unsampled', 'windows': out},
                     inconclusive=True)
    return _line(all(o['rises'] >= 1 and o['max_gap_s'] <= s['SURVIVOR_MAX_GAP_S'] for o in out), out)


def line_dup_outcomes(w):
    """F7: outside the swap windows (baseline [10, 30) s and after [60, 90) s), the ME leader's duplicate counter delta ==
    (N - 1) x the tapped command dispatches (RELEASE_ID excluded: releases are not duplicate-suppressed, cost.log), within
    A05_DUP_EDGE_SLACK. N is the drill's design (2); the N = 1 control must FAIL it."""
    s = w.get('settings') or SETTINGS
    t0 = _t0_s(w)
    points = series(w['samples'], 'me', 'match_durable_duplicates_suppressed_total')
    out = {}
    for name, (a, b) in (('baseline', (10, 30)), ('after', (60, 90))):
        lo, hi = t0 + a, t0 + b
        first, last = at_or_before(points, lo), at_or_before(points, hi)
        dispatched = sum(1 for r in w['tap_dispatch'] if r.get('kind') != RELEASE_KIND and r.get('at_ms') is not None
                         and lo * 1000 <= r['at_ms'] < hi * 1000)
        dup = None if first is None or last is None else last - first
        out[name] = {'duplicates': dup, 'dispatches': dispatched, 'expected': (w.get('n', 2) - 1) * dispatched}
    if any(v['duplicates'] is None for v in out.values()):     # no sampler row at a window edge
        return _line(False, {'why': 'a dup window edge has no sampler row', 'windows': out}, inconclusive=True)
    ok = all(v['dispatches'] > 0 and abs(v['duplicates'] - v['expected']) <= s['A05_DUP_EDGE_SLACK'] for v in out.values())
    return _line(ok, {'windows': out, 'slack': s['A05_DUP_EDGE_SLACK']})


def line_keep_state(w):
    """A05-keep (row 47): both swaps (one forwarder, one bridge) replaced the binary with the slot's state dir in place."""
    out = [{'slot': s['slot'], 'keep_state': s['replace'].get('keep_state'), 'state_dir': s['replace'].get('state_dir')}
           for s in w.get('swaps') or []]
    ok = len(out) == 2 and {o['slot'][:3] for o in out} == {'fwd', 'bri'} and all(o['keep_state'] and o['state_dir'] for o in out)
    return _line(ok, out)


def line_ready_after_kill(w):
    bound = (w.get('settings') or SETTINGS)['READY_AFTER_KILL_S']
    out = [{'slot': s['slot'], 'kind': s['kind'], 'ready_after_kill_s': s['replace'].get('ready_after_kill_s'),
            'f7_rejected': s['replace'].get('f7_rejected')} for s in w.get('swaps') or []]
    ok = len(out) == 2 and all(o['kind'] == 'kill' and o['ready_after_kill_s'] is not None and o['ready_after_kill_s'] <= bound
                               for o in out)
    return _line(ok, {'swaps': out, 'bound_s': bound})


def line_settle_no_gap(w):
    """A05 bridges: settle lag = ME leader match_trades_total - core core_last_applied_trade_id per sample; each swap
    window's max lag <= the baseline [10, 30) max + A05_SETTLE_LAG_SLACK trades (a count: the projection has no clock)."""
    s = w.get('settings') or SETTINGS
    t0 = _t0_s(w)
    lag = []
    for row in w.get('samples') or []:
        me, ae = s_value(row, 'me', 'match_trades_total'), s_value(row, 'ae', 'core_last_applied_trade_id')
        if me is not None and ae is not None:
            lag.append(((row['t0'] + row['t1']) / 2, me - ae))

    def peak(lo, hi, closed=True):
        values = [v for t, v in lag if lo <= t and (t <= hi if closed else t < hi)]
        return max(values) if values else None
    base = peak(t0 + 10, t0 + 30, closed=False)
    out = [{'slot': sw['slot'], 'max_lag': peak(t0 + sw['start_s'], t0 + sw['ready_s'])} for sw in w.get('swaps') or []]
    if base is None or not out or any(o['max_lag'] is None for o in out):
        return _line(False, {'why': 'a lag window has no sample', 'baseline_max': base, 'swaps': out}, inconclusive=True)
    return _line(all(o['max_lag'] <= base + s['A05_SETTLE_LAG_SLACK'] for o in out),
                 {'baseline_max': base, 'swaps': out, 'slack': s['A05_SETTLE_LAG_SLACK']})


TICK_CORE = ['core_ticks_applied_total', 'core_ticks_stale_total', 'core_ticks_invalid_total',
             'core_ticks_epoch_drop_total', 'core_ticks_unbound_total']


def line_tick_conservation(w):
    """A06: the AE leader never changed; offered = fwd0 up to its pre-kill scrape + its post-restart value
    + fwd1's delta (summed over every market and edge); core = the five tick counters' deltas on the leader.
    Lower bound: core >= offered - lost, lost = fwd0's offers between its t=29 and pre-kill scrapes (the offers of its
    last second, which SIGKILL may lose). Upper bound (a06-n1: core 449 > offered 447 + 1): fwd0 keeps
    offering between its pre-kill scrape and the SIGKILL, and a dead process cannot be scraped; those offers are bounded
    by the core's own count across that gap, read on the AE leader just before the pre-kill scrape (``core_prekill``)
    and TICK_SETTLE_S after the kill (``core_postkill``): core <= offered + (postkill - prekill). The bound is a
    scrape, never a rate guess; a missing core scrape is INCONCLUSIVE. Pending age 0 and ticks ready 1 on every
    forwarder at the barrier."""
    snaps, name = w['snaps'], 'forwarder_tick_offered_total'
    leaders = w['ae_leaders']
    leader = leaders[0] if leaders and all(l == leaders[0] for l in leaders) and leaders[0] else None
    offered, lost = 0, 0
    for fwd in w['forwarders']:
        if fwd == 'fwd0':
            pre = value(snaps['prekill'], 'fwd0', name, 0)
            offered += pre + (value(snaps['after'], 'fwd0', name, 0) or 0)
            lost = max(0, pre - value(snaps['t29'], 'fwd0', name, 0))
        else:
            offered += (value(snaps['after'], fwd, name, 0) or 0) - value(snaps['before'], fwd, name, 0)

    def core_total(label):
        snap = snaps.get(label)
        if leader is None or snap is None or leader not in snap or 'unavailable' in (snap.get(leader) or {}):
            return None
        return sum(value(snap, leader, n, 0) or 0 for n in TICK_CORE)
    core = None if leader is None else sum((value(snaps['after'], leader, n, 0) or 0) - value(snaps['before'], leader, n, 0)
                                           for n in TICK_CORE)
    gap = None
    if 'fwd0' in w['forwarders']:
        a, b = core_total('core_prekill'), core_total('core_postkill')
        gap = None if a is None or b is None else max(0, b - a)
    quiet = {fwd: (value(snaps['after'], fwd, 'forwarder_tick_pending_age_ms'), value(snaps['after'], fwd, 'forwarder_ticks_ready'))
             for fwd in w['forwarders']}
    detail = {'ae_leaders': leaders, 'offered': offered, 'core': core, 'lost_slack': lost, 'kill_gap_core_count': gap,
              'quiet': quiet}
    if leader is not None and 'fwd0' in w['forwarders'] and gap is None:
        return _line(False, dict(detail, why='no AE leader scrape around the kill: the upper bound is unjudgeable'),
                     inconclusive=True)
    ok = leader is not None and offered - lost <= core <= offered + (gap or 0) and all(q == (0.0, 1.0) for q in quiet.values())
    return _line(ok, detail)


def _tick_delta(w, n):
    leader = (w.get('ae_leaders') or [None])[-1]
    return None if leader is None else (value(w['snaps']['after'], leader, n, 0) or 0) - value(w['snaps']['before'], leader, n, 0)


def line_tick_stale_positive(w):
    d = _tick_delta(w, 'core_ticks_stale_total')
    return _line(d is not None and d > 0, f'core_ticks_stale_total delta {d}')


def line_tick_invalid_zero(w):
    d = {n: _tick_delta(w, n) for n in ('core_ticks_invalid_total', 'core_ticks_epoch_drop_total')}
    leader = (w.get('ae_leaders') or [None])[-1]
    unbound = None if leader is None else (value(w['snaps']['after'], leader, 'core_ticks_unbound_total', 0) or 0) \
        - value(w['snaps']['t29'], leader, 'core_ticks_unbound_total', 0)
    applied29 = value(w['snaps']['t29'], leader, 'core_ticks_applied_total', 0) if leader else 0
    return _line(all(v == 0 for v in d.values()) and unbound == 0 and applied29 > 0,
                 dict(d, unbound_after_first_applied=unbound, applied_at_t29=applied29))


def line_tick_end_state(w):
    """After the quiet: the core's market-1 best bid/ask equal T1MeDriver book; its book version <= the ME's and == the
    forwarders' max last offered version; markets 2..5 empty at both or equal."""
    leader = (w.get('ae_leaders') or [None])[-1]
    after, book = w['snaps']['after'], w.get('book') or {}

    def core(name, m):
        v = value(after, leader, f'{name}{{market="{m}"}}') if leader else None
        return None if v is None else int(v)
    out, ok = {}, bool(book.get(1)) and leader is not None
    for m in range(1, 6):
        me = book.get(m)
        c = {'bid': core('core_market_best_bid', m), 'ask': core('core_market_best_ask', m),
             'version': core('core_market_book_version', m)}
        if me is None:
            ok = ok and c['version'] in (None, 0)
        else:
            ok = ok and c['bid'] == me['bid'] and c['ask'] == me['ask'] and c['version'] is not None and c['version'] <= me['version']
        out[m] = {'core': c, 'me': me}
    offered = [value(after, f, 'forwarder_tick_last_offered_version{market="1"}') for f in w['forwarders']]
    offered = [int(v) for v in offered if v is not None]
    ok = ok and bool(offered) and out[1]['core']['version'] == max(offered)
    return _line(ok, {'markets': out, 'forwarders_last_offered_1': offered})


def line_tick_survivor(w):
    """fwd0 dead from its kill to its restart: core_ticks_applied_total rose with fwd1 alone. Measured (a06-n1: 2
    "rises" with no survivor): a rise counts only between two sampler rows both inside [kill + TICK_SETTLE_S, restart
    issued] (``restart_begin_s``, read before docker start: the restarted fwd0 offered before its /ready returned, and
    fwd0's pre-kill ticks commit just after the kill, which the row before the window used to count). Fewer than two
    rows in the window: INCONCLUSIVE."""
    s = dict(SETTINGS, **(w.get('settings') or {}))
    t0, win = w['t0_s'], w.get('kill_window') or {}
    if win.get('kill_s') is None or win.get('restart_begin_s') is None:
        return _line(False, {'why': 'kill window not bracketed', 'kill_window': win}, inconclusive=True)
    lo, hi = t0 + win['kill_s'] + s['TICK_SETTLE_S'], t0 + win['restart_begin_s']
    rises, _, n = progress(series(w['samples'], 'ae', 'core_ticks_applied_total'), lo, hi, inside=True)
    after = value(w['snaps']['after'], 'fwd0', 'forwarder_tick_offered_total')
    detail = {'applied_rises_while_fwd0_down': len(rises), 'rows': n, 'window_s': [round(lo - t0, 3), round(hi - t0, 3)],
              'fwd0_offered_after_restart': after}
    if n < 2:
        return _line(False, dict(detail, why='fewer than two sampler rows while fwd0 was down'), inconclusive=True)
    return _line(bool(rises) and (after or 0) > 0, detail)


def line_ring_outlived_thaw(w):
    """fwdring, both pauses: the paused fwd0 never exited and reconnected nothing (branch 'none' with the reconnect
    counters 0 on both clusters by thaw + NO_LOSS_AFTER_S), and its last_sent moved past every dispatch tapped up to the
    thaw. A bracketed row without a pause (the nopause control) has no heal: FAIL."""
    rows = [r for r in w['ledger'] if r.get('kind') == 'pause' and r.get('target') == 'fwd0']
    out = []
    for r in rows:
        heal = r.get('heal') or {}
        hw = heal.get('witness') or {}
        thaw = (r.get('witness') or {}).get('thaw_ms')
        tapped = [d['seq'] for d in w['tap_dispatch'] if d.get('seq') is not None and d.get('at_ms') is not None
                  and thaw is not None and d['at_ms'] <= thaw]
        reconnect = hw.get('reconnect_delta_by_cluster') or {}
        after, before = hw.get('last_sent_after'), (r.get('witness') or {}).get('last_sent_before')
        ok = heal.get('branch') == 'none' and all(reconnect.get(c) == 0 for c in ('core', 'me')) and after is not None \
            and before is not None and after > before and after >= max(tapped or [0])
        out.append({'row': r['row'], 'branch': heal.get('branch'), 'reconnect': reconnect, 'last_sent_before': before,
                    'last_sent_after': after, 'max_tapped_seq_by_thaw': max(tapped or [0]), 'ok': ok})
    return _line(len(out) == 2 and all(o['ok'] for o in out), out)


def line_released_after_thaw(w):
    counts = w.get('released_after_thaw')
    if counts is None:
        return _line(False, 'no bracketed pause row: the RELEASED attribution is unjudgeable', inconclusive=True)
    return _line(len(counts) == 2 and all(c > 0 for c in counts), {'per_pause': counts})


def line_driver_death_loud(w):
    """C13 engines (judged on a build with the polite-stop fix): three kills (AE follower twice, ME leader once); each exit
    NON-ZERO within DRIVER_DEATH_BOUND_S, the value recorded; exit 0 is a FAIL and a finding; each restart
    on a new driver identity; the second kill hit the driver the first restart created."""
    bound = SETTINGS['DRIVER_DEATH_BOUND_S']
    kills = w.get('kills') or []
    out, ok = [], len(kills) == 3
    for n, k in enumerate(kills):
        drv = (k.get('restart') or {}).get('driver') or {}
        new_driver = drv.get('new') is not None and drv.get('new') != drv.get('old')
        loud = k.get('exit_code') not in (None, 0) and k.get('exit_after_s') is not None and k['exit_after_s'] <= bound
        hit_new = n != 1 or k.get('identity_before') == ((kills[0].get('restart') or {}).get('driver') or {}).get('new')
        row = {'target': k['target'], 'exit_code': k.get('exit_code'), 'exit_after_s': k.get('exit_after_s'),
               'new_driver': new_driver, 'hit_new_driver': hit_new, 'ready_during_grace': k.get('ready_during_grace')}
        if k.get('exit_code') == 0:
            row['finding'] = 'exit 0 on driver death: a finding (only a non-zero exit is accepted)'
        out.append(row)
        ok = ok and loud and new_driver and hit_new
    return _line(ok, {'kills': out, 'bound_s': bound})


def line_cluster_served(w):
    """During each AE follower driver kill (kill to restart /ready) the ME keeps progressing with no gap above
    SERVED_MAX_GAP_S (no election); the ME leader kill elects a new leader and the story resolves every UNKNOWN."""
    t0 = _t0_s(w)
    gap_max = SETTINGS['SERVED_MAX_GAP_S']
    points = series(w.get('samples'), 'me', PROGRESS)
    kills = w.get('kills') or []
    out, ok, unsampled = [], len(kills) == 3, False
    for k in kills:
        if k['role'] == 'ae_follower':
            hi = k.get('ready_s')
            if hi is None:
                out.append({'target': k['target'], 'why': 'restart not observed'}); ok = False; continue
            rises, gap, n = progress(points, t0 + k['kill_s'], t0 + hi)
            out.append({'target': k['target'], 'rises': len(rises), 'max_gap_s': gap, 'rows': n})
            if n == 0:      # An unsampled window is a missing witness, never a FAIL
                unsampled = True
            ok = ok and bool(rises) and n > 0 and gap <= gap_max
        else:
            e = w.get('election') or {}
            elected = e.get('new_leader') not in (None, e.get('killed'))
            out.append({'target': k['target'], 'election': e, 'story_unresolved': w.get('story_unresolved')})
            ok = ok and elected and w.get('story_unresolved') == 0
    if unsampled and len(kills) == 3:
        return _line(False, {'why': 'an AE follower kill window has no sampler row', 'kills': out}, inconclusive=True)
    return _line(ok, out)


def line_cnc_timeout_loud(w):
    """``exit_after_s`` is FinishedAt minus the engine's own driver-wait start (its log line, docker timestamps on
    one clock), so the container create, the JVM start and the harness's polling are outside the bound; a member whose
    origin is the process start (``measured_from`` 'process_start': the line was not found) is judged on the same bound
    and says so. No origin at all is INCONCLUSIVE."""
    bound = SETTINGS['CNC_TIMEOUT_BOUND_S']
    cnc = w.get('cnc') or {}
    if cnc and any(v.get('exit_code') not in (None, 0) and v.get('exit_after_s') is None for v in cnc.values()):
        return _line(False, {'why': 'an exit was seen but its time origin is missing', 'members': cnc, 'bound_s': bound},
                     inconclusive=True)
    ok = bool(cnc) and all(v.get('exit_code') not in (None, 0) and (v.get('exit_after_s') or 1e9) <= bound
                           and not v.get('ready_200_seen') for v in cnc.values())
    return _line(ok, {'members': cnc, 'bound_s': bound})


def line_engine_polite_stop(w):
    """With the polite-stop fix: every engine the drill stopped politely (``stop``: SIGTERM, then
    docker stop at the 15 s escalation bound) exited ENGINE_STOP_EXIT (143) within ENGINE_SHUTDOWN_TIMEOUT_S +
    ENGINE_STOP_SLACK_S. An escalation to 137 is a FAIL. No engine stop in the run: INCONCLUSIVE (nothing to judge)."""
    s = dict(SETTINGS, **(w.get('settings') or {}))
    bound = s['ENGINE_SHUTDOWN_TIMEOUT_S'] + s['ENGINE_STOP_SLACK_S']
    stops = [x for x in (w.get('engine_stops') or [])]
    if not stops:
        return _line(False, {'why': 'no engine was stopped politely in this life', 'bound_s': bound}, inconclusive=True)
    out = [{'target': x.get('target'), 'exit_code': x.get('exit_code'), 'elapsed_s': x.get('elapsed_s'),
            'ok': x.get('exit_code') == s['ENGINE_STOP_EXIT'] and x.get('elapsed_s') is not None and x['elapsed_s'] <= bound}
           for x in stops]
    return _line(all(o['ok'] for o in out), {'stops': out, 'expected_exit': s['ENGINE_STOP_EXIT'], 'bound_s': bound})


LINES = {name[5:]: fn for name, fn in globals().items() if name.startswith('line_')}


# ------------------------------------------------------------------ the sampler

SAMPLE_NAMES = {
    'ae': ('core_cluster_role', 'core_me_capacity_estimate', 'core_release_backlog', 'core_order_entry_gate_reasons',
           'core_pending_commands', 'core_last_applied_trade_id', 'core_ticks_applied_total',
           'core_release_minted_order_total', 'core_release_minted_up_to_total'),
    'me': ('match_cluster_role', 'match_command_ledger_size', PROGRESS, 'match_durable_duplicates_suppressed_total',
           'match_trades_total', 'match_orders_submitted_total', 'match_release_applied_total', 'match_durable_capacity_total'),
    'bridge': ('bridge_halted', 'bridge_halt_reason'),
}
SAMPLER_CODE = '''import json,sys,urllib.request,urllib.error
out={}
for role,url in json.loads(sys.stdin.read()).items():
    try:
        r=urllib.request.urlopen(url,timeout=1);out[role]={"status":r.status,"body":r.read().decode()}
    except urllib.error.HTTPError as e:out[role]={"status":e.code,"body":e.read().decode()}
    except Exception as e:out[role]={"status":0,"error":str(e)}
print(json.dumps(out))
'''


class Sampler:
    """One probe exec per tick reads /metrics of every engine member (and the bridges when asked), keeps the named
    series, and calls ``on_tick(row)`` (A03's gate watcher). It runs on its own thread and talks to Docker directly, never
    through the fixture's registry (the drill thread owns that); the probe container's ownership is checked once."""

    def __init__(self, fixture, period_s=None, bridges=False, on_tick=None):
        self.f, self.period = fixture, period_s or SETTINGS['SAMPLER_PERIOD_S']
        self.on_tick, self.rows, self.errors, self.watcher_errors = on_tick, [], [], []
        ports, nodes = fixture.m['ports'], fixture.m['nodes']
        self.urls, self.wanted = {}, {}
        for engine in ('ae', 'me'):
            for i in range(3):
                role = f'{engine}{i}'
                self.urls[role] = f'http://{nodes[role]}:{ports[engine + "_metrics"]}/metrics'
                self.wanted[role] = SAMPLE_NAMES[engine]
        if bridges:
            for b in BRIDGES:
                self.urls[b] = f'http://{nodes[b]}:{ports["bridge_http"]}/metrics'
                self.wanted[b] = SAMPLE_NAMES['bridge']
        self.stopped, self.thread = False, None

    @staticmethod
    def parse(stdout, wanted, t0, t1):
        try:
            answers = json.loads(stdout or '{}')
        except ValueError:
            answers = {}
        roles = {}
        for role, names in wanted.items():
            answer = answers.get(role) or {}
            if answer.get('status') != 200:
                roles[role] = {'unavailable': answer.get('error') or answer.get('status')}
                continue
            values = {}
            for line in answer['body'].splitlines():
                if not line or line.startswith('#'):
                    continue
                key, _, rest = line.rpartition(' ')
                base = key.split('{', 1)[0]
                if base in names:
                    try:
                        values[key] = float(rest)
                    except ValueError:
                        continue
            roles[role] = values
        return {'t0': round(t0, 3), 't1': round(t1, 3), 'roles': roles}

    def tick(self, cid):
        import subprocess
        t0 = time.time()
        try:
            r = subprocess.run(['docker', 'exec', '-i', cid, 'python3', '-c', SAMPLER_CODE], input=json.dumps(self.urls),
                               text=True, capture_output=True, timeout=10)
            out = r.stdout
        except subprocess.TimeoutExpired:
            out = ''
        row = self.parse(out, self.wanted, t0, time.time())
        self.rows.append(row)
        if self.on_tick:
            try:
                self.on_tick(row)
            except Exception as error:     # The watcher's failure is the run's (INCONCLUSIVE), never a silent gap
                self.watcher_errors.append(repr(error))
        return row

    def start(self):
        import threading
        cid = self.f.registry['containers']['probe']
        self.f.inspect('container', cid)       # ownership (label + token), once, on the drill thread

        def loop():
            while not self.stopped:
                started = time.monotonic()
                try:
                    self.tick(cid)
                except Exception as error:     # recorded; a sampler error leaves a gap the lines see as missing rows
                    self.errors.append(repr(error))
                time.sleep(max(0.0, self.period - (time.monotonic() - started)))
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stopped = True
        if self.thread:
            self.thread.join(timeout=15)
        return self.rows

    def latest(self):
        return self.rows[-1] if self.rows else None


class GateWatcher:
    """A03: reads the tap incrementally and writes ``capacity_closed`` when the GLOBAL gate shows
    [SUSPENDED, ME_CAPACITY], then ``capacity_open`` on the next [OPEN, ADMIN]; the story moves its phases on these files."""

    def __init__(self, tap_path, signal_dir):
        self.tap, self.dir, self.offset = Path(tap_path), Path(signal_dir), 0
        self.closed_ns = self.opened_ns = None

    def __call__(self, _row=None):
        if not self.tap.exists():
            return
        with self.tap.open() as stream:
            stream.seek(self.offset)
            while True:
                line = stream.readline()
                if not line.endswith('\n'):
                    break
                self.offset = stream.tell()
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                row = entry.get('row') or {}
                if entry.get('tap') != 'admission' or row.get('market') != 0:
                    continue
                if self.closed_ns is None and (row['state'], row['reason']) == ('SUSPENDED', 'ME_CAPACITY'):
                    self.closed_ns = time.time_ns()
                    (self.dir / 'capacity_closed').write_text('closed\n')
                elif self.closed_ns is not None and self.opened_ns is None and (row['state'], row['reason']) == ('OPEN', 'ADMIN'):
                    self.opened_ns = time.time_ns()
                    (self.dir / 'capacity_open').write_text('open\n')


def _iso_ns(text):
    """Docker's StartedAt / FinishedAt (RFC 3339 with ns) -> epoch ns."""
    from datetime import datetime, timezone
    head, _, frac = text.rstrip('Z').partition('.')
    base = datetime.strptime(head, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    return int(base.timestamp()) * 10**9 + int((frac + '000000000')[:9])


class ScheduleDrills:
    """The fault schedules on the DrillRun machinery."""

    # ---------------------------------------------------------------- helpers

    def active_forwarders(self):
        return [s for s in FORWARDERS if (self.f.slots.get(s) or {}).get('state') == 'STARTED' and s not in self.removed]

    def life_genesis_id(self):
        return int(self.f.genesis_id(self.f.life('core')), 16)

    def health_of(self, role):
        port, _ = self.f.ready_target(role)
        response = self.f.http(role, port, '/health')
        try:
            body = json.loads(response.get('body') or '{}')
        except ValueError:
            body = {'unparsed': (response.get('body') or '')[:300]}
        return response.get('status'), body

    def slot_metrics(self, role):
        port = self.f.m['ports']['forwarder_http' if role.startswith('fwd') else 'bridge_http']
        try:
            return {role: self.f.metrics(role, port)}
        except Inconclusive as error:
            return {role: {'unavailable': str(error)}}

    def engine_metrics(self, role):
        """One engine member's /metrics as a scrape row ({role: values}); None role or no answer: 'unavailable'."""
        if role is None:
            return {}
        try:
            return {role: self.f.metrics(role, self.f.m['ports'][role[:2] + '_metrics'])}
        except Inconclusive as error:
            return {role: {'unavailable': str(error)}}

    # ---------------------------------------------------------------- A03 lifetime

    def faults_a03(self):
        """Phase 1 on the no-release build (the ME ledger fills, the gate closes at 0.8 c); at the story's fill_ended:
        pause fwd1 2.5 s, kill fwd0 inside the pause, replace fwd0 with build A (after_kill), thaw fwd1, stop fwd1 and
        replace it with build A: the drain and the reopen run on real code. RED-A03 keeps the no-release build (the kill
        is healed by a restart of the same container). Control a03-nokill (hold false): both slots are swapped to build A
        before the fill, so releases relay live; the same swap point is recorded and nothing is killed or paused."""
        f, red = self.f, self.red == 'red-a03'
        hold = self.variant.get('hold', True)
        self.a03_hold = None
        if not hold:
            for fwd in FORWARDERS:
                self.swap(fwd, 'forwarder', how='stop')
        self.wait_marker('fill_ended', story_seconds(self.spec['story']) + 60)
        latest = self.sampler.latest()
        me = f.leader('me')
        hold_w = {'backlog_at_swap': s_value(latest, 'ae', 'core_release_backlog'),
                  'swap_dispatch_seq': max([r['seq'] for r in self.tap_rows()['dispatch'] if r.get('seq') is not None] or [0]),
                  'swap_me_seq': self.me_seq(me), 'closed_seen': self.gate.closed_ns is not None}
        if not hold:
            for kind, target in (('pause', 'fwd1'), ('kill', 'fwd0'), ('stop', 'fwd1')):
                self.ledger.skip(kind, target, 'control a03-nokill: releases relayed live')
            self.a03_hold = dict(hold_w, kill_in_closed_window=False, restarted=False)
            return
        thaw_at = time.monotonic() + A03_PAUSE_S
        before = core_scenarios.barrier_scrape(f)
        pause = self.pause('fwd1', A03_PAUSE_S)
        kill = self.kill('fwd0')
        in_window = self.gate.closed_ns is not None and self.gate.opened_ns is None
        if red:
            restart = f.restart('fwd0', readiness='/health')
            self.ledger.heal(kill, 'restart', dict(restart, ready=True))
        else:
            f.readiness_override.pop('fwd0', None)
            rep = f.replace_slot('fwd0', 'forwarder', after_kill=True)
            self.ledger.heal(kill, 'replace', rep)
        self.sleep(max(0.0, thaw_at - time.monotonic()))
        thawed = time.time_ns()
        f.unpause('fwd1')
        self.await_branches({'fwd1': pause}, before, thawed)
        if not red:
            self.swap('fwd1', 'forwarder', how='stop')
        self.a03_hold = dict(hold_w, kill_in_closed_window=in_window, restarted=True,
                             pause_s=round((thawed - pause['opened_ns']) / 1e9, 3))

    def swap(self, slot, artifact, how='stop', record=None, hold_s=0.0, keep_state=False):
        """stop (polite, exit 0) or kill, then replace_slot; one ledger row healed by the replacement's /ready.
        ``hold_s``: the slot stays down that long before the replacement (the N = 1 controls, A05_N1_HOLD_S)."""
        f = self.f
        start = time.time()
        if how == 'kill':
            row = self.kill(slot)
        else:
            stop = f.stop(slot)
            row = self.ledger.open('stop', slot, stop)
        if hold_s:
            self.sleep(hold_s)
            row['witness']['held_s'] = hold_s
        f.readiness_override.pop(slot, None)
        rep = (f.replace_slot(slot, artifact, after_kill=how == 'kill', keep_state=True) if keep_state
               else f.replace_slot(slot, artifact, after_kill=how == 'kill'))
        ready = time.time()
        self.ledger.heal(row, 'replace', rep)
        if record is not None:
            record.append({'slot': slot, 'kind': how, 'start_s': round(start - self.t0 / 1e9, 3),
                           'ready_s': round(ready - self.t0 / 1e9, 3), 'replace': rep})
        return rep

    def faults_a04(self):
        raise Violation('A04 regenesis runs two lives through run_a04, not a single fault schedule')

    # ---------------------------------------------------------------- A04 one bridge halt

    def faults_one_bridge_halt(self):
        """t=20 kill(bridge0); restart it once bridge1's /health.cursor passed the ME seq at the kill + COLD_RESTART_LEAD
        (bound COLD_RESTART_BOUND_S); bridge0's first /health right after its /ready is the sync witness (cold_restart_skips).
        Control a04-earlyrestart: an early restart alone cannot keep the backlog undelivered (measured: bridge1
        streams live, so the core cursor at bridge0's sync was already 1938 past the kill seq after 1.08 s); the control
        freezes bridge1 (docker pause) just before the kill, restarts bridge0 EARLY_RESTART_AFTER_S after it, reads the same
        first /health, then thaws bridge1 (within EARLY_PEER_PAUSE_BUDGET_S, sessions stay open) and observes its branch.
        bridge0 then syncs at about the kill seq and forwards the backlog itself: clause (a) FAILs, M8 still holds."""
        f, early = self.f, self.variant.get('early', False)
        before = core_scenarios.barrier_scrape(f) if early else None
        self.at(20)
        me = f.leader('me')
        seq_kill = self.me_seq(me)
        peer = self.pause('bridge1', SETTINGS['EARLY_PEER_PAUSE_BUDGET_S']) if early else None
        paused_ns = time.time_ns()
        row = self.kill('bridge0')
        killed = time.monotonic()
        cursor = None
        while time.monotonic() - killed < SETTINGS['COLD_RESTART_BOUND_S']:
            if early:
                if time.monotonic() - killed >= SETTINGS['EARLY_RESTART_AFTER_S']:
                    break
            else:
                cursor = self.health_of('bridge1')[1].get('cursor')
                if seq_kill is not None and cursor is not None and cursor >= seq_kill + SETTINGS['COLD_RESTART_LEAD']:
                    break
            self.sleep(0.2)
        after_s = round(time.monotonic() - killed, 3)
        self.restart(row)
        first = self.health_of('bridge0')[1]          # the sync witness: read at once after /ready
        skipped = value(self.slot_metrics('bridge0'), 'bridge0', 'bridge_skipped_total')
        peer_pause_s = None
        if early:
            thawed = time.time_ns()
            peer_pause_s = round((thawed - paused_ns) / 1e9, 3)
            f.unpause('bridge1')
        me_seq_restart = self.me_seq(me)                  # evidence only, read after the thaw (the pause stays short)
        if early:
            self.await_branches({'bridge1': peer}, before, thawed)
        deadline = time.monotonic() + SETTINGS['COLD_RESTART_BOUND_S']
        health = self.health_of('bridge0')[1]
        while time.monotonic() < deadline and health.get('state') != 'STREAMING':
            self.sleep(0.5)
            health = self.health_of('bridge0')[1]
        self.cold = {'me_seq_at_kill': seq_kill, 'peer_cursor_at_restart': cursor, 'restart_after_kill_s': after_s,
                     'skipped_delta': skipped, 'me_seq_at_restart': me_seq_restart,
                     'health_first': {k: first.get(k) for k in ('cursor', 'expected', 'last', 'state')},
                     'health_after': {k: health.get(k) for k in ('cursor', 'expected', 'last', 'state')},
                     'early': early, 'peer_paused_s': peer_pause_s}

    # ---------------------------------------------------------------- A05 (9)

    def faults_a05(self):
        """t=30 slot 0, t=50 slot 1: stop (exit 0) or kill, replace_slot with build B, /ready. Control *-n1: slot 1 is
        stopped at t=25 and never replaced (the ledger records it as the control's switch, not a fault)."""
        f = self.f
        kind, how = self.spec['swap'], self.spec['how']
        if kind == 'both':           # A05-keep: t=30 fwd0, t=50 bridge0, each on build B with its state kept
            self.swaps = []
            for slot, artifact, t in (('fwd0', 'forwarder_b', 30), ('bridge0', 'bridge_b', 50)):
                self.at(t)
                pre = self.health_of(slot)[1].get('build')
                record = []
                self.swap(slot, artifact, how=how, record=record, keep_state=True)
                record[0]['pre_build'] = pre
                self.swaps += record
            return
        slots, artifact = (FORWARDERS, 'forwarder_b') if kind == 'fwd' else (BRIDGES, 'bridge_b')
        self.swaps = []
        if self.variant.get('n1'):
            self.at(25)
            witness = f.stop(slots[1])
            self.ledger.skip('stop', slots[1], f'control {self.variant.get("control")}: the survivor is removed',
                             witness=witness)
            self.removed.add(slots[1])
        # a05-fwd-upgrade-n1: with no survivor the single slot is held down A05_N1_HOLD_S, so the gap the
        # control must show (settle lag, ME progress) is well beyond the lines' slack (measured: 1.1 s windows, lag 51 vs 45,
        # progress gap 0.76 s < 1.0 s)
        hold = SETTINGS['A05_N1_HOLD_S'] if self.variant.get('n1') else 0.0
        for slot, t in zip(slots, (30, 50)):
            if slot in self.removed:
                continue
            self.at(t)
            pre = self.health_of(slot)[1].get('build')
            record = []
            self.swap(slot, artifact, how=how, record=record, hold_s=hold)
            record[0]['pre_build'] = pre
            self.swaps += record

    # ---------------------------------------------------------------- A06 two forwarders ticks

    def faults_a06(self):
        f = self.f
        self.ae_leaders = [leader_of(self.snaps['before'], 'ae')]
        self.at(29)
        self.snap('t29')
        self.ae_leaders.append(leader_of(self.snaps['t29'], 'ae'))
        self.at(30)
        leader = self.ae_leaders[-1]
        # The core's count around the kill bounds fwd0's offers between its last scrape and the SIGKILL
        self.snaps['core_prekill'] = self.engine_metrics(leader)
        self.snaps['prekill'] = self.slot_metrics('fwd0')
        row = self.kill('fwd0')
        self.kill_window = {'kill_s': round((time.time_ns() - self.t0) / 1e9, 3)}
        self.sleep(SETTINGS['TICK_SETTLE_S'])
        self.snaps['core_postkill'] = self.engine_metrics(leader)
        self.at(45)
        self.kill_window['restart_begin_s'] = round((time.time_ns() - self.t0) / 1e9, 3)
        self.restart(row)
        self.kill_window['restart_s'] = round((time.time_ns() - self.t0) / 1e9, 3)

    def a06_barrier_extra(self):
        """At the barrier: every forwarder's pending tick age 0 (bounded), a 1 s quiet, then T1MeDriver book."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            scrape = core_scenarios.barrier_scrape(self.f)
            if all(value(scrape, fwd, 'forwarder_tick_pending_age_ms') == 0 for fwd in self.active_forwarders()):
                break
            self.sleep(0.5)
        self.sleep(1)
        out = self.f._driver('t1_me_driver', 'T1MeDriver', 'book', PROBE_AERON_DIR, self.f._ingress('me'), timeout=60)
        self.book_text = out.stdout
        self.book = parse_book(out.stdout)

    # ---------------------------------------------------------------- A01 fwdring

    def faults_fwdring(self):
        """t=15 and t=45: start an IOC burst (the story crosses every create for 2 s), pause fwd0 2.5 s inside it, read
        the ME seq before the pause and before the thaw (the bracket), thaw, observe the branch. Controls: pause15 (15 s:
        branch A expected), nopause (the same bracketed reads 2.5 s apart, no pause: skipped rows with their witness)."""
        f = self.f
        pause_s = self.variant.get('pause_s', FWDRING_PAUSE_S)
        burst = f.root / 'state' / 'probe' / IOC_BURST_FILE
        for n, t in enumerate((15, 45), start=1):
            self.at(t)
            if burst.exists():
                burst.unlink()        # re-arms the story's burst (a deleted file re-arms)
            # every read that costs a docker exec happens BEFORE the burst: the burst lasts 2 s and the pause must sit in it
            before = core_scenarios.barrier_scrape(f)
            me = f.leader('me')
            witness = {'me_seq_pause': self.me_seq(me), 'burst': n,
                       'last_sent_before': value(before, 'fwd0', 'forwarder_dispatch_seq{point="last_sent"}')}
            burst.write_text(f'burst {n}\n')
            self.wait_marker('ioc_burst_started', 5, where=lambda m, n=n: m.get('n', 1) == n)
            if self.variant.get('pause', True) is False:
                self.sleep(pause_s)
                witness.update(me_seq_thaw=self.me_seq(me), thaw_ms=time.time_ns() // 10**6)
                self.ledger.skip('pause', 'fwd0', 'control fwdring-nopause', witness=witness)
                continue
            row = self.pause('fwd0', pause_s)
            row['witness'].update(witness)
            self.sleep(pause_s)
            row['witness']['me_seq_thaw'] = self.me_seq(me)       # read before the unpause
            row['witness']['thaw_ms'] = time.time_ns() // 10**6
            thawed = time.time_ns()
            f.unpause('fwd0')
            self.await_branches({'fwd0': row}, before, thawed)
            if row['heal'] is not None:
                after = core_scenarios.barrier_scrape(f)
                row['heal']['witness']['last_sent_after'] = value(after, 'fwd0', 'forwarder_dispatch_seq{point="last_sent"}')

    # ---------------------------------------------------------------- C13 enginedriverkill

    def faults_edk(self):
        f = self.f
        if f.engine_driver() != 'external':
            raise Inconclusive('enginedriverkill needs engine_driver external (s16-ext.json)')
        self.kills, self.election = [], None
        self.at(15)
        leader = f.leader('ae')
        follower = next((f'ae{i}' for i in range(3) if f'ae{i}' != leader), None) if leader else None
        if follower is None:
            raise Inconclusive('no single AE leader at t=15 s')
        if self.variant.get('kill', True) is False:
            for target in (follower, follower, 'me-leader'):
                self.ledger.skip('exec_kill', target, 'control edk-nokill')
            return
        first = self.driver_kill(follower, 'ae_follower')
        self.sleep(5)                                    # triggered by the restart's witnesses (identity + /ready)
        if first.get('restart'):
            self.driver_kill(follower, 'ae_follower')
            self.sleep(5)
        me = f.leader('me')
        if me is None:
            raise Inconclusive('no single ME leader for the third driver kill')
        self.driver_kill(me, 'me_leader', restart=False)
        new, election = self.wait_leader('me', me)
        self.election = {'killed': me, 'new_leader': new, 'election_s': election}

    def driver_kill(self, role, kind, restart=True):
        """exec_kill the staged aeronmd, watch the engine's exit (recording /ready answers during the grace), record its
        code through wait_exit (last_kill: the 12.5 s AE rule), restart on a new driver. A member that does not exit within
        the bound is killed by the harness so the run heals (the line then FAILs on the missing exit)."""
        f = self.f
        bound = SETTINGS['DRIVER_DEATH_BOUND_S']
        identity = (f.registry.get('driver_identity') or {}).get(role)
        witness = f.exec_kill(role, f.engine_driver_pidfile(role), 'KILL', heal_bound_s=story_seconds(self.spec['story']) + 300)
        row = self.ledger.open('exec_kill', role, dict(witness, identity_before=identity))
        killed = time.time()
        entry = {'target': role, 'role': kind, 'kill_s': round(killed - self.t0 / 1e9, 3), 'identity_before': identity,
                 'ready_during_grace': [], 'row': row['row']}
        self.kills.append(entry)
        code = None
        while time.time() - killed < bound + 10:
            state = self.state(role)
            if not state['Running']:
                code = state['ExitCode']
                break
            entry['ready_during_grace'].append(f.ready_body(role)[0])
            self.sleep(0.5)
        entry['exit_after_s'] = round(time.time() - killed, 3) if code is not None else None
        if code is None:
            f.command(['docker', 'kill', '--signal=KILL', self.cid(role)])
            entry['forced_kill'] = True
            code_seen = self.state(role)['ExitCode']
            f.wait_exit(role, code_seen, 5)
        else:
            f.wait_exit(role, code, 5)
        entry['exit_code'] = code
        if restart:
            self.restart_driver_row(row, entry)
        return entry

    def restart_driver_row(self, row, entry):
        restart = self.f.restart(row['target'])
        self.restarted.add(row['target'])
        entry['restart'] = restart
        entry['ready_s'] = round(time.time() - self.t0 / 1e9, 3)
        self.ledger.heal(row, 'restart', dict(restart, ready=True))

    # ---------------------------------------------------------------- the generic scheduled run

    def run_schedule(self):
        f, spec = self.f, self.spec
        if spec['faults'] == 'a04':
            return self.run_a04()
        if spec['faults'] == 'a03':
            # Phase 1 runs the no-release build, which may answer /ready 503 STALLED; liveness is /health
            self.extra['readiness'] = {fwd: '/health' for fwd in FORWARDERS}
            f.readiness_override = dict(self.extra['readiness'])
        f.start(plan_for(spec, self.seed, story_extra_s(self.red), variant=self.variant))
        self.snap('before')
        self.start_sampler()
        self.story_paths = f.start_story(self.story_args(), name=self.story_name)
        self.t0 = self.wait_marker('load_started', 60)['at_ns']
        getattr(self, 'faults_' + spec['faults'])()
        self.post_load()
        story = self.wait_story()
        pre = self.pre_barrier()
        self.stop_sampler()
        if spec['faults'] == 'a06':
            self.a06_barrier_extra()
        tap_summary = self.wait_tap_end()
        tap = self.tap_rows()
        first, second = self.barrier(story, tap, tap_summary)
        after = self.snap('after')
        sample = self.seal(self.build_sample(story, tap, tap_summary, second, pre), first, second)
        money, order = core_oracle.judge(sample), order_oracle.judge(sample)
        w = self.witness(sample, after)
        w.update(self.schedule_witness(sample, story))
        lines = {name: LINES[name](w) for name in spec['lines'] + ['fault_cycles']}
        rows = of_rows(after, sample)
        result = self.decide(money, order, lines, rows, sample, after)
        self.write_evidence(sample, money, order, lines, rows, w, story, tap_summary, result)
        self.write_schedule_evidence(self.out, w)
        return result

    def start_sampler(self, bridges=None):
        period = SETTINGS['A05_SAMPLER_PERIOD_S'] if self.spec['faults'] == 'a05' else SETTINGS['SAMPLER_PERIOD_S']
        bridges = self.spec['faults'] in ('a05', 'one_bridge_halt', 'a04') if bridges is None else bridges
        on_tick = None
        if self.spec['faults'] == 'a03':
            signals = self.f.root / 'state' / 'probe' / A03_SIGNALS
            signals.mkdir(parents=True, exist_ok=True)
            self.gate = GateWatcher(self.f.registry['tap']['path'], signals)
            on_tick = self.gate
        self.sampler = Sampler(self.f, period, bridges=bridges, on_tick=on_tick).start()

    def stop_sampler(self):
        if getattr(self, 'sampler', None) is not None:
            self.sampler.stop()
            self.samples = (getattr(self, 'samples', None) or []) + self.sampler.rows
            self.sampler_errors = (getattr(self, 'sampler_errors', None) or []) + self.sampler.errors
            self.watcher_errors = (getattr(self, 'watcher_errors', None) or []) + self.sampler.watcher_errors
            self.sampler = None

    def schedule_witness(self, sample, story):
        f = self.f
        terminals = {e['order'] for e in sample['core_events'] if e.get('status') in TERMINAL}
        b = f.m['artifacts'].get('forwarder_b' if self.spec.get('swap') == 'fwd' else 'bridge_b') or {}
        t0_ms = self.t0 // 10**6
        w = {'capacity': (self.variant.get('ledger_capacity') or self.spec.get('ledger_capacity') or 100_000),
             'samples': getattr(self, 'samples', []), 'admission': sample['admission'], 'tap_dispatch': sample['dispatch_tap'],
             'me_journal': sample['me_journal'], 'order_terminals': len(terminals), 'hold': getattr(self, 'a03_hold', None),
             'a03': (story.get('summary') or {}).get('a03'), 'swaps': getattr(self, 'swaps', []), 't0_ms': t0_ms,
             't0_s': self.t0 / 1e9, 'latency': latency_table(sample['dispatch_tap'], sample['me_journal']),
             'settings': dict(SETTINGS), 'b_source_sha': b.get('source_sha'), 'n': 2, 'cold': getattr(self, 'cold', None),
             'forwarders': [s for s in FORWARDERS if (f.slots.get(s) or {}).get('state') == 'STARTED'],
             'ae_leaders': getattr(self, 'ae_leaders', []) + [leader_of(self.snaps.get('after'), 'ae')],
             'book': getattr(self, 'book', None), 'kill_window': getattr(self, 'kill_window', None),
             'kills': getattr(self, 'kills', None), 'election': getattr(self, 'election', None),
             'story_unresolved': (story.get('summary') or {}).get('unresolved')}
        return w

    def write_schedule_evidence(self, out, w):
        from credentials import redact as scrub
        out.mkdir(parents=True, exist_ok=True)
        redact = getattr(self.f, 'secret_values', [])
        for name, data in (('samples.json', w.get('samples')), ('latency.json', w.get('latency')),
                           ('s16-witness.json', {k: v for k, v in w.items() if k not in {'samples', 'latency', 'me_journal',
                                                                                       'tap_dispatch', 'admission', 'ledger',
                                                                                       'snaps'}}),
                           ('settings.json', SETTINGS)):
            (out / name).write_text(scrub(json.dumps(data, indent=1, default=str) + '\n', redact))
        if getattr(self, 'book_text', None):
            (out / 'me-book.txt').write_text(self.book_text)

    # ---------------------------------------------------------------- A04 regenesis

    def freeze_me(self):
        """Life 1's ME evidence, read after the pre-barrier drain and BEFORE regenesis('me'): the three members'
        journals (merged and equal), the resting legs, and the ME scrape (O-F1 / O-F4 of life 1)."""
        journal, has_seq = core_scenarios.me_journal(self.f)
        legs = self.f.me_open_legs()
        scrape = core_scenarios.barrier_scrape(self.f)
        return {'me_journal': journal, 'me_journal_seq': has_seq, 'me_open_legs': legs,
                'scrape_me': {r: v for r, v in scrape.items() if r.startswith('me')}, 'at_ns': time.time_ns()}

    def wait_fenced(self, first_start_ns):
        """fenced_forwarders line: both forwarders exit 78 (F8_EPOCH); the time from the first ME member's start
        and the stop reason from the log. Never raises: the line judges what was seen."""
        out = {}
        deadline = time.monotonic() + SETTINGS['FENCE_BOUND_S'] + 30
        while time.monotonic() < deadline and len(out) < len(FORWARDERS):
            for fwd in FORWARDERS:
                if fwd in out:
                    continue
                state = self.state(fwd)
                if not state['Running']:
                    logs = self.f.command(['docker', 'logs', '--tail', '80', self.cid(fwd)], check=False)
                    text = logs.stdout + logs.stderr
                    reason = 'F8_EPOCH_ZERO' if 'F8_EPOCH_ZERO' in text else 'F8_EPOCH' if 'F8_EPOCH' in text else None
                    out[fwd] = {'exit_code': state['ExitCode'], 'reason': reason,
                                'after_first_me_start_s': round((_iso_ns(state['FinishedAt']) - first_start_ns) / 1e9, 3)}
            self.sleep(0.5)
        for fwd in FORWARDERS:
            out.setdefault(fwd, {'exit_code': None, 'reason': None, 'after_first_me_start_s': None})
        return out

    def wait_bridges_halted(self):
        deadline = time.monotonic() + SETTINGS['BRIDGE_HALT_BOUND_S']
        seen = {}
        while time.monotonic() < deadline:
            for b in BRIDGES:
                status, body = self.health_of(b)
                if b not in seen and status == 503 and body.get('halted'):
                    seen[b] = round(SETTINGS['BRIDGE_HALT_BOUND_S'] - (deadline - time.monotonic()), 3)
            if len(seen) == len(BRIDGES):
                break
            self.sleep(0.5)
        return seen

    def halt_actions(self):
        """9 A04: 4 deposits and 2 withdrawals through fund_rows (M9, M2/M3), one create (GATE_CLOSED expected), one ADMIN
        OPEN (refused expected, AE:837-838). The create joins the sample's creates (O1 judges it)."""
        users = self.spec['story']['users']
        rows = [{'kind': 'deposit', 'user': u, 'asset': 0, 'amount': 1000 * FP} for u in users[:4]] + \
               [{'kind': 'withdraw', 'user': u, 'asset': 0, 'amount': 100 * FP} for u in users[:2]]
        funding = self.f.fund_rows(rows)
        meaning, reply = self.f.core('create', 'probe-gateway', user=users[4], market=1, side='BUY', type='LIMIT', tif='GTC',
                                     price=50 * FP, qty=FP // 100, budget=0, stop=0, delta=0, display=0, expires=0,
                                     rh=9, rl=1, ch=0, cl=900001)
        row = {'request': [9, 1], 'user': users[4], 'market': 1, 'side': 'BUY', 'type': 'LIMIT', 'tif': 'GTC',
               'price': 50 * FP, 'quantity': FP // 100, 'budget': 0, 'stop_price': 0, 'display_qty': 0}
        if meaning == 'UNKNOWN' or not reply or not reply.get('replies'):
            row['reply'] = {'outcome': 'UNKNOWN'}
        else:
            r = reply['replies'][-1]
            row['reply'] = ({'outcome': 'ACK', 'order': r['order'], 'duplicate': r['duplicate'], 'hold_asset': r['hold_asset'],
                             'hold_amount': r['hold_amount'], 'status': r['status']} if r['t'] == 'OrderAck'
                            else {'outcome': 'REJECT', 'reason': r['reason']})
        self.extra_creates = [row]
        gate_meaning, gate_reply = self.f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
        return {'halt_funding': funding, 'halt_create': row, 'open_gate': {'meaning': gate_meaning, 'reply': gate_reply}}

    def judge_life(self, life, story, pre, out):
        """Tap end, barrier, sample (declared per life), both oracles; evidence under ``out``."""
        tap_summary = self.wait_tap_end()
        tap = self.tap_rows()
        first, second = self.barrier(story, tap, tap_summary)
        after = self.snap('after' if life == 2 else 'halt', skip_me=self.frozen is not None)    # never the fresh ME
        sample = self.seal(self.build_sample(story, tap, tap_summary, second, pre), first, second)
        money, order = core_oracle.judge(sample), order_oracle.judge(sample)
        w = self.witness(sample, after)
        w.update(self.schedule_witness(sample, story))
        return {'sample': sample, 'money': money, 'order': order, 'w': w, 'after': after, 'tap_summary': tap_summary,
                'story': story, 'out': out}

    def run_a04(self):
        f, spec = self.f, self.spec
        regen = self.variant.get('regen', True)
        f.start(plan_for(spec, self.seed, variant=self.variant))
        self.snap('before')
        self.start_sampler()
        self.story_paths = f.start_story(self.story_args(), name=self.story_name)
        self.t0 = self.wait_marker('load_started', 60)['at_ns']
        self.post_load()
        story1 = self.wait_story()
        pre1 = self.pre_barrier()
        self.frozen = self.freeze_me() if regen else None
        pre_regen = self.snap('pre_regen')
        halt = {'fence': {}, 'bridges_halted_after_s': {}, 'engine_stops': []}
        if regen:
            row = self.ledger.open('regenesis', 'me', {})
            mark = len(f.registry.get('faults') or [])
            witness = f.regenesis(plan_for(spec, self.seed, variant=self.variant), 'me')
            halt['engine_stops'] = engine_stops(f.registry.get('faults') or [], mark)
            starts = [_iso_ns(self.state(f'me{i}')['StartedAt']) for i in range(3)]
            self.ledger.heal(row, 'me_genesis', dict(witness, first_me_start_ns=min(starts)))
            halt['fence'] = self.wait_fenced(min(starts))
            halt['bridges_halted_after_s'] = self.wait_bridges_halted()
            fresh = f.journal_dump('me0')          # evidence only: never enters the life-1 sample
            (self.out / 'life-1').mkdir(parents=True, exist_ok=True)
            (self.out / 'life-1' / 'fresh-me.jsonl').write_text('\n'.join(fresh) + '\n')
        halt.update(self.halt_actions())
        halt['bridge_health'] = {b: self.health_of(b) for b in BRIDGES}
        pre1['forwarders_fenced'] = halt['fence']
        self.stop_sampler()
        life1 = self.judge_life(1, story1, pre1, self.out / 'life-1')
        life1['w'].update(g1=int(f.genesis_id(1), 16), halt_scrape=life1['after'], core=life1['sample']['core'],
                          settle_rejected=life1['sample']['faults']['settle_rejected'], life2_gate_open=None, **halt)
        life1['w']['skipped_delta'] = {b: delta(pre_regen, life1['after'], b, 'bridge_skipped_total') for b in BRIDGES}
        lines1 = {name: LINES[name](life1['w']) for name in spec['lines'] + ['fault_cycles']}
        rows1 = of_rows(life1['after'], life1['sample'], me_scrape=(self.frozen or {}).get('scrape_me'), halted=regen)
        self.halt_w = life1['w']
        if self.red or not regen:
            result = self.decide(life1['money'], life1['order'], lines1, rows1, life1['sample'], life1['after'])
            self.finish_life(life1, lines1, rows1, result)
            return dict(result, lives={'1': {k: result.get(k) for k in ('status', 'oracle_status', 'lines', 'reasons')}})
        # Life 1's evidence is on disk when life 1 ends, before the core is wiped; the final verdict (with life 2's
        # genesis OPEN and second_life_exact) overwrites it after life 2
        provisional = self.decide(life1['money'], life1['order'], lines1, rows1, life1['sample'], life1['after'])
        self.finish_life(life1, lines1, rows1, dict(provisional, provisional=True,
                                                    note='life 1 judged at its end; life 2 pending (final verdict overwrites)'))
        # life 2: the dual genesis: core wiped and bound to g2 via the bridges, fresh projection, fresh users
        self.frozen = None
        ledger1, snaps1 = self.ledger, self.snaps
        self.ledger, self.snaps, self.extra_creates, self.samples = Ledger(), {}, [], []
        row = self.ledger.open('regenesis', 'core', {})
        mark = len(f.registry.get('faults') or [])
        witness = f.regenesis(plan_for(spec, self.seed, variant=self.variant, life=2), 'core')
        core_stops = engine_stops(f.registry.get('faults') or [], mark)
        self.ledger.heal(row, 'core_genesis', witness)
        gate = f.tap_gate(0)
        self.life_no, self.story_name, self.resolve_name = 2, 'story-life2', 'resolve-life2.go'
        self.snap('before')
        self.start_sampler()
        self.story_paths = f.start_story(self.story_args(), name=self.story_name)
        self.t0 = self.wait_marker('load_started', 60)['at_ns']
        self.post_load()
        story2 = self.wait_story()
        pre2 = self.pre_barrier()
        self.stop_sampler()
        life2 = self.judge_life(2, story2, pre2, self.out / 'life-2')
        s2 = life2['sample']
        g2 = int(f.genesis_id(2), 16)
        epoch2 = [t['trade_id'] for t in s2['me_journal'] if t['type'] == 'trade' and t.get('me_epoch') == g2]
        life1['w']['life2_gate_open'] = bool(gate and gate.get('state') == 'OPEN')
        life2['w']['engine_stops'] = core_stops
        observed = sorted({e['me_epoch'] for e in s2['me_journal'] if e.get('me_epoch') is not None})   # observed
        life1['w']['life2'] = {'money': life2['money'], 'order': life2['order'], 'epochs': observed, 'g2': g2,
                               'declared_epochs': s2['declared']['epochs'],
                               'bound_me_epoch': s2['core'].get('bound_me_epoch'),
                               'last_applied_trade_id': s2['core']['last_applied_trade_id'],
                               'max_epoch2_trade': max(epoch2) if epoch2 else 0}
        lines1 = {name: LINES[name](life1['w']) for name in spec['lines'] + ['fault_cycles']}
        lines2 = {'second_life_exact': LINES['second_life_exact'](life1['w']), 'fault_cycles': LINES['fault_cycles'](life2['w']),
                  'engine_polite_stop': LINES['engine_polite_stop'](life2['w'])}
        rows2 = of_rows(life2['after'], s2)
        ledger2, snaps2 = self.ledger, self.snaps
        self.ledger, self.snaps, self.life_no = ledger1, snaps1, 1
        v1 = self.decide(life1['money'], life1['order'], lines1, rows1, life1['sample'], life1['after'])
        self.finish_life(life1, lines1, rows1, v1)
        self.ledger, self.snaps, self.life_no = ledger2, snaps2, 2
        v2 = verdict(life2['money'], life2['order'], lines2, rows2, (), s2['declared']['fault_open'])
        self.finish_life(life2, lines2, rows2, v2)
        status = 'FAIL' if 'FAIL' in (v1['status'], v2['status']) else 'INCONCLUSIVE' \
            if 'INCONCLUSIVE' in (v1['status'], v2['status']) else 'PASS'
        return dict(v1, status=status, reasons=[f'life 1: {r}' for r in v1['reasons']] + [f'life 2: {r}' for r in v2['reasons']],
                    lines=dict(v1['lines'], **{'life2.' + k: v['holds'] for k, v in lines2.items()}),
                    lives={'1': {k: v1.get(k) for k in ('status', 'oracle_status', 'lines', 'reasons')},
                           '2': {'status': v2['status'], 'reasons': v2['reasons'],
                                 'oracle_status': {'money': life2['money']['status'], 'order': life2['order']['status']},
                                 'lines': {k: v['holds'] for k, v in lines2.items()}}})

    def finish_life(self, life, lines, rows, result):
        out = life['out']
        saved = self.out
        self.out = out
        try:
            self.write_evidence(life['sample'], life['money'], life['order'], lines, rows, life['w'], life['story'],
                                life['tap_summary'], result)
            self.write_schedule_evidence(out, life['w'])
        finally:
            self.out = saved


# ------------------------------------------------------------------ O-F rows and the verdict


def engine_stops(faults, mark=0):
    """The polite engine stops (fixture ``stop`` witnesses) recorded after index ``mark`` of the fixture's fault log."""
    return [dict(x) for x in faults[mark:] if x.get('kind') == 'stop' and x.get('target') in core_contracts.ENGINES]


def of_rows(after, sample, me_scrape=None, halted=False):
    """``me_scrape``: A04 life 1's ME rows from the pre-wipe freeze; ``halted``: the declared halt, whose bridges are
    judged by halt_local, not by bridges_not_halted."""
    if me_scrape:
        after = dict(after, **me_scrape)
    of1 = {m: {n: value(after, m, n, 0) for n in ME_REFUSALS} for m in ('me0', 'me1', 'me2')}
    ae = leader_of(after, 'ae')
    me = leader_of(after, 'me')
    of4 = {'pending': value(after, ae, 'core_pending_commands'), 'release_backlog': value(after, ae, 'core_release_backlog'),
           'core_ledger': value(after, ae, 'core_me_ledger_size'), 'me_ledger': value(after, me, 'match_command_ledger_size')}
    try:
        gap = Model(sample).tap_closed()
        of5 = {'closed': gap is None, 'open_gap': gap}
    except (Inconclusive, Violation) as error:
        of5 = {'closed': False, 'error': str(error)}
    halted_bridges = {b: value(after, b, 'bridge_halted') for b in BRIDGES}
    rows = {
        'O-F1': {'holds': all(v == 0 for row in of1.values() for v in row.values()), 'detail': of1},
        'O-F4': {'holds': ae is not None and me is not None and of4['pending'] == 0 and of4['release_backlog'] == 0
                 and of4['core_ledger'] is not None and of4['core_ledger'] == of4['me_ledger'], 'detail': of4},
        'O-F5': {'holds': of5['closed'], 'detail': of5, 'inconclusive_when_failing': True},
        'bridges_not_halted': {'holds': all(v == 0 for v in halted_bridges.values()), 'detail': halted_bridges},
    }
    if halted:
        del rows['bridges_not_halted']
    return rows


def verdict(money, order, lines, rows, setup_failures=(), fault_open=False):
    """FAIL > INCONCLUSIVE > PASS. A line that does not hold and a window not held are FAIL; an open fault or a tap
    gap not closed (O-F5) is INCONCLUSIVE; PASS needs both oracles PASS and every line and row."""
    reasons = []
    if setup_failures:
        reasons += [('FAIL', f'setup: {s}') for s in setup_failures]
    for name, result in (('money', money), ('order', order)):
        if result['status'] == 'FAIL':
            failed = sorted(k for k, v in result.get('rules', {}).items() if v['status'] == 'FAIL') or [result.get('error')]
            reasons.append(('FAIL', f'{name} oracle FAIL {failed}'))
    for name, line in lines.items():
        if not line['holds']:
            # with a fault still open its effect cannot be judged yet: INCONCLUSIVE, the sibling rule; a line whose
            # witness is missing (inconclusive) likewise
            reasons.append(('INCONCLUSIVE' if fault_open or line.get('inconclusive') else 'FAIL',
                            f'non-vacuity line {name} does not hold' + (' (witness missing)' if line.get('inconclusive') else '')))
    for name, row in rows.items():
        if not row['holds']:
            reasons.append(('INCONCLUSIVE' if row.get('inconclusive_when_failing') else 'FAIL', f'{name} does not hold'))
    if fault_open:
        reasons.append(('INCONCLUSIVE', 'a fault row was never observed healed (fault_open at the barrier)'))
    for name, result in (('money', money), ('order', order)):
        if result['status'] == 'INCONCLUSIVE':
            open_rules = sorted(k for k, v in result.get('rules', {}).items() if v['status'] == 'INCONCLUSIVE') or [result.get('error')]
            reasons.append(('INCONCLUSIVE', f'{name} oracle INCONCLUSIVE {open_rules}'))
    status = 'FAIL' if any(r[0] == 'FAIL' for r in reasons) else 'INCONCLUSIVE' if reasons else 'PASS'
    return {'status': status, 'reasons': [r[1] for r in reasons]}


def with_watcher_errors(v, errors):
    """An exception in the sampler's on_tick watcher (A03's GateWatcher writes the story's phase markers) leaves the
    story on its marker timeouts, so what the run shows is not the schedule it declared: a PASS (GREEN, control or RED)
    becomes INCONCLUSIVE; a FAIL stays FAIL with the error named."""
    if not errors:
        return v
    reason = f'harness: the sampler watcher raised {len(errors)} time(s): {errors[:3]}'
    status = 'INCONCLUSIVE' if v['status'] == 'PASS' else v['status']
    return dict(v, status=status, reasons=list(v.get('reasons') or []) + [reason], watcher_errors=list(errors[:10]))


def control_verdict(money, order, lines, named):
    """A control run PASSES as a control when both oracles PASS and every named line FAILS."""
    if money['status'] != 'PASS' or order['status'] != 'PASS':
        return {'status': 'INCONCLUSIVE' if 'FAIL' not in {money['status'], order['status']} else 'FAIL',
                'reasons': [f'control needs both oracles PASS: money {money["status"]}, order {order["status"]}']}
    unjudged = [n for n in named if lines[n].get('inconclusive')]
    if unjudged:
        return {'status': 'INCONCLUSIVE', 'reasons': [f'control line {n} has no witness: {lines[n]["detail"]}' for n in unjudged]}
    vacuous = [n for n in named if lines[n]['holds']]
    if vacuous:
        return {'status': 'FAIL', 'reasons': [f'control line {n} held without its fault: the line is vacuous' for n in vacuous]}
    return {'status': 'PASS', 'reasons': [f'line {n} FAILS without its fault, as it must' for n in named]}


def red_verdict(kind, money, order, preconditions):
    """8.1 RED-1: order FAIL O10 with its text, the nc forwarders Running and /health 200 at the barrier.
    RED-2: M7/M8 PASS with settle rows present AND one of O4/M5/O5/M4 FAIL with its text; the nc bridges never halted
    and /ready 200 throughout. A RED that is GREEN is a BLOCKER (FAIL); a missing precondition is INCONCLUSIVE."""
    missing = [k for k, v in preconditions.items() if not v]
    if kind in ('red-a03', 'red-a04'):
        # O12 FAIL on the named text; the mechanism witnesses are preconditions (a crash is not a RED)
        text = RED_A03_TEXT if kind == 'red-a03' else RED_A04_TEXT
        o12 = order.get('rules', {}).get('O12', {})
        if o12.get('status') == 'FAIL' and text in o12.get('detail', ''):
            if missing:
                return {'status': 'INCONCLUSIVE', 'red': 'NOT_ACCEPTED', 'reasons': [f'{kind} O12 fired but precondition missing: {missing}']}
            return {'status': 'PASS', 'red': 'RED', 'reasons': [f'O12 FAIL: {o12["detail"][:300]}']}
        if order['status'] == 'PASS' and money['status'] == 'PASS':
            return {'status': 'FAIL', 'red': 'GREEN', 'reasons': [f'BLOCKER: {kind} is GREEN']}
        return {'status': 'INCONCLUSIVE', 'red': 'UNJUDGED', 'reasons': [f'O12 {o12.get("status")}: {o12.get("detail", "")[:200]}']}
    if kind == 'red1':
        o10 = order.get('rules', {}).get('O10', {})
        if o10.get('status') == 'FAIL' and RED1_TEXT in o10.get('detail', ''):
            if missing:
                return {'status': 'INCONCLUSIVE', 'reasons': [f'RED-1 fired but precondition missing: {missing}']}
            return {'status': 'PASS', 'red': 'RED', 'reasons': [f'O10 FAIL: {o10["detail"][:200]}']}
        if order['status'] == 'PASS' and money['status'] == 'PASS':
            return {'status': 'FAIL', 'red': 'GREEN', 'reasons': ['BLOCKER: the resync-skipping forwarder is GREEN']}
        return {'status': 'INCONCLUSIVE', 'red': 'UNJUDGED', 'reasons': [f'O10 {o10.get("status")}; order {order["status"]}']}
    rules = dict(money.get('rules', {}), **order.get('rules', {}))
    named = [r for r, texts in RED2_TEXTS.items()
             if rules.get(r, {}).get('status') == 'FAIL' and any(t in rules[r].get('detail', '') for t in texts)]
    trade_path = all(rules.get(r, {}).get('status') == 'PASS' for r in ('M7', 'M8')) and preconditions.get('settle_rows', False)
    if named and trade_path and not missing:
        return {'status': 'PASS', 'red': 'RED', 'named': named,
                'reasons': [f'{r} FAIL: {rules[r]["detail"][:160]}' for r in named]}
    if money['status'] == 'PASS' and order['status'] == 'PASS':
        return {'status': 'FAIL', 'red': 'GREEN', 'reasons': ['BLOCKER: the outcome-dropping bridge is GREEN']}
    return {'status': 'INCONCLUSIVE' if missing or not trade_path else 'FAIL', 'red': 'NOT_ACCEPTED',
            'reasons': [f'named rules {named}, M7/M8 trade path {trade_path}, missing preconditions {missing}']}


# ------------------------------------------------------------------ the run


def story_extra_s(red):
    """Wall seconds the story may run beyond its nominal length: the RED-2 builds never confirm an outcome."""
    return RED2_STORY_EXTRA_S if red and red.startswith('red2') else 0


def plan_for(spec, seed, extra_s=0, variant=None, life=1):
    """The genesis plan of one life. ``ledger_capacity`` (A03, its cap100k control), life 2's fresh users, and the
    life-1 tap of A04 sized to outlast the halt phase (the life-1 tap ends on its duration only)."""
    story = spec['story']
    users = spec['life2_users'] if life == 2 else story['users']
    tap_s = 60 + story_seconds(story) + 30 + 30 + 2 * ELECTION_BOUND_S + PRE_BARRIER_S + 30 + extra_s \
        + ((spec.get('tap_extra_s', 0) + (SETTINGS[spec['tap_extra_setting']] if 'tap_extra_setting' in spec else 0))
           if life == 1 else 0)
    plan = {'users': users, 'markets': [1, 2, 3, 4, 5], 'funding_for': funding_script(story), 'seed': seed,
            'risk': {'per_sec': 1000, 'max_open': 5000, 'slippage_bps': 100, 'collar_bps': 5000}, 'tap_ms': tap_s * 1000}
    capacity = (variant or {}).get('ledger_capacity', spec.get('ledger_capacity'))
    if capacity is not None:
        plan['ledger_capacity'] = capacity
    return plan


class DrillRun(ScheduleDrills):
    def __init__(self, fixture, name, out_dir, variant=None, red=None):
        self.f, self.name, self.out = fixture, name, Path(out_dir)
        self.spec = DRILLS[name]
        self.variant = variant or {}
        self.red = red
        self.ledger = Ledger()
        self.snaps, self.windows, self.partition, self.extra = {}, {}, {}, {}
        self.restarted = set()
        self.ordering_exception = None
        self.bridge_watch = []
        self.seed = fixture.m['seed'] & 0xFFFFFFFF
        self.clock, self.sleep = fixture.clock, fixture.sleep
        # Slots a control removed, the life being judged, the per-life story and resolution gate names
        self.removed, self.life_no, self.story_name, self.resolve_name = set(), 1, 'story', 'resolve.go'
        self.extra_creates, self.frozen = [], None

    # ---------------------------------------------------------------- small helpers

    def cid(self, role):
        return self.f.registry['containers'][role]

    def state(self, role):
        return self.f.inspect('container', self.cid(role))['State']

    def snap(self, label, skip_me=False):
        scrape = core_scenarios.barrier_scrape(self.f, skip_me=True) if skip_me else core_scenarios.barrier_scrape(self.f)
        scrape['_at_ns'] = time.time_ns()
        self.snaps[label] = scrape
        return scrape

    def at(self, seconds):
        """Sleep until t0 + seconds of the story's own clock (wall epoch ns, RealClock)."""
        remaining = (self.t0 + seconds * 1e9 - time.time_ns()) / 1e9
        if remaining > 0:
            self.sleep(remaining)

    def markers(self):
        path = self.story_paths['markers']
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []

    def wait_marker(self, name, bound_s, where=None):
        deadline = time.monotonic() + bound_s
        while time.monotonic() < deadline:
            for m in self.markers():
                if m.get('marker') == name and (where is None or where(m)):
                    return m
            if self.story_paths['exit'].exists():
                break
            self.sleep(0.2)
        raise Inconclusive(f'story marker {name} not written within {bound_s} s')

    def tap_rows(self):
        return core_scenarios.read_tap(Path(self.f.registry['tap']['path']))

    def wait_leader(self, engine, old, bound_s=ELECTION_BOUND_S):
        started = time.monotonic()
        while time.monotonic() - started < bound_s:
            leader = self.f.leader(engine)
            if leader is not None and leader != old:
                status, _ = self.f.ready_body(leader)
                if status == 200:
                    return leader, round(time.monotonic() - started, 3)
            self.sleep(0.2)
        return None, None

    # ---------------------------------------------------------------- fault primitives with ledger rows

    def pause(self, role, duration_s):
        witness = self.f.pause(role, duration_s=duration_s, heal_bound_s=HEAL_BOUND_S)
        return self.ledger.open('pause', role, witness)

    def kill(self, role, leader_of_engine=None, wait=True):
        # an engine member is restarted only after the load, so its fault_targets bound covers the whole story
        bound = story_seconds(self.spec['story']) + 4 * 30 + 180 if role[:2] in {'ae', 'me'} else HEAL_BOUND_S
        witness = dict(self.f.kill(role, heal_bound_s=bound))
        row = self.ledger.open('kill', role, witness)
        if leader_of_engine:
            witness['was_leader'] = True
            if wait:
                self.observe_election(row, leader_of_engine)
        return row

    def observe_election(self, row, engine):
        new, election = self.wait_leader(engine, row['target'])
        row['witness'].update(new_leader=new, election_s=election)

    def restart(self, row, readiness=None):
        role = row['target']
        restart = self.f.restart(role, readiness=readiness) if readiness else self.f.restart(role)
        self.restarted.add(role)
        return self.ledger.heal(row, 'restart', dict(restart, ready=True))

    def await_branches(self, rows, before, thawed_ns, due=None):
        """After a thaw, observe which branch each process takes: A = it exits 70 (restart, /ready 200);
        B = it stays up and reconnects (counters move after /health or /ready showed the loss); none = it stays up, /ready
        200, no reconnect by NO_LOSS_AFTER_S (the pause did not close a session). An exit other than 70 is INCONCLUSIVE.
        A row whose heal is not observed within HEAL_BOUND_S stays open (fault_open at the barrier: INCONCLUSIVE).
        ``due`` = (wall ns, action): an action of the schedule that must not wait for the branches (lostack's forwarder
        restart at t=37, review F9); it runs once, between two observations, as soon as its time has come. Returns
        whether it ran."""
        pending, saw_down = dict(rows), {r: False for r in rows}
        fired = [due is None]

        def run_due():
            if not fired[0] and time.time_ns() >= due[0]:
                fired[0] = True
                due[1]()
        while pending:
            elapsed = (time.time_ns() - thawed_ns) / 1e9
            for role, row in list(pending.items()):
                run_due()
                state = self.state(role)
                if not state['Running']:
                    if state['ExitCode'] != 70:
                        raise Inconclusive(f'{role} exited {state["ExitCode"]} after the thaw, expected 70 or a reconnect')
                    readiness = self.extra.get('readiness', {}).get(role)
                    restart = self.f.restart(role, readiness=readiness) if readiness else self.f.restart(role)
                    self.restarted.add(role)
                    after = self.wait_resync(role, None)
                    self.ledger.heal(row, 'A', {'exit_code': 70, 'exit_after_thaw_s': round(elapsed, 3), 'ready': True,
                                                'restart': restart, 'resync_delta': after})
                    del pending[role]
                    continue
                status, body = self.f.ready_body(role)
                health = self.health(role)
                if status != 200 or health.get('coreConnected') is False:
                    saw_down[role] = True
                    continue
                scrape = core_scenarios.barrier_scrape(self.f)
                if role.startswith('bridge'):
                    d = delta(before, scrape, role, 'bridge_client_sessions_opened_total')
                    by_cluster = None
                else:
                    by_cluster = {c: delta(before, scrape, role, f'forwarder_session_reconnect_total{{cluster="{c}"}}') for c in ('core', 'me')}
                    d = min(by_cluster.values()) if all(v is not None for v in by_cluster.values()) else None
                if (d or 0) >= 1:
                    resync = sum(delta(before, scrape, role, f'forwarder_resync_total{{reason="T{t}"}}') or 0 for t in range(1, 8)) \
                        if role.startswith('fwd') else None
                    self.f.close_fault(role)
                    self.ledger.heal(row, 'B', {'saw_down': saw_down[role], 'reconnect_delta': d, 'ready': True,
                                                'reconnect_delta_by_cluster': by_cluster, 'resync_delta': resync})
                    del pending[role]
                elif elapsed >= NO_LOSS_AFTER_S:
                    self.f.close_fault(role)
                    self.ledger.heal(row, 'none', {'saw_down': saw_down[role], 'reconnect_delta': d, 'ready': True,
                                                   'reconnect_delta_by_cluster': by_cluster})
                    del pending[role]
            if pending and (time.time_ns() - thawed_ns) / 1e9 > HEAL_BOUND_S:
                for role in pending:
                    self.extra.setdefault('heal_not_observed', []).append(role)
                return fired[0]
            if pending:
                self.sleep(0.25)
        return fired[0]

    def health(self, role):
        port, _ = self.f.ready_target(role)
        try:
            return json.loads(self.f.http(role, port, '/health').get('body') or '{}')
        except (ValueError, TypeError):
            return {}

    def resync_total(self, scrape, role):
        return sum(value(scrape, role, f'forwarder_resync_total{{reason="T{t}"}}', 0) for t in range(1, 8))

    def wait_resync(self, role, peer, bound_s=15):
        """After a forwarder restart: its resync counter (fresh process) moves above 0; returns the value seen."""
        if not role.startswith('fwd'):
            return None
        deadline = time.monotonic() + bound_s
        total = 0
        while time.monotonic() < deadline:
            total = self.resync_total(core_scenarios.barrier_scrape(self.f), role)
            if total > 0:
                return total
            self.sleep(0.5)
        return total

    # ---------------------------------------------------------------- fault schedules

    def faults_none(self):
        pass

    def faults_lostack(self):
        pause_s = self.variant.get('pause_s', 15)
        before = self.snap('pre_pause')
        self.at(20)
        pauses = {b: self.pause(b, pause_s) for b in BRIDGES}
        self.at(22)
        kills = {fwd: self.kill(fwd) for fwd in FORWARDERS}
        self.at(20 + pause_s)
        thawed = time.time_ns()
        for b in BRIDGES:
            self.f.unpause(b)
        restart_at = max(37, 20 + pause_s + 2)   # the forwarders restart after the bridges resumed (t=37)
        record = self.extra.setdefault('lostack_forwarder_restart', {'planned_s': restart_at})

        def restart_forwarders():
            # review F9: at t=37 whatever branch the bridges are still in; their rows do not depend on it
            for fwd, row in kills.items():
                record[fwd + '_at_s'] = round((time.time_ns() - self.t0) / 1e9, 3)
                row['witness']['restart_at_s'] = record[fwd + '_at_s']
                self.restart(row, readiness=self.extra.get('readiness', {}).get(fwd))
        if not self.await_branches(pauses, before, thawed, due=(self.t0 + int(restart_at * 1e9), restart_forwarders)):
            self.at(restart_at)                  # the bridges' branches resolved before t=37
            restart_forwarders()

    def faults_coreleader(self):
        self.at(30)
        leader = self.f.leader('ae')
        if leader is None:
            raise Inconclusive('no single AE leader at t=30 s')
        self.kill(leader, leader_of_engine='ae')     # restarted after the load (post_load)

    def faults_meleader(self):
        self.at(30)
        leader = self.f.leader('me')
        if leader is None:
            raise Inconclusive('no single ME leader at t=30 s')
        survivors_seq = [value(self.snap('pre_me_kill'), f'me{i}', 'match_engine_next_journal_seq') for i in range(3)]
        self.kill(leader, leader_of_engine='me')
        self.capture_ordering_exception(leader, survivors_seq)

    def capture_ordering_exception(self, killed, seqs_at_kill):
        """The window is the ids the new ME term's first T2 resync re-sent: until_seq = the forwarders'
        last_sent right after their T2 resync counter moved; from_journal_seq = the survivors' next journal seq at the kill."""
        before = self.snaps.get('before')
        start = [s for i, s in enumerate(seqs_at_kill) if f'me{i}' != killed and s is not None]
        deadline = time.monotonic() + ELECTION_BOUND_S
        while time.monotonic() < deadline:
            scrape = core_scenarios.barrier_scrape(self.f)
            moved = [fwd for fwd in FORWARDERS if (delta(before, scrape, fwd, 'forwarder_resync_total{reason="T2"}') or 0) > 0]
            if moved:
                until = max(value(scrape, fwd, 'forwarder_dispatch_seq{point="last_sent"}', 0) for fwd in FORWARDERS)
                self.ordering_exception = {'me_term': {'killed': killed, 'new_leader': leader_of(scrape, 'me')},
                                           'until_seq': int(until), 'from_journal_seq': int(min(start)) if start else None,
                                           'forwarders_resynced': moved}
                return
            self.sleep(0.5)
        self.ordering_exception = None
        self.extra['ordering_exception'] = 'no T2 resync observed within the bound; the window stays empty (O9 judges all)'

    def faults_fwdrestart(self):
        for fwd, t in (('fwd0', 15), ('fwd1', 35)):
            peer = 'fwd1' if fwd == 'fwd0' else 'fwd0'
            self.at(t)
            if self.variant.get('kill', True) is False:
                self.ledger.skip('kill', fwd, 'control fwdrestart-nokill')
                continue
            pre = core_scenarios.barrier_scrape(self.f)
            row = self.kill(fwd)
            self.at(t + 5)
            restart = self.f.restart(fwd)
            self.restarted.add(fwd)
            resync = self.wait_resync(fwd, peer)
            post = core_scenarios.barrier_scrape(self.f)
            self.ledger.heal(row, 'restart', dict(restart, ready=True, resync_after=resync,
                                                  peer_resync_delta=self.resync_total(post, peer) - self.resync_total(pre, peer)))

    def faults_fwdpause(self):
        pause_s = self.variant.get('pause_s', 15)
        for t in (15, 45):
            self.at(t)
            before = core_scenarios.barrier_scrape(self.f)
            me = self.f.leader('me')     # looked up before the pause; the two seq reads bracket the pause
            seq_pause = self.me_seq(me)
            row = self.pause('fwd0', pause_s)
            row['witness']['me_seq_pause'] = seq_pause
            self.at(t + pause_s)
            # read BEFORE the unpause: a surviving fwd0 flushes its ring within a second of the thaw (fwdpause-pause3: 142
            # RELEASED copies from seq 6698 while a read taken after the unpause saw 6873), so a later read would hide them
            row['witness']['me_seq_thaw'] = self.me_seq(me)
            thawed = time.time_ns()
            self.f.unpause('fwd0')
            self.await_branches({'fwd0': row}, before, thawed)

    def faults_partition(self):
        drop = self.variant.get('drop', True)
        self.at(10)
        rows = {}
        me = self.f.leader('me')     # looked up before the drop: the sampler reads this member only
        if me is None:
            raise Inconclusive('no single ME leader at t=10 s for partition phase 1')

        def add():
            for fwd in FORWARDERS:
                if not drop:     # the control samples the same way with nothing dropped: the line must fail on data
                    self.ledger.skip('partition', fwd, 'control partition-nodrop, phase 1')
                    continue
                added = self.f.partition(fwd, 'me', 'ingress', 'add')
                rows[fwd] = self.ledger.open('partition', fwd, {'phase': 1, 'target': 'me', 'kind': 'ingress',
                                                                'added_ns': time.time_ns(), 'helper': len(added)})

        def delete():
            for fwd, row in rows.items():
                self.f.partition(fwd, 'me', 'ingress', 'delete')
                row['witness']['deleted_ns'] = time.time_ns()
                row['witness']['drop_s'] = round((row['witness']['deleted_ns'] - row['witness']['added_ns']) / 1e9, 3)

        self.phase1_ae = self.f.leader('ae')
        samples = self.sample_me_progress(me, PARTITION1_DROP_S, add, delete)
        stalled = _stalled_seq(samples)
        self.partition.update(phase1_samples=samples, me_stall_s=me_stall(samples), me_stall_upper_s=me_stall(samples, upper=True),
                              phase1_heal_observed=bool(samples) and samples[-1]['me_seq'] is not None
                              and samples[-1]['me_seq'] != stalled)
        self.heal_ready(rows)
        self.at(30)
        before = core_scenarios.barrier_scrape(self.f)
        if not drop:
            for fwd in FORWARDERS:
                self.ledger.skip('partition', fwd, 'control partition-nodrop, phase 2')
            self.sleep(15)
        else:
            leader = self.f.leader('ae')
            if leader is None:
                raise Inconclusive('no single AE leader at t=30 s for partition phase 2')
            rows = {}
            for fwd in FORWARDERS:
                self.f.partition(fwd, leader, 'ingress', 'add')
                rows[fwd] = self.ledger.open('partition', fwd, {'phase': 2, 'target': leader, 'kind': 'ingress',
                                                                'added_ns': time.time_ns()})
            self.sleep(15)
            for fwd, row in rows.items():
                self.f.partition(fwd, leader, 'ingress', 'delete')
                row['witness']['deleted_ns'] = time.time_ns()
                row['witness']['drop_s'] = round((row['witness']['deleted_ns'] - row['witness']['added_ns']) / 1e9, 3)
            self.heal_ready(rows)
        after = core_scenarios.barrier_scrape(self.f)
        self.partition['phase2'] = {fwd: {
            'reconnect_core': delta(before, after, fwd, 'forwarder_session_reconnect_total{cluster="core"}'),
            'new_leader_core': delta(before, after, fwd, 'forwarder_session_new_leader_total{cluster="core"}')}
            for fwd in FORWARDERS}

    @staticmethod
    def pace(read):
        """The sleep that makes reads start PHASE1_CADENCE_S apart (a read itself costs 0.1 to 0.5 s)."""
        return max(0.0, PHASE1_CADENCE_S - (read['t1'] - read['t0']))

    def me_seq(self, me):
        """The ME leader's next journal seq (one GET), None when unreadable."""
        if me is None:
            return None
        try:
            return self.f.metrics(me, self.f.m['ports']['me_metrics']).get('match_engine_next_journal_seq')
        except Inconclusive:
            return None

    def phase1_read(self, me, started, phase, full=True):
        """One phase-1 read: the ME leader's next journal seq and the forwarders' core head (three GETs, not the
        12-container barrier scrape), stamped before (t0) and after (t1) on one monotonic clock."""
        t0 = time.monotonic() - started

        def get(role, port, name):
            try:
                return self.f.metrics(role, port).get(name)
            except Inconclusive:
                return None
        seq = get(me, self.f.m['ports']['me_metrics'], 'match_engine_next_journal_seq')
        if not full:     # The ME seq alone (one GET) keeps the cadence near 150 ms; the core side every 4th read
            return {'t0': round(t0, 3), 't1': round(time.monotonic() - started, 3), 'phase': phase, 'me_seq': seq,
                    'core_head': None, 'core_pending': None}
        heads = [get(f, self.f.m['ports']['forwarder_http'], 'forwarder_dispatch_seq{point="core_head"}') for f in FORWARDERS]
        # The forwarders' core_head is their own consumption head and freezes with the cut forwarders (first partition
        # run: 2121 for the whole drop). The AE leader's pending-command gauge is the core's side: it rises while the core
        # dispatches and the ME applies nothing.
        ae = getattr(self, 'phase1_ae', None)
        pending = get(ae, self.f.m['ports']['ae_metrics'], 'core_pending_commands') if ae else None
        return {'t0': round(t0, 3), 't1': round(time.monotonic() - started, 3), 'phase': phase, 'me_seq': seq,
                'core_head': max((h for h in heads if h is not None), default=None), 'core_pending': pending}

    @staticmethod
    def background(fn):
        """Run ``fn`` on a thread and return it (tests replace this with a synchronous stub); the sampler keeps reading
        while a netfilter helper call runs (each costs about 2.5 s)."""
        import threading
        errors = []

        def target():
            try:
                fn()
            except BaseException as error:    # re-raised by the sampler after the join
                errors.append(error)
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.errors = errors
        return thread

    def sample_while(self, me, started, samples, phase, thread):
        """Read every PHASE1_CADENCE_S while ``thread`` runs (the hole: the helper calls took 2 s unread)."""
        while thread.is_alive():
            samples.append(self.phase1_read(me, started, phase, full=len(samples) % 4 == 0))
            self.sleep(self.pace(samples[-1]))
        thread.join()
        if thread.errors:
            raise thread.errors[0]

    def sample_me_progress(self, me, hold_s, add, delete, after_bound_s=PARTITION1_HEAL_BOUND_S):
        """Partition phase 1 witness, sampled from before the add THROUGH the heal: one read
        before the add; reads every 200 ms while the add helper runs, while the drop is in place for ``hold_s``
        (measured from the last add), while the delete helper runs, then until the ME seq moves past the value it
        stalled at (bounded). me_stall() reports the lower bound of the gap (first to last read at the stalled seq); a
        run whose heal is never seen counts nothing."""
        started = time.monotonic()
        samples = [self.phase1_read(me, started, 'pre')]
        self.sample_while(me, started, samples, 'add', self.background(add))
        dropped = time.monotonic()
        while time.monotonic() - dropped < hold_s:
            samples.append(self.phase1_read(me, started, 'drop', full=len(samples) % 4 == 0))
            self.sleep(max(0.0, min(self.pace(samples[-1]), hold_s - (time.monotonic() - dropped))))
        stalled = _stalled_seq(samples)
        self.sample_while(me, started, samples, 'delete', self.background(delete))
        healed = time.monotonic()
        while time.monotonic() - healed < after_bound_s:
            if samples[-1]['me_seq'] is not None and stalled is not None and samples[-1]['me_seq'] != stalled:
                break
            samples.append(self.phase1_read(me, started, 'heal', full=len(samples) % 4 == 0))
            if samples[-1]['me_seq'] is not None and stalled is not None and samples[-1]['me_seq'] != stalled:
                break
            self.sleep(self.pace(samples[-1]))
        return samples

    def heal_ready(self, rows, bound_s=HEAL_BOUND_S):
        """A partition heals when the forwarder answers /ready 200 again after the delete."""
        for fwd, row in rows.items():
            deadline = time.monotonic() + bound_s
            while time.monotonic() < deadline:
                status, _ = self.f.ready_body(fwd)
                if status == 200:
                    self.ledger.heal(row, 'ready', {'ready': True})
                    break
                self.sleep(0.25)

    def faults_driverkill(self):
        if self.f.m['artifacts'][self.f.m['slot_artifacts']['fwd0']]['driver'] != 'external':
            raise Inconclusive('driverkill needs the external driver manifest (C13): fwd0 runs embedded')
        for t in (20, 40):
            self.at(t)
            identity = self.f.driver_identity('fwd0')
            witness = dict(self.f.exec_kill('fwd0', '/data/aeronmd.pid', 'KILL'), identity_before=identity)
            row = self.ledger.open('exec_kill', 'fwd0', witness)
            exit_row = self.f.wait_exit('fwd0', 70, EXIT70_BOUND_S)
            restart = self.f.restart('fwd0')
            self.restarted.add('fwd0')
            self.ledger.heal(row, 'restart', {'exit': exit_row, 'restart': restart, 'ready': True})

    def faults_lifecycle_faults(self):
        """Two windows held open by pausing both bridges (< 5 s), not by racing a kill."""
        hold = self.wait_marker('hold_ready', 120, where=lambda m: m.get('hold') == 'slice1_exhausting_fill')
        parent = held_order(hold)
        self.windows['slice1'] = self.hold_window(
            hold, 'ae', parent, lambda events: iceberg_slice_journaled(events, parent))
        hold = self.wait_marker('hold_ready', 120, where=lambda m: m.get('hold') == WINDOW2_HOLD)
        index = int(WINDOW2_HOLD.split(':')[1])
        self.windows['replace'] = self.hold_window(
            hold, 'me', None, None, marker=('replace_open', lambda m: m.get('index') == index))

    def hold_window(self, hold, engine, order, predicate, marker=None):
        """Pause both bridges, release the story's hold, wait for the ME journal to show the records, kill the leader of
        ``engine``, thaw both bridges. A window not held within the pause budget is a setup FAIL."""
        before = core_scenarios.barrier_scrape(self.f)
        # every lookup that costs a docker exec happens BEFORE the pause: the budget is for the journal wait only
        me, target = self.f.leader('me'), self.f.leader(engine)
        profile = journal_decode.load_profile(self.f.m['me_journal_profile'])
        go = self.f.root / 'state' / 'probe' / Path(hold['go']).relative_to('/data')
        go.parent.mkdir(parents=True, exist_ok=True)
        window = {'hold': hold['hold'], 'order': order, 'held': False, 'me_leader': me, 'kill_target': target}
        killed, seen = None, None
        paused_ns = time.time_ns()
        pauses = {b: self.pause(b, WINDOW_PAUSE_BUDGET_S) for b in BRIDGES}
        go.write_text('go\n')
        try:
            if marker is not None:
                name, where = marker
                try:
                    sent = self.wait_marker(name, WINDOW_PAUSE_BUDGET_S, where=where)
                except Inconclusive as error:   # A window not held is a setup FAIL, not an INCONCLUSIVE
                    window['why'] = str(error)
                    me = None
                else:
                    order = window['order'] = sent.get('order')
                    predicate = lambda events: any(e['type'] == 'outcome' and e['order'] == order and e['kind'] == 2 for e in events)
            while (time.time_ns() - paused_ns) / 1e9 < WINDOW_PAUSE_BUDGET_S and me is not None and target is not None:
                events = journal_decode.decode_dump(self.f.journal_dump(me), profile)
                if predicate(events):
                    seen = [e.get('journal_seq') for e in events][-1]
                    break
            if seen is not None:
                killed = self.kill(target, leader_of_engine=engine, wait=False)   # the election is observed after the thaw
                window.update(held=True, killed=target, journal={'last_journal_seq': seen, 'member': me},
                              killed_after_s=round((time.time_ns() - paused_ns) / 1e9, 3))
        finally:
            thawed = time.time_ns()
            for b in BRIDGES:
                self.f.unpause(b)
            window['pause_s'] = round((thawed - paused_ns) / 1e9, 3)
        if killed is not None:
            self.observe_election(killed, engine)
            if engine == 'me':
                # the old term journaled through ``seen`` (the dump read just before the kill): the new term starts after it
                self.capture_ordering_exception(killed['target'], [None if f'me{i}' == killed['target'] else seen + 1
                                                                   for i in range(3)])
        self.await_branches(pauses, before, thawed)
        if not window['held']:
            self.extra.setdefault('setup_failures', []).append(f'window {hold["hold"]} not held within {WINDOW_PAUSE_BUDGET_S} s')
        return window

    # ---------------------------------------------------------------- after the load

    def post_load(self):
        """Engine members killed during the load are restarted after it (late arrivals), then the resolution gate
        opens: the re-send pass runs only after every heal was observed."""
        bound = story_seconds(self.spec['story']) + 4 * 30 + 120 + story_extra_s(self.red)
        deadline = time.monotonic() + bound
        while time.monotonic() < deadline:
            if self.story_paths['exit'].exists() or any(m.get('marker') == 'resolve_gate_wait' for m in self.markers()):
                break
            self.watch_bridges()     # RED-2's "throughout" covers the load itself, not only after it
            self.sleep(0.5)
        for row in self.ledger.open_rows():
            if row['kind'] == 'kill' and row['target'][:2] in {'ae', 'me'}:
                self.restart(row)
            elif row['kind'] == 'exec_kill' and row['target'][:2] in {'ae', 'me'}:     # enginedriverkill: the ME leader
                entry = next(k for k in self.kills if k['row'] == row['row'])
                self.restart_driver_row(row, entry)
        gate = self.f.root / 'state' / 'probe' / getattr(self, 'resolve_name', 'resolve.go')
        gate.write_text('go\n')

    def wait_story(self):
        deadline = time.monotonic() + 120 + story_extra_s(self.red)
        while not self.story_paths['exit'].exists():
            if time.monotonic() > deadline:
                raise Inconclusive('story JVM did not exit within 120 s of the resolution gate')
            self.watch_bridges()
            self.sleep(0.5)
        self.story_exit_ns = time.time_ns()
        self.watch_bridges()     # one row after the story's exit, so the watched span covers it
        code = int(self.story_paths['exit'].read_text().strip() or -1)
        out = self.story_paths['out'].read_text().splitlines() if self.story_paths['out'].exists() else []
        line = next((l for l in out if l.startswith('STORY ')), None)
        summary = next((j for j in (_json(l) for l in out) if j.get('verb') == 'story'), None)
        if code == 3:
            raise Inconclusive(f'story setup failure (every request UNKNOWN or nothing sent): {line}')
        if code != 0 or line is None:
            raise Inconclusive(f'story exited {code}: {(self.story_paths["err"].read_text()[-300:] if self.story_paths["err"].exists() else "")}')
        lists = {'creates': [], 'amends': [], 'cancels': [], 'unsent': []}
        for l in self.story_paths['log'].read_text().splitlines():
            if l.strip():
                entry = json.loads(l)
                lists[entry['story']].append(entry['row'])
        return {'line': line, 'summary': summary, 'lists': lists}

    def watch_bridges(self):
        """RED-2: the nc bridges must be /ready 200 and bridge_halted 0 over the whole run."""
        if not (self.red and self.red.startswith('red2')) and not os.environ.get('WATCH_BRIDGES'):
            return       # WATCH_BRIDGES=1: a diagnostic watch on a real-bridge run (is the RED-2 503 the control's or the bridge's?)
        row = {'at_ns': time.time_ns()}
        answers = {b: self.f.ready_body(b) for b in BRIDGES}
        scrape = core_scenarios.barrier_scrape(self.f)
        for b in BRIDGES:
            row[b] = {'ready': answers[b][0], 'halted': value(scrape, b, 'bridge_halted')}
            if answers[b][0] != 200:      # The reason of a 503 is evidence (the status alone hid it in the first RED-2 run)
                row[b]['ready_body'] = str(answers[b][1])[:400]
                row[b]['not_ready_bits'] = value(scrape, b, 'bridge_not_ready_bits')
        self.bridge_watch.append(row)

    def pre_barrier(self):
        """Section 4: forwarders Running and /health 200, nothing pending at the AE leader, the ME members converged; a
        60 s bound that falls through and is recorded (only the barrier's own bound gives INCONCLUSIVE). Only the
        forwarders the run still has (a *-n1 control removed one, an N = 1 manifest has none in fwd1); A03 also needs
        core_release_backlog 0 (O-F4)."""
        deadline = time.monotonic() + PRE_BARRIER_S
        status = 'settled'
        forwarders = self.active_forwarders() if hasattr(self, 'removed') else FORWARDERS
        a03 = self.spec.get('faults') == 'a03'
        while True:
            scrape = core_scenarios.barrier_scrape(self.f)
            fwd_ok = all(self.state(f)['Running'] and self.f.http(f, self.f.ready_target(f)[0], '/health')['status'] == 200
                         for f in forwarders)
            ae = leader_of(scrape, 'ae')
            pending = value(scrape, ae, 'core_pending_commands') if ae else None
            backlog = value(scrape, ae, 'core_release_backlog') if ae else None
            seqs = {value(scrape, f'me{i}', 'match_engine_next_journal_seq') for i in range(3)}
            drained = not a03 or backlog == 0
            if fwd_ok and pending == 0 and drained and len(seqs) == 1 and None not in seqs:
                break
            if time.monotonic() > deadline:
                status = 'pending_not_drained' if pending != 0 else 'release_backlog_not_drained' if not drained \
                    else 'me_not_converged' if len(seqs) != 1 or None in seqs else 'forwarders_not_healthy'
                break
            self.watch_bridges()
            self.sleep(1)
        out = {'status': status, 'pending': pending, 'me_next_journal_seq': sorted(s for s in seqs if s is not None)}
        if a03:
            out['release_backlog'] = backlog
        return out

    def wait_tap_end(self):
        tap = self.f.registry['tap']
        end_ns = tap['started_ns'] + tap['duration_ms'] * 1_000_000
        remaining = (end_ns - time.time_ns()) / 1e9 + 3
        if (self.red and self.red.startswith('red2')) or os.environ.get('WATCH_BRIDGES'):
            while remaining > 0:     # RED-2's watch runs until the barrier, not only to the story's end
                self.watch_bridges()
                self.sleep(min(remaining, 2.0))
                remaining = (end_ns - time.time_ns()) / 1e9 + 3
        elif remaining > 0:
            self.sleep(remaining)
        deadline = time.monotonic() + 20
        while True:
            try:
                return self.f.read_tap_summary()
            except Inconclusive:
                if time.monotonic() > deadline:
                    raise
                self.sleep(1)

    def observation(self, story, tap, tap_summary):
        frozen = getattr(self, 'frozen', None)
        obs = core_scenarios.observe(self.f, frozen=frozen) if frozen is not None else core_scenarios.observe(self.f)
        known = set()
        for row in story['lists']['creates']:
            if row['reply'].get('outcome') == 'ACK':
                known.add(row['reply']['order'])
        rows, report = backfill(tap['dispatch'], obs['pending']['entries'], obs['me_journal'], known,
                                obs['core']['pending_dispatch']['head'])
        obs['dispatch_tap'] = tap['dispatch'] + rows
        obs['backfill'] = report
        return obs

    def barrier(self, story, tap, tap_summary):
        """Two observations >= 1 s apart byte-equal on every barrier collection (OM:49, 66-86); 90 s bound."""
        deadline = time.monotonic() + BARRIER_S
        first = self.observation(story, tap, tap_summary)
        names = [n for n in BARRIER_COLLECTIONS if n != 'core_events']   # core_events is the finished tap, equal by construction
        while True:
            self.sleep(1)
            second = self.observation(story, tap, tap_summary)
            if all(fingerprint(first[n]) == fingerprint(second[n]) for n in names):
                return first, second
            if time.monotonic() > deadline:
                raise Inconclusive('barrier did not settle: two observations 1 s apart differ for 90 s')
            first = second

    def build_sample(self, story, tap, tap_summary, second, pre):
        f = self.f
        lists = story['lists']
        sample = {'version': 'core-sample-v2', 'markets': {str(m): {'base': m, 'quote': 0} for m in range(1, 6)},
                  'risk': f.registry['risk'], 'genesis': f.registry['genesis_snapshot'], 'counters': second['counters'],
                  'funding': [{k: v for k, v in r.items() if k != 'reply'} for r in f.registry['funding']],
                  'creates': lists['creates'] + list(getattr(self, 'extra_creates', [])), 'amends': lists['amends'],
                  'cancels': lists['cancels'],
                  'core_events': tap['order_event'], 'admission': tap['admission'], 'dispatch_tap': second['dispatch_tap'],
                  **{k: second[k] for k in ['core', 'me_journal', 'me_journal_seq', 'me_open_legs', 'money_journal',
                                            'money_journal_legs']},
                  'faults': {'settle_fault': max(g['core_settle_faults_total'] for g in second['gauges'].values()),
                             'settle_rejected': max(g['core_settle_rejects_total'] for g in second['gauges'].values()),
                             'order_fault': len(tap['order_fault']),
                             'quarantined': sum(1 for e in tap['order_event'] if e['kind'] == 'QUARANTINED')},
                  'declared': declared_block(self.ledger, int(f.genesis_id(f.life('core') if hasattr(f, 'life') else 1), 16),
                                             self.ordering_exception if self.spec.get('ordering_exception') else None,
                                             **declared_for(self.name, self.variant, getattr(self, 'life_no', 1))),
                  'tap_continuity': {'transitions': tap_summary['transitions'], 'summary': tap_summary['summary'],
                                     'line': tap_summary['line'], 'backfill': second['backfill']},
                  'story': {'line': story['line'], 'summary': story['summary'], 'unsent': lists['unsent']},
                  'pre_barrier': pre, 'fault_rows': self.ledger.rows}
        return sample

    def seal(self, sample, first, second):
        observations = []
        for obs in (first, second):
            view = dict(sample, **{k: obs[k] for k in ['core', 'me_journal', 'me_open_legs', 'money_journal',
                                                       'money_journal_legs', 'dispatch_tap']})
            observations.append({name + '_digest': fingerprint(view[name]) for name in BARRIER_COLLECTIONS})
        sample['barrier'] = {'input_closed': True, 'samples': observations}
        return sample

    def witness(self, sample, after):
        model = Model(sample)
        try:
            counts = lifecycle_counts(sample)
        except (Inconclusive, Violation, KeyError) as error:
            counts = {'error': str(error)}
        positions = {}

        def commit_of(role):
            status, body = self.f.ready_body(role)
            match = re.search(r'commit=(\d+)', body or '')
            return int(match.group(1)) if status == 200 and match else None

        leader_now = leader_of(after, 'ae')
        before = commit_of(leader_now) if leader_now else None
        for i in range(3):
            value_ = commit_of(f'ae{i}')
            if value_ is not None:
                positions[f'ae{i}'] = value_
        after_leader = commit_of(leader_now) if leader_now else None
        window = [before, after_leader] if before is not None and after_leader is not None else None
        return {'ledger': self.ledger.rows, 'snaps': self.snaps, 'expect_cycles': self.spec['cycles'],
                'restarted': sorted(self.restarted), 'released_repeats': len(model.released_repeats),
                'released_after_thaw': released_after_thaw(model, self.ledger.rows),
                'fwd0_late_copies_after_thaw': late_copies_after_thaw(model, self.ledger.rows),
                'ae_leader_after': leader_of(after, 'ae'), 'partition': self.partition, 'windows': self.windows,
                'window_closures': window_closures(sample, self.windows), 'lifecycle_counts': counts,
                'ae_commit_positions': positions, 'ae_commit_leader_window': window}

    def story_args(self):
        story = self.spec['story']
        if story['script'] == 'a03-fill':        # Phases moved by the fixture's signal files, no seconds=
            return {'script': 'a03-fill', 'seed': self.seed, 'users': ','.join(map(str, story['users'])), 'rate': story['rate'],
                    'fill_s': story['fill_s'], 'reopen_s': story['reopen_s'], 'marker_timeout_s': story['marker_timeout_s'],
                    'signal_dir': '/data/' + A03_SIGNALS}
        users = self.spec['life2_users'] if getattr(self, 'life_no', 1) == 2 else story['users']
        kv = {'script': story['script'], 'seed': self.seed, 'seconds': story['seconds'], 'rate': story['rate'],
              'users': ','.join(map(str, users)), 'resolve_gate': '/data/' + getattr(self, 'resolve_name', 'resolve.go'),
              'resolve_gate_ms': 180_000}
        if story.get('ioc_burst_on'):
            kv['ioc_burst_on'] = story['ioc_burst_on']
        if story.get('hold'):
            kv.update(hold=story['hold'], gate_dir='/data/gates', hold_ms=120_000)
        if self.variant.get('without'):
            kv['without'] = self.variant['without']
        return kv

    def run(self):
        f = self.f
        spec = self.spec
        if spec.get('schedule_v4'):
            return self.run_schedule()
        if spec.get('netfilter') and not f.m.get('netfilter_helper'):
            raise Inconclusive('partition needs the hash-pinned netfilter_helper in the manifest')
        if self.red == 'red1':
            # The nc forwarders may answer /ready 503 STALLED; their liveness precondition is Running + /health 200
            self.extra['readiness'] = {fwd: '/health' for fwd in FORWARDERS}
            f.readiness_override = dict(self.extra['readiness'])
        f.start(plan_for(spec, self.seed, story_extra_s(self.red)))
        self.snap('before')
        self.story_paths = f.start_story(self.story_args())
        self.t0 = self.wait_marker('load_started', 60)['at_ns']
        getattr(self, 'faults_' + spec['faults'])()
        self.post_load()
        story = self.wait_story()
        pre = self.pre_barrier()
        tap_summary = self.wait_tap_end()
        tap = self.tap_rows()
        first, second = self.barrier(story, tap, tap_summary)
        after = self.snap('after')
        sample = self.seal(self.build_sample(story, tap, tap_summary, second, pre), first, second)
        money, order = core_oracle.judge(sample), order_oracle.judge(sample)
        w = self.witness(sample, after)
        lines = {name: LINES[name](w) for name in spec['lines'] + ['fault_cycles']}
        rows = of_rows(after, sample)
        result = self.decide(money, order, lines, rows, sample, after)
        self.write_evidence(sample, money, order, lines, rows, w, story, tap_summary, result)
        return result

    def decide(self, money, order, lines, rows, sample, after):
        setup = self.extra.get('setup_failures', [])
        base = {'drill': self.name, 'variant': self.variant, 'red': self.red,
                'oracle_status': {'money': money['status'], 'order': order['status']},
                'lines': {k: v['holds'] for k, v in lines.items()}, 'of_rows': {k: v['holds'] for k, v in rows.items()},
                'pre_barrier': sample['pre_barrier'], 'fault_open': sample['declared']['fault_open'],
                'driver': {s: (self.f.m['artifacts'].get(self.f.m['slot_artifacts'][s]) or {}).get('driver')
                           for s in FORWARDERS + BRIDGES if self.f.m['slot_artifacts'].get(s)},
                'o9': order.get('rules', {}).get('O9', {})}
        if self.red in ('red-a03', 'red-a04'):
            v = red_verdict(self.red, money, order, self.schedule_red_preconditions(sample, after))
            base['preconditions'] = v.get('preconditions')
        elif self.red:
            pre = {'settle_rows': any(r['kind'] == 'settle' for r in sample['money_journal'])}
            if self.red == 'red1':
                for fwd in FORWARDERS:
                    pre[f'{fwd}_running_health_200'] = self.state(fwd)['Running'] and \
                        self.f.http(fwd, self.f.ready_target(fwd)[0], '/health')['status'] == 200
            else:
                span = watch_span(self.bridge_watch, getattr(self, 't0', None), getattr(self, 'story_exit_ns', None))
                base['bridge_watch_span'] = span
                pre['bridges_ready_and_not_halted_throughout'] = bridges_ready_throughout(self.bridge_watch) \
                    and all(value(after, b, 'bridge_halted') == 0 for b in BRIDGES)
                base['bridge_ready_transients'] = ready_transients(self.bridge_watch)
                pre['bridge_watch_covers_the_story'] = span['covers_the_story']
            v = red_verdict('red1' if self.red == 'red1' else 'red2', money, order, pre)
            if REDS[self.red].get('data_point'):
                v = {'status': 'PASS', 'red': 'DATA_POINT', 'reasons': ['negctl data point: ' + '; '.join(v['reasons'])],
                     'halts': not pre['bridges_ready_and_not_halted_throughout'], 'judged_as_red2': v}
            base['preconditions'] = pre
        elif self.variant.get('control'):
            v = control_verdict(money, order, lines, CONTROLS[self.variant['control']][2])
        else:
            v = verdict(money, order, lines, rows, setup, sample['declared']['fault_open'])
        if self.spec.get('schedule_v4'):
            base['settings'] = dict(SETTINGS)
            base['slot_override'] = dict(self.f.registry.get('slot_override') or {})
            if getattr(self, 'sampler_errors', None):
                base['sampler_errors'] = self.sampler_errors[:10]
            v = with_watcher_errors(v, getattr(self, 'watcher_errors', None))
        return dict(base, **v)

    def schedule_red_preconditions(self, sample, after):
        """Both nc forwarders Running and /health 200, the ME ledger still >= 60 % of capacity (the drain did not
        happen). 8.2: both nc bridges Running and /health answering, never halted, skipping (delta >= 1 each), nothing
        refused, no order fault, the core not halted."""
        f = self.f
        if self.red == 'red-a03':
            pre = {f'{fwd}_running_health_200': self.state(fwd)['Running'] and self.health_of(fwd)[0] == 200 for fwd in FORWARDERS}
            me = leader_of(after, 'me')
            ledger = value(after, me, 'match_command_ledger_size') if me else None
            capacity = self.variant.get('ledger_capacity') or self.spec.get('ledger_capacity')
            pre['ledger_still_full'] = ledger is not None and ledger >= 0.6 * capacity
            return pre
        w = self.halt_w
        pre = {f'{b}_running_health': self.state(b)['Running'] and self.health_of(b)[0] in (200, 503) for b in BRIDGES}
        pre['bridges_not_halted'] = all(value(after, b, 'bridge_halt_reason') == 0 for b in BRIDGES)
        for b in BRIDGES:
            pre[f'{b}_skipped'] = (w['skipped_delta'].get(b) or 0) >= 1
        pre['settle_rejected_0'] = sample['faults']['settle_rejected'] == 0
        pre['order_fault_0'] = sample['faults']['order_fault'] == 0
        pre['feed_not_halted'] = sample['core'].get('feed_halted') is False
        return pre

    def write_evidence(self, sample, money, order, lines, rows, w, story, tap_summary, result):
        """Section 12: the sealed subset of one run, next to the runner's result.json (secrets never reach these files)."""
        out = self.out
        out.mkdir(parents=True, exist_ok=True)
        redact = getattr(self.f, 'secret_values', [])
        from credentials import redact as scrub

        def put(name, value):
            text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str) + '\n'
            (out / name).write_text(scrub(text, redact))
        put('core-sample.json', sample)
        put('oracle.json', {'money': money, 'order': order})
        put('faults.json', {'ledger': self.ledger.rows, 'fixture': self.f.registry.get('faults', [])})
        put('lines.json', {'lines': lines, 'of_rows': rows, 'result': result})
        put('scrapes.json', self.snaps)
        put('witness.json', {k: v for k, v in w.items() if k not in {'snaps', 'ledger'}})
        put('story-summary.json', {'line': story['line'], 'summary': story['summary']})
        put('tap-summary.json', tap_summary)
        for name, path in (('markers.jsonl', self.story_paths['markers']), ('story.jsonl', self.story_paths['log']),
                           ('tap.jsonl', Path(self.f.registry['tap']['path']))):
            if path.exists():
                put(name, path.read_text())
        if self.bridge_watch:
            put('bridge-watch.json', self.bridge_watch)


TRANSIENT_503 = 'no_source_attached'


def ready_transients(rows):
    """Every /ready answer that was not 200 in the watch: (row index, bridge, status, body). Evidence."""
    return [(i, b, row[b]['ready'], (row[b].get('ready_body') or '').strip()) for i, row in enumerate(rows)
            for b in BRIDGES if row[b]['ready'] != 200]


def bridges_ready_throughout(rows):
    """"/ready 200 and bridge_halted 0 over the whole run", as measured on the real binary: the
    production ct-bridge itself answers 503 "not ready: no_source_attached" for single watch rows while it re-attaches an
    ME journal source (3 of 76 rows on a GREEN lostack run). The precondition keeps its point, that the nc bridge never
    halted and never stayed down: halted must be 0 in every row, and a 503 counts only when its reason is
    no_source_attached and the same bridge answers 200 on the next row (never two rows running). Any other 503 body, an
    unreadable body or a second consecutive 503 fails it."""
    if not rows:
        return False
    for b in BRIDGES:
        previous = False
        for row in rows:
            r = row[b]
            if r['halted'] != 0:
                return False
            if r['ready'] == 200:
                previous = False
            elif r['ready'] == 503 and TRANSIENT_503 in (r.get('ready_body') or '') and not previous:
                previous = True
            else:
                return False
    return True


def watch_span(rows, t0_ns, story_exit_ns, start_slack_s=WATCH_START_SLACK_S, max_gap_s=WATCH_MAX_GAP_S):
    """The span the RED-2 bridge watch covered. It covers the story when its first row is within
    ``start_slack_s`` of the load start, a row exists at or after the story's exit, and no two rows are further apart
    than ``max_gap_s`` (a halt that heals between two distant rows would not be seen)."""
    at = [r['at_ns'] for r in rows]
    gaps = [(b - a) / 1e9 for a, b in zip(at, at[1:])]
    covers = bool(at) and t0_ns is not None and story_exit_ns is not None and at[0] <= t0_ns + start_slack_s * 1e9 \
        and at[-1] >= story_exit_ns and all(g <= max_gap_s for g in gaps)
    return {'rows': len(at), 'first_at_ns': at[0] if at else None, 'last_at_ns': at[-1] if at else None,
            't0_ns': t0_ns, 'story_exit_ns': story_exit_ns, 'max_gap_s': round(max(gaps), 3) if gaps else None,
            'covers_the_story': covers}


def _json(line):
    try:
        return json.loads(line) if line.startswith('{') else {}
    except ValueError:
        return {}


def _t(sample, edge):
    return sample.get(edge, sample.get('t'))


def _stalled_seq(samples):
    """The ME seq of the last read taken while the drop was in place (None without such a read)."""
    drops = [s for s in samples if s.get('phase') in ('drop', 'add') and s['me_seq'] is not None]
    return drops[-1]['me_seq'] if drops else None


def me_stall(samples, upper=False):
    """Partition phase 1: the ME first-apply gap (s) the reads PROVE, a lower bound: from the end
    (t1) of the first read at a stalled seq to the start (t0) of the last read at it. ``upper=True`` gives the outer
    bracket instead: from the start of the read before the stand-still to the end of the first read that saw the seq
    move (not a proof, kept for the record). A stand-still counts only when at least two reads saw the same seq, the
    core moved meanwhile (a forwarder core head or the AE leader's pending-command gauge rose), and a later read saw
    the seq move again; reads that end inside the stand-still (the heal never seen) count nothing. Times: ``t0``/``t1``
    (before/after the read) or ``t`` for both."""
    if not samples:
        return None
    best, i, n = 0.0, 0, len(samples)
    while i < n:
        if samples[i]['me_seq'] is None:
            i += 1
            continue
        j = i
        while j + 1 < n and samples[j + 1]['me_seq'] == samples[i]['me_seq']:
            j += 1
        heads = [s['core_head'] for s in samples[i:j + 1] if s.get('core_head') is not None]
        pending = [s['core_pending'] for s in samples[i:j + 1] if s.get('core_pending') is not None]
        advanced = j + 1 < n and samples[j + 1]['me_seq'] is not None
        # the core moved when a counter ROSE above its first value at any read of the stand-still; the pending gauge drops back
        # to its floor when the heal clears it (f-s15-partition-3: 2, 66 ... 396, 2), so first against last would miss it
        core_moved = len(heads) >= 2 and max(heads) > heads[0] or len(pending) >= 2 and max(pending) > pending[0]
        if j > i and advanced and core_moved:
            if upper:
                start = _t(samples[i - 1], 't0') if i > 0 else _t(samples[i], 't0')
                best = max(best, _t(samples[j + 1], 't1') - start)
            else:
                best = max(best, _t(samples[j], 't0') - _t(samples[i], 't1'))
        i = j + 1
    return round(best, 3)


def held_order(hold):
    """Review F6: the order a hold holds, from its hold_ready marker (CoreProbe names it; no tap heuristic)."""
    order = hold.get('order')
    if not isinstance(order, int) or isinstance(order, bool) or order <= 0:
        raise Inconclusive(f'hold_ready {hold.get("hold")} names no held order: {hold}')
    return order


def iceberg_slice_journaled(events, parent):
    """Window 1 predicate: the ME journaled slice 1's exhausting trade and its terminal (records 1 and 2)."""
    filled = sum(e['quantity'] for e in events if e['type'] == 'trade' and parent in (e['maker_order'], e['taker_order']))
    terminal = any(e['type'] == 'terminal' and e['order'] == parent for e in events)
    return filled >= ICEBERG_DISPLAY and terminal


def scenario(fixture, scenario_name, out_dir):
    """runner.py entry: ``core-drill-<drill>``, ``core-control-<control>``, ``core-red-<1|2|2-negctl>``."""
    core_contracts.check_build_b(fixture.m, scenario_name)      # Build B is real, a RED's _b is an nc_ target
    if scenario_name.startswith('core-drill-'):
        name, variant, red = scenario_name[len('core-drill-'):], {}, None
    elif scenario_name == 'core-control-edk-cnctimeout':
        return run_cnc_timeout(fixture, Path(out_dir) / 'drill')       # its own boot
    elif scenario_name.startswith('core-control-'):
        control = scenario_name[len('core-control-'):]
        if control not in CONTROLS:
            raise Inconclusive('unknown control: ' + control)
        name, variant, _ = CONTROLS[control]
        variant = dict(variant, control=control)
        red = None
    elif scenario_name.startswith('core-red-'):
        suffix = scenario_name[len('core-red-'):]
        red = 'red' + suffix if 'red' + suffix in REDS else 'red-' + suffix      # red1/red2, red-a03/red-a04
        if red not in REDS:
            raise Inconclusive('unknown RED: ' + red)
        spec = REDS[red]
        for slot in spec['slots']:
            if fixture.m['slot_artifacts'].get(slot) != spec['artifact'] or not fixture.m['artifacts'].get(spec['artifact']):
                raise Inconclusive(f'{red} needs the negative build {spec["artifact"]} staged in {slot}')
        name, variant = spec['drill'], {}
    else:
        raise Inconclusive('not a drill scenario: ' + scenario_name)
    if name not in DRILLS:
        raise Inconclusive('scenario is not implemented and cannot pass: ' + scenario_name)
    if not red:
        # A03 phase 1 runs ct_forwarder_nc_norelease in both forwarder slots, on a manifest of an A03 kind
        # (base or cut) that declares that swap and nothing more
        a03 = name == 'a03-lifetime' and core_contracts.a03_phase1_declared(fixture.m)
        for slot in FORWARDERS + BRIDGES:
            artifact = fixture.m['slot_artifacts'].get(slot)
            if artifact in {'forwarder_b', 'bridge_b'} and not (a03 and slot in FORWARDERS and artifact == 'forwarder_b'):
                raise Inconclusive(f'{slot} stages {artifact}: GREEN drills run the real binaries only')
    run = DrillRun(fixture, name, Path(out_dir) / 'drill', variant=variant, red=red)
    result = run.run()
    status = result['status']
    return dict(result, status=status, assertions=len(result['lines']) + len(result['of_rows']) + 2, processed=1, skipped=0,
                child_exit_codes=[0], scope=('core-topology drill on fixture v4; GREEN needs 3/3'
                                             if DRILLS[name].get('schedule_v4') else
                                             'core-topology drill on fixture v3; GREEN needs 3/3'))


CNC_WAIT_LINE = 'Driver mode EXTERNAL: connecting to media driver'   # me/as AeronCluster.java, right before awaitExternalDriver


def cnc_exit_timing(f, cid, state):
    """The exit time of a CnC-timeout member from the engine's own clock origin. Docker's FinishedAt minus the
    docker timestamp of the engine's CNC_WAIT_LINE (the driver wait's start: the 30 s TRANSPORT_EXTERNAL_DRIVER_TIMEOUT_MS
    counts from there); without that line, minus StartedAt (the process start, the wrapper execs java), said so."""
    finished = _iso_ns(state['FinishedAt'])
    logs = f.command(['docker', 'logs', '--timestamps', cid], check=False)
    for line in ((logs.stdout or '') + '\n' + (logs.stderr or '')).splitlines():
        stamp, _, text = line.partition(' ')
        if CNC_WAIT_LINE in text:
            try:
                origin = _iso_ns(stamp)
            except ValueError:
                continue
            return {'exit_after_s': round((finished - origin) / 1e9, 3), 'measured_from': 'driver_wait_log'}
    started = state.get('StartedAt')
    if not started:
        return {'exit_after_s': None, 'measured_from': None}
    return {'exit_after_s': round((finished - _iso_ns(started)) / 1e9, 3), 'measured_from': 'process_start'}


def run_cnc_timeout(fixture, out_dir):
    """Control edk-cnctimeout (cnc_timeout_loud; only on s16-ctl-edk-cnctimeout.json with ENGINE_DRIVER_SKIP=1):
    its own boot, since start() waits /ready on all six members. ae0 and me0 start java with no driver; each must exit
    non-zero within CNC_TIMEOUT_BOUND_S with no /ready 200 in between (judged on a build with the polite-stop fix)."""
    f = fixture
    members = tuple(getattr(f, 'engine_driver_skip', ()) or ())
    if not members:
        raise Inconclusive('edk-cnctimeout needs ENGINE_DRIVER_SKIP=1 on its own manifest')
    f.check_image(); f.stage_artifacts(); f.start_network()
    f.spawn('probe', f.probe_command())
    spawned = {}
    for engine in ('ae', 'me'):
        for i in range(3):
            f.spawn(f'{engine}{i}', f.engine_command(engine, i), f.engine_env(engine, i))
            spawned[f'{engine}{i}'] = time.time()
    bound = SETTINGS['CNC_TIMEOUT_BOUND_S']
    watch = {m: {'exit_code': None, 'exit_after_s': None, 'ready_200_seen': False, 'ready_answers': []} for m in members}
    deadline = time.time() + bound + 15
    while time.time() < deadline and any(v['exit_code'] is None for v in watch.values()):
        for m, v in watch.items():
            if v['exit_code'] is not None:
                continue
            cid = f.registry['containers'][m]
            state = f.inspect('container', cid)['State']
            if not state['Running']:
                v['exit_code'] = state['ExitCode']
                v['exit_after_spawn_s'] = round(time.time() - spawned[m], 3)     # the spawn-relative measure, evidence only
                v.update(cnc_exit_timing(f, cid, state))
                continue
            status, _ = f.ready_body(m)
            v['ready_answers'].append(status)
            v['ready_200_seen'] = v['ready_200_seen'] or status == 200
        f.sleep(0.5)
    w = {'cnc': {m: {k: v.get(k) for k in ('exit_code', 'exit_after_s', 'measured_from', 'ready_200_seen')}
                 for m, v in watch.items()}}
    line = line_cnc_timeout_loud(w)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'cnc-timeout.json').write_text(json.dumps({'watch': watch, 'line': line, 'settings': SETTINGS}, indent=1) + '\n')
    status = 'PASS' if line['holds'] else 'FAIL'
    return {'status': status, 'drill': 'c13-enginedriverkill', 'variant': {'control': 'edk-cnctimeout'}, 'red': None,
            'lines': {'cnc_timeout_loud': line['holds']}, 'detail': line['detail'], 'settings': dict(SETTINGS),
            'reasons': [] if line['holds'] else [f'cnc_timeout_loud does not hold: {line["detail"]}'],
            'assertions': 1, 'processed': 1, 'skipped': 0, 'child_exit_codes': [0],
            'scope': 'control edk-cnctimeout: the measurement of the CnC-timeout exit'}
