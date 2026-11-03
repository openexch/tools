# SPDX-License-Identifier: Apache-2.0
"""RC2 S15 T2 drills A01 + A02 on fixture v3 (contract sections 4, 5.7, 6.1, 7, 8, 9, 12).

One fresh fixture per run. Every drill: genesis 5.3 (``CoreFixture.start(plan)``), the tap for the whole run, the seeded
story (``CoreProbe story``), the fault schedule of section 9, the observed heals (5.5, C3), the UNKNOWN resolution pass
(6.1, gated on the heals), the pre-barrier wait (section 4, falls through and is recorded), the two-sample barrier,
backfill of the tap (5.7 rule 2), the sample with its declared block (7), both oracles, the non-vacuity lines (8.4) and
the O-F rows (section 2). PASS only when both oracles PASS and every line and row holds (section 9 "Common").

Verdicts (C8): FAIL > INCONCLUSIVE > PASS. A product FAIL, a non-vacuity line that does not hold or a lifecycle-faults
window that was not held is FAIL; a fault whose heal was never observed leaves ``declared.fault_open`` true, which the
oracles answer INCONCLUSIVE (R1), so the drill can never PASS on it (C4: ``test_fault_open_resets_twice`` and its sibling).

The pure parts (the ledger, the backfill, the lines, the verdicts, the declared block) take recorded witnesses and are
unit tested on recorded and synthesized samples (``test_core_drills.py``); ``DrillRun`` drives a ``CoreFixture``.
"""
import json
import os
from pathlib import Path
import re
import time

from contracts import FP, Inconclusive, Violation, fingerprint
import core_oracle
import core_scenarios
import journal_decode
import order_oracle
from oracle_model import BARRIER_COLLECTIONS, RELEASE_KIND, Model, integer, seq_gaps

A01_USERS = list(range(73001, 73041))         # A7: 256 retained requests per user per 15 min; a01 at 100/s needs >= 29
A02_USERS = [74001, 74002, 74003, 74004]
BRIDGES, FORWARDERS = ('bridge0', 'bridge1'), ('fwd0', 'fwd1')
DRIVER_TIMEOUT_S = 5.0                        # FWD_DRIVER_TIMEOUT_MS / BRIDGE_DRIVER_TIMEOUT_MS = 5000 (D-S15-11)
EXIT70_BOUND_S = DRIVER_TIMEOUT_S + 2         # 8.4: exit 70 within FWD_DRIVER_TIMEOUT_MS + 2 s
SESSION_TIMEOUT_S = 10.0                      # AEC:135-141, MEC:149-155
NO_LOSS_AFTER_S = SESSION_TIMEOUT_S + 2       # a thawed process with no exit and no reconnect by then kept its sessions
HEAL_BOUND_S = 60                             # section 4
ELECTION_BOUND_S = 30                         # W0 answer 2 measured 2.7-2.8 s; the bound only stops a hung wait
PRE_BARRIER_S = 60
# W5 (RED-2): with the outcome records dropped (8.2) no a02 await can complete, so every one of the story's awaits runs its
# full AWAIT_NS (CoreProbe.AWAIT_NS = 30 s, 43 await calls at most). The RED-2 story, its tap and its bounds are sized for that.
RED2_AWAITS = 43
RED2_AWAIT_S = 30
RED2_STORY_EXTRA_S = RED2_AWAITS * RED2_AWAIT_S
BARRIER_S = 90
PARTITION1_DROP_S = 3.0                       # section 9 partition phase 1: both forwarders' ME ingress dropped 3 s
PARTITION1_HEAL_BOUND_S = 30                  # review B1: phase-1 reads continue after the delete until the ME seq moves
PHASE1_CADENCE_S = 0.2
WATCH_START_SLACK_S = 5                       # review F1: the RED-2 bridge watch starts within 5 s of the load start
WATCH_MAX_GAP_S = 10                          # ... and never leaves 10 s between two rows
WINDOW_PAUSE_BUDGET_S = 4.5                   # section 9: lifecycle-faults pauses stay under 5 s (sessions stay open)
GATE_SEQUENCE = [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']]   # 7, W0 answer 4
ME_REFUSALS = ['match_ingress_decode_rejects_total', 'match_ingress_unauthorized_total', 'match_durable_invalid_tif_total',
               'match_durable_invalid_sign_total', 'match_durable_invalid_owner_id_total', 'match_durable_capacity_total']
KIND_NAMES = {0: 'CREATE', 1: 'CANCEL', 2: 'AMEND'}
ICEBERG_DISPLAY = 10 * FP                     # CoreProbe a02 moment 1: ICEBERG qty 30, display 10
# 8.4 / C10 / C4: the second lifecycle-faults window is the amend that follows a partial fill (replace_open:1, "amend up
# after a partial fill"). The contract writes "order 2"; W2 exposes replace_open:1/2/3. Coordinator to confirm.
WINDOW2_HOLD = 'replace_open:1'


def _a01(seconds=60, rate=100):
    return {'script': 'a01-mix', 'seconds': seconds, 'rate': rate, 'users': A01_USERS}


def _a02():
    return {'script': 'a02-lifecycle', 'seconds': 20, 'rate': 40, 'users': A02_USERS}   # about 400 filler orders (6)


# Section 9. ``cycles``: fault rows that must be opened and healed (C4: twice where the contract says so).
DRILLS = {
    'lostack': {'story': _a01(), 'faults': 'lostack', 'cycles': 4, 'lines': ['duplicates_delta', 'bridge_branches']},
    'coreleader': {'story': _a01(), 'faults': 'coreleader', 'cycles': 1, 'lines': ['ae_leader_changed', 'resync_t1_both',
                                                                                    'member_caught_up']},
    'meleader': {'story': _a01(), 'faults': 'meleader', 'cycles': 1, 'lines': ['me_leader_changed', 'resync_t2'],
                 'ordering_exception': True},
    'fwdrestart': {'story': _a01(), 'faults': 'fwdrestart', 'cycles': 2, 'lines': ['fwd_restarts']},
    # FIX-5 (fix round 2): 'released_outcome' is a recorded MEASUREMENT (witness.released_after_thaw), not a line. Measured on
    # f-s15-fwdpause-2: both thaws take branch A (exit 70, restart), the restarted fwd0 re-offers nothing, so 0 RELEASED
    # copies are attributable to fwd0 after a thaw; the RELEASED repeats the run does journal are the adjacent second copies
    # of every command that two active forwarders deliver (also present with no pause). A line that must hold would fail
    # always; one that counts those repeats cannot fail without its fault. PO: 19.1 line 5.
    'fwdpause': {'story': _a01(seconds=75), 'faults': 'fwdpause', 'cycles': 2, 'lines': ['duplicates_delta', 'pause_branches']},
    'partition': {'story': _a01(), 'faults': 'partition', 'cycles': 4, 'lines': ['partition_phase1', 'partition_phase2'],
                  'netfilter': True},
    'driverkill': {'story': _a01(), 'faults': 'driverkill', 'cycles': 2, 'lines': ['driver_kills'], 'external_only': True},
    'lifecycle': {'story': _a02(), 'faults': 'none', 'cycles': 0, 'lines': ['lifecycle_story']},
    'lifecycle-faults': {'story': dict(_a02(), hold=f'slice1_exhausting_fill,{WINDOW2_HOLD}'), 'faults': 'lifecycle_faults',
                         'cycles': 6, 'lines': ['lifecycle_story', 'window_lines'], 'ordering_exception': True},
}
# 8.4: the recorded controls ("both oracles PASS, the named line FAILS"); the variant switches one fault off.
CONTROLS = {
    'lostack-pause3': ('lostack', {'pause_s': 3}, ['bridge_branches']),
    'fwdpause-pause3': ('fwdpause', {'pause_s': 3}, ['pause_branches']),
    'fwdrestart-nokill': ('fwdrestart', {'kill': False}, ['fwd_restarts']),
    'partition-nodrop': ('partition', {'drop': False}, ['partition_phase1', 'partition_phase2']),
    'lifecycle-noiceberg': ('lifecycle', {'without': 'iceberg'}, ['lifecycle_story']),
}
# 8.1 / 8.2: the REDs run an unchanged drill on a manifest that stages the negative build in both slots.
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
    metric = 'assets_cluster_role' if engine == 'ae' else 'match_cluster_role'
    leaders = [f'{engine}{i}' for i in range(3) if value(scrape, f'{engine}{i}', metric) == 2.0]
    return leaders[0] if len(leaders) == 1 else None


# ------------------------------------------------------------------ fault ledger (5.5, C3, C4)


class Ledger:
    """Every deliberate fault is a row; it is closed only by an OBSERVED heal (C3), with the branch actually taken."""

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

    def skip(self, kind, target, why):
        """A control run (8.4) records the fault it did NOT inject; the row is not a fault and never opens."""
        row = {'row': len(self.rows) + 1, 'kind': kind, 'target': target, 'skipped': why, 'opened_ns': None, 'heal': None}
        self.rows.append(row)
        return row

    def faults(self):
        return [r for r in self.rows if 'skipped' not in r]

    def open_rows(self):
        return [r for r in self.faults() if r['heal'] is None]

    def fault_open(self):
        return bool(self.open_rows())


def declared_block(ledger, genesis_id, ordering_exception=None):
    """Section 7: zero faults, no halt, gate sequence and epochs; ``fault_open`` from the ledger, never assumed (R1)."""
    return {'settle_fault': 0, 'settle_rejected': 0, 'order_fault': 0, 'quarantined': 0, 'halt': False,
            'fault_open': ledger.fault_open(), 'forwarder_absent': False, 'gate_sequence': GATE_SEQUENCE,
            'epochs': [genesis_id], 'ordering_exception': ordering_exception}


# ------------------------------------------------------------------ tap backfill (5.7 rule 2)


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


# ------------------------------------------------------------------ non-vacuity lines (8.4), each can fail


def _line(holds, detail):
    return {'holds': bool(holds), 'detail': detail}


def _rows(w, kind=None, target=None):
    return [r for r in w['ledger'] if 'skipped' not in r and (kind is None or r['kind'] == kind)
            and (target is None or r['target'] == target)]


def line_fault_cycles(w):
    """C4: the drill opened exactly its ``cycles`` fault rows. Whether each was healed is ``declared.fault_open``: an
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
    """lostack: each bridge took branch A (exit 70 observed, restart, /ready 200) or B (/health aeConnected false or
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
    """L8 item 4 (review FIX-5): at least one leg-less RELEASED (7) repeat journaled AFTER fwd0's thaw for an order that
    was ORDER-released WHILE fwd0 was paused (the ME journal seq read just before the pause and just after the thaw
    brackets both), and the core's release NOOP counter moved. Repeats from outside the pause window do not count."""
    attributed = w.get('released_after_thaw')
    d = delta(w['snaps']['before'], w['snaps']['after'], w['ae_leader_after'] or 'ae0', 'assets_release_confirm_stale_total')
    n = sum(attributed or [])
    return _line(attributed is not None and n >= 1 and (d or 0) >= 1,
                 f'RELEASED repeats after the thaw of fwd0 for orders released during its pause {attributed} '
                 f'(all RELEASED repeats in the run {w["released_repeats"]}), assets_release_confirm_stale_total delta {d}')


def late_copies_after_thaw(model, ledger_rows):
    """Per pause of fwd0: outcome copies (any result) journaled after the thaw for a command whose FIRST outcome was
    journaled while fwd0 was paused. Only fwd0 can deliver such a copy (fwd1 delivered the first one), so this is the
    count of frames the thawed or restarted fwd0 put on the wire (measurement, FIX-5). None without a bracketed pause."""
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
    """coreleader (section 9, W0 answer 14 substitution): the restarted AE member is /ready 200 and its commit position
    equals the leader's (the member's money journal archive is not readable from the probe)."""
    positions = w.get('ae_commit_positions') or {}
    rows = [r for r in _rows(w, 'kill') if r['target'].startswith('ae')]
    member = rows[0]['target'] if rows else None
    restarted_ready = bool(rows) and (rows[0]['heal'] or {}).get('witness', {}).get('ready') is True
    leader = w.get('ae_leader_after')
    # W5: an idle AE log still grows about 1.3 KB/s (leader heartbeat entries), so three sequential /ready reads never show
    # equal numbers (first run: 12528576, 12529216, 12529984). The leader is read before and after the member: "equal to the
    # leader's" means the member's position lies inside that window. No slack (review FIX-8): every recorded run needed none.
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
    """8.4: ME first-apply gap > 3 s, proven by reads (lower bound, review FIX-4) that cover the heal (review B1)."""
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
    """8.4 lifecycle: the story summary read from the core's own events and the tap (never from the story's claims)."""
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
    """lifecycle-faults (8.4): both windows held (bridges paused < 5 s, the ME journaled the records before the kill,
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


# ------------------------------------------------------------------ O-F rows (section 2) and the verdict


def of_rows(after, sample):
    of1 = {m: {n: value(after, m, n, 0) for n in ME_REFUSALS} for m in ('me0', 'me1', 'me2')}
    ae = leader_of(after, 'ae')
    me = leader_of(after, 'me')
    of4 = {'pending': value(after, ae, 'assets_pending_commands'), 'release_backlog': value(after, ae, 'assets_release_backlog'),
           'core_ledger': value(after, ae, 'assets_me_ledger_size'), 'me_ledger': value(after, me, 'match_command_ledger_size')}
    try:
        gap = Model(sample).tap_closed()
        of5 = {'closed': gap is None, 'open_gap': gap}
    except (Inconclusive, Violation) as error:
        of5 = {'closed': False, 'error': str(error)}
    halted = {b: value(after, b, 'bridge_halted') for b in BRIDGES}
    return {
        'O-F1': {'holds': all(v == 0 for row in of1.values() for v in row.values()), 'detail': of1},
        'O-F4': {'holds': ae is not None and me is not None and of4['pending'] == 0 and of4['release_backlog'] == 0
                 and of4['core_ledger'] is not None and of4['core_ledger'] == of4['me_ledger'], 'detail': of4},
        'O-F5': {'holds': of5['closed'], 'detail': of5, 'inconclusive_when_failing': True},
        'bridges_not_halted': {'holds': all(v == 0 for v in halted.values()), 'detail': halted},
    }


def verdict(money, order, lines, rows, setup_failures=(), fault_open=False):
    """FAIL > INCONCLUSIVE > PASS (C8). A line that does not hold and a window not held are FAIL; an open fault or a tap
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
            # with a fault still open its effect cannot be judged yet: INCONCLUSIVE, the C4 sibling rule
            reasons.append(('INCONCLUSIVE' if fault_open else 'FAIL', f'non-vacuity line {name} does not hold'))
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


def control_verdict(money, order, lines, named):
    """8.4: a control run PASSES as a control when both oracles PASS and every named line FAILS."""
    if money['status'] != 'PASS' or order['status'] != 'PASS':
        return {'status': 'INCONCLUSIVE' if 'FAIL' not in {money['status'], order['status']} else 'FAIL',
                'reasons': [f'control needs both oracles PASS: money {money["status"]}, order {order["status"]}']}
    vacuous = [n for n in named if lines[n]['holds']]
    if vacuous:
        return {'status': 'FAIL', 'reasons': [f'control line {n} held without its fault: the line is vacuous' for n in vacuous]}
    return {'status': 'PASS', 'reasons': [f'line {n} FAILS without its fault, as it must' for n in named]}


def red_verdict(kind, money, order, preconditions):
    """8.1 RED-1: order FAIL O10 with its text, the nc forwarders Running and /health 200 at the barrier.
    8.2 RED-2: M7/M8 PASS with settle rows present AND one of O4/M5/O5/M4 FAIL with its text; the nc bridges never halted
    and /ready 200 throughout. A RED that is GREEN is a BLOCKER (FAIL); a missing precondition is INCONCLUSIVE."""
    missing = [k for k, v in preconditions.items() if not v]
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
    """Wall seconds the story may run beyond its nominal length: the RED-2 builds never confirm an outcome (8.2)."""
    return RED2_STORY_EXTRA_S if red and red.startswith('red2') else 0


def plan_for(spec, seed, extra_s=0):
    story = spec['story']
    tap_s = 60 + story['seconds'] + 30 + 30 + 2 * ELECTION_BOUND_S + PRE_BARRIER_S + 30 + extra_s
    return {'users': story['users'], 'markets': [1, 2, 3, 4, 5], 'funding_for': story['script'], 'seed': seed,
            'risk': {'per_sec': 1000, 'max_open': 5000, 'slippage_bps': 100, 'collar_bps': 5000}, 'tap_ms': tap_s * 1000}


class DrillRun:
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

    # ---------------------------------------------------------------- small helpers

    def cid(self, role):
        return self.f.registry['containers'][role]

    def state(self, role):
        return self.f.inspect('container', self.cid(role))['State']

    def snap(self, label):
        scrape = core_scenarios.barrier_scrape(self.f)
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
        # an engine member is restarted only after the load (C2), so its fault_targets bound covers the whole story
        bound = self.spec['story']['seconds'] + 4 * 30 + 180 if role[:2] in {'ae', 'me'} else HEAL_BOUND_S
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
        """After a thaw, observe which branch each process takes (5.5, 8.4): A = it exits 70 (restart, /ready 200);
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
                if status != 200 or health.get('aeConnected') is False:
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

    # ---------------------------------------------------------------- section 9 schedules

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
        restart_at = max(37, 20 + pause_s + 2)   # C2: the forwarders restart after the bridges resumed (section 9: t=37)
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
        """7 / D9: the window is the ids the new ME term's first T2 resync re-sent: until_seq = the forwarders'
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
                self.ledger.skip('kill', fwd, 'control fwdrestart-nokill (8.4)')
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
            me = self.f.leader('me')     # looked up before the pause; the two seq reads bracket the pause (review FIX-5)
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
                    self.ledger.skip('partition', fwd, 'control partition-nodrop (8.4), phase 1')
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
                self.ledger.skip('partition', fwd, 'control partition-nodrop (8.4), phase 2')
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
        if not full:     # FIX-4: the ME seq alone (one GET) keeps the cadence near 150 ms; the core side every 4th read
            return {'t0': round(t0, 3), 't1': round(time.monotonic() - started, 3), 'phase': phase, 'me_seq': seq,
                    'core_head': None, 'core_pending': None}
        heads = [get(f, self.f.m['ports']['forwarder_http'], 'forwarder_dispatch_seq{point="core_head"}') for f in FORWARDERS]
        # W5: the forwarders' core_head is their own consumption head and freezes with the cut forwarders (first partition
        # run: 2121 for the whole drop). The AE leader's pending-command gauge is the core's side: it rises while the core
        # dispatches and the ME applies nothing.
        ae = getattr(self, 'phase1_ae', None)
        pending = get(ae, self.f.m['ports']['ae_metrics'], 'assets_pending_commands') if ae else None
        return {'t0': round(t0, 3), 't1': round(time.monotonic() - started, 3), 'phase': phase, 'me_seq': seq,
                'core_head': max((h for h in heads if h is not None), default=None), 'core_pending': pending}

    @staticmethod
    def background(fn):
        """Run ``fn`` on a thread and return it (tests replace this with a synchronous stub); the sampler keeps reading
        while a netfilter helper call runs (each costs about 2.5 s, F-S15-36)."""
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
        """Read every PHASE1_CADENCE_S while ``thread`` runs (the review FIX-4 hole: the helper calls took 2 s unread)."""
        while thread.is_alive():
            samples.append(self.phase1_read(me, started, phase, full=len(samples) % 4 == 0))
            self.sleep(self.pace(samples[-1]))
        thread.join()
        if thread.errors:
            raise thread.errors[0]

    def sample_me_progress(self, me, hold_s, add, delete, after_bound_s=PARTITION1_HEAL_BOUND_S):
        """8.4 partition phase 1 witness, sampled from before the add THROUGH the heal (reviews B1, FIX-4): one read
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
        """Section 9 / D-S15-14: two windows held open by pausing both bridges (< 5 s), not by racing a kill."""
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
        ``engine``, thaw both bridges. A window not held within the pause budget is a setup FAIL (8.4)."""
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
                except Inconclusive as error:   # 8.4: a window not held is a setup FAIL, not an INCONCLUSIVE
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
        """Engine members killed during the load are restarted after it (C2: late arrivals), then the resolution gate
        opens: the 6.1 re-send pass runs only after every heal was observed."""
        bound = self.spec['story']['seconds'] + 4 * 30 + 120 + story_extra_s(self.red)
        deadline = time.monotonic() + bound
        while time.monotonic() < deadline:
            if self.story_paths['exit'].exists() or any(m.get('marker') == 'resolve_gate_wait' for m in self.markers()):
                break
            self.watch_bridges()     # review F1: RED-2's "throughout" covers the load itself, not only after it
            self.sleep(0.5)
        for row in self.ledger.open_rows():
            if row['kind'] == 'kill' and row['target'][:2] in {'ae', 'me'}:
                self.restart(row)
        gate = self.f.root / 'state' / 'probe' / 'resolve.go'
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
        """RED-2 (8.2): the nc bridges must be /ready 200 and bridge_halted 0 over the whole run."""
        if not (self.red and self.red.startswith('red2')) and not os.environ.get('S15_WATCH_BRIDGES'):
            return       # S15_WATCH_BRIDGES=1: a diagnostic watch on a real-bridge run (W5: is the RED-2 503 the control's or the bridge's?)
        row = {'at_ns': time.time_ns()}
        answers = {b: self.f.ready_body(b) for b in BRIDGES}
        scrape = core_scenarios.barrier_scrape(self.f)
        for b in BRIDGES:
            row[b] = {'ready': answers[b][0], 'halted': value(scrape, b, 'bridge_halted')}
            if answers[b][0] != 200:      # W5: the reason of a 503 is evidence (the status alone hid it in the first RED-2 run)
                row[b]['ready_body'] = str(answers[b][1])[:400]
                row[b]['not_ready_bits'] = value(scrape, b, 'bridge_not_ready_bits')
        self.bridge_watch.append(row)

    def pre_barrier(self):
        """Section 4: forwarders Running and /health 200, nothing pending at the AE leader, the ME members converged; a
        60 s bound that falls through and is recorded (only the barrier's own bound gives INCONCLUSIVE)."""
        deadline = time.monotonic() + PRE_BARRIER_S
        status = 'settled'
        while True:
            scrape = core_scenarios.barrier_scrape(self.f)
            fwd_ok = all(self.state(f)['Running'] and self.f.http(f, self.f.ready_target(f)[0], '/health')['status'] == 200
                         for f in FORWARDERS)
            ae = leader_of(scrape, 'ae')
            pending = value(scrape, ae, 'assets_pending_commands') if ae else None
            seqs = {value(scrape, f'me{i}', 'match_engine_next_journal_seq') for i in range(3)}
            if fwd_ok and pending == 0 and len(seqs) == 1 and None not in seqs:
                break
            if time.monotonic() > deadline:
                status = 'pending_not_drained' if pending != 0 else 'me_not_converged' if len(seqs) != 1 or None in seqs \
                    else 'forwarders_not_healthy'
                break
            self.watch_bridges()
            self.sleep(1)
        return {'status': status, 'pending': pending, 'me_next_journal_seq': sorted(s for s in seqs if s is not None)}

    def wait_tap_end(self):
        tap = self.f.registry['tap']
        end_ns = tap['started_ns'] + tap['duration_ms'] * 1_000_000
        remaining = (end_ns - time.time_ns()) / 1e9 + 3
        if (self.red and self.red.startswith('red2')) or os.environ.get('S15_WATCH_BRIDGES'):
            while remaining > 0:     # review F1: RED-2's watch runs until the barrier, not only to the story's end
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
        obs = core_scenarios.observe(self.f)
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
                  'creates': lists['creates'], 'amends': lists['amends'], 'cancels': lists['cancels'],
                  'core_events': tap['order_event'], 'admission': tap['admission'], 'dispatch_tap': second['dispatch_tap'],
                  **{k: second[k] for k in ['core', 'me_journal', 'me_journal_seq', 'me_open_legs', 'money_journal',
                                            'money_journal_legs']},
                  'faults': {'settle_fault': max(g['assets_settle_faults_total'] for g in second['gauges'].values()),
                             'settle_rejected': max(g['assets_settle_rejects_total'] for g in second['gauges'].values()),
                             'order_fault': len(tap['order_fault']),
                             'quarantined': sum(1 for e in tap['order_event'] if e['kind'] == 'QUARANTINED')},
                  'declared': declared_block(self.ledger, int(f.genesis_id(), 16),
                                             self.ordering_exception if self.spec.get('ordering_exception') else None),
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
        kv = {'script': story['script'], 'seed': self.seed, 'seconds': story['seconds'], 'rate': story['rate'],
              'users': ','.join(map(str, story['users'])), 'resolve_gate': '/data/resolve.go', 'resolve_gate_ms': 180_000}
        if story.get('hold'):
            kv.update(hold=story['hold'], gate_dir='/data/gates', hold_ms=120_000)
        if self.variant.get('without'):
            kv['without'] = self.variant['without']
        return kv

    def run(self):
        f = self.f
        spec = self.spec
        if spec.get('netfilter') and not f.m.get('netfilter_helper'):
            raise Inconclusive('partition needs the hash-pinned netfilter_helper in the manifest (3.1, A14)')
        if self.red == 'red1':
            # 8.1: the nc forwarders may answer /ready 503 STALLED; their liveness precondition is Running + /health 200
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
        if self.red:
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
                v = {'status': 'PASS', 'red': 'DATA_POINT', 'reasons': ['negctl data point (8.2): ' + '; '.join(v['reasons'])],
                     'halts': not pre['bridges_ready_and_not_halted_throughout'], 'judged_as_red2': v}
            base['preconditions'] = pre
        elif self.variant.get('control'):
            v = control_verdict(money, order, lines, CONTROLS[self.variant['control']][2])
        else:
            v = verdict(money, order, lines, rows, setup, sample['declared']['fault_open'])
        return dict(base, **v)

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
    """Every /ready answer that was not 200 in the watch: (row index, bridge, status, body). W5 evidence."""
    return [(i, b, row[b]['ready'], (row[b].get('ready_body') or '').strip()) for i, row in enumerate(rows)
            for b in BRIDGES if row[b]['ready'] != 200]


def bridges_ready_throughout(rows):
    """8.2 "/ready 200 and bridge_halted 0 over the whole run", as measured on the real binary (W5 finding F-S15-32): the
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
    """Review F1: the span the RED-2 bridge watch covered. It covers the story when its first row is within
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
    """8.4 partition phase 1 (reviews B1, FIX-4): the ME first-apply gap (s) the reads PROVE, a lower bound: from the end
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
    if scenario_name.startswith('core-drill-'):
        name, variant, red = scenario_name[len('core-drill-'):], {}, None
    elif scenario_name.startswith('core-control-'):
        control = scenario_name[len('core-control-'):]
        if control not in CONTROLS:
            raise Inconclusive('unknown control: ' + control)
        name, variant, _ = CONTROLS[control]
        variant = dict(variant, control=control)
        red = None
    elif scenario_name.startswith('core-red-'):
        red = 'red' + scenario_name[len('core-red-'):]
        if red not in REDS:
            raise Inconclusive('unknown RED: ' + red)
        spec = REDS[red]
        for slot in spec['slots']:
            if fixture.m['slot_artifacts'].get(slot) != spec['artifact'] or not fixture.m['artifacts'].get(spec['artifact']):
                raise Inconclusive(f'{red} needs the negative build {spec["artifact"]} staged in {slot} (8.1, 8.2)')
        name, variant = spec['drill'], {}
    else:
        raise Inconclusive('not a drill scenario: ' + scenario_name)
    if name not in DRILLS:
        raise Inconclusive('scenario is not implemented and cannot pass: ' + scenario_name)
    if not red:
        for slot in FORWARDERS + BRIDGES:
            artifact = fixture.m['slot_artifacts'].get(slot)
            if artifact in {'forwarder_b', 'bridge_b'}:
                raise Inconclusive(f'{slot} stages {artifact}: GREEN drills run the real binaries only (8.3)')
    run = DrillRun(fixture, name, Path(out_dir) / 'drill', variant=variant, red=red)
    result = run.run()
    status = result['status']
    return dict(result, status=status, assertions=len(result['lines']) + len(result['of_rows']) + 2, processed=1, skipped=0,
                child_exit_codes=[0], scope='RC2 S15 T2 drill on fixture v3; GREEN needs 3/3 (section 11)')
