# SPDX-License-Identifier: Apache-2.0
"""RC2 S15 W3: oracle rule changes (5.7, 6.1, 7, L8 item 4, F-S15-25) and the drill logic (4, 8, 9), on recorded and
synthesized samples. Each RED names the text the c781b4c rule set gives on the same sample.

"Recorded" here: the S14 clean lifecycle sample (oracle_samples, sealed like a barrier) and the W2 story rows (the
resolved-UNKNOWN shape of evidence/w2/sample-a01-resolved). No drill has run yet (W5/W6), so every non-vacuity line is
proven on witnesses synthesized from those samples (contract 8.4 allows it until W5; the README must say so).
"""
import copy
import json
from pathlib import Path
import time
import types
import unittest
from unittest import mock

import core_drills as cd
import core_oracle
import order_oracle
from contracts import FP, Inconclusive, Violation
from oracle_model import Model, resolve_requests
from oracle_samples import BUYER, SELLER, P, Q, clean_sample, schema4_sample, seal, variant


def judge(sample):
    return core_oracle.judge(sample), order_oracle.judge(sample)


def rule(result, name):
    return result['rules'].get(name, {})


def outcome_index(sample, order, low):
    return next(i for i, e in enumerate(sample['me_journal'])
                if e['type'] == 'outcome' and e['command_id_high'] == order and e['command_id_low'] == low)


def with_ids(sample):
    """Give the request rows story ids, as CoreProbe story writes them (W2)."""
    for n, row in enumerate(sample['creates'] + sample['amends'] + sample['cancels'], start=1):
        row['id'] = n
    return sample


# ------------------------------------------------------------------ 6.1 UNKNOWN resolution


class ResolutionTest(unittest.TestCase):
    def _unknown(self, duplicate):
        """Order 1003's create: the original reply was lost (UNKNOWN); the same-requestId re-send answers."""
        def edit(s):
            with_ids(s)
            original = next(c for c in s['creates'] if c['reply']['order'] == 1003)
            reply = dict(original['reply'], duplicate=duplicate)
            original['reply'] = {'outcome': 'UNKNOWN'}
            original['resolved_by'] = 100
            s['creates'].append(dict(copy.deepcopy(original), id=100, resolves=original['id'], reply=reply))
            del s['creates'][-1]['resolved_by']
        return variant(clean_sample(), edit)

    def test_resolved_unknown_create_is_judged_not_inconclusive(self):
        """RED c781b4c: O1 INCONCLUSIVE "create outcome unknown". After W3 the re-send's fresh ACK is the verdict."""
        money, order = judge(self._unknown(duplicate=False))
        self.assertEqual(order['status'], 'PASS', order)
        self.assertEqual(money['status'], 'PASS', money)

    def test_committed_unknown_create_is_not_a_false_fail(self):
        """The core committed the lost offer: the re-send gets a duplicate ACK naming it; ownership, M4, M5, O1 judge it."""
        money, order = judge(self._unknown(duplicate=True))
        self.assertEqual(order['status'], 'PASS', order)
        self.assertEqual(money['status'], 'PASS', money)
        model = Model(self._unknown(duplicate=True))
        self.assertEqual(model.orders[1003]['reply']['source'], 'replay')

    def test_replayed_create_with_a_gone_hold_block_is_not_a_hold_asset_violation(self):
        """S15 W5: the duplicate ACK of a re-sent UNKNOWN reports the CURRENT hold block, (0, 0) once the hold is gone."""
        def edit(s):
            with_ids(s)
            original = next(c for c in s['creates'] if c['reply']['order'] == 1001)
            reply = dict(original['reply'], duplicate=True, hold_asset=0, hold_amount=0)
            original['reply'] = {'outcome': 'UNKNOWN'}
            original['resolved_by'] = 100
            s['creates'].append(dict(copy.deepcopy(original), id=100, resolves=original['id'], reply=reply))
            del s['creates'][-1]['resolved_by']
        money, order = judge(variant(clean_sample(), edit))
        self.assertEqual(money['rules']['M5']['status'], 'PASS', money['rules']['M5'])

    def test_first_reply_with_the_wrong_hold_asset_still_fails(self):
        def edit(s):
            next(c for c in s['creates'] if c['reply']['order'] == 1001)['reply']['hold_asset'] = 0
        money, _ = judge(variant(clean_sample(), edit))
        self.assertEqual(money['rules']['M5']['status'], 'FAIL', money['rules']['M5'])

    def test_unresolved_committed_create_is_inconclusive_never_fail(self):
        """6.1 rule 4. RED c781b4c: M4 FAIL "hold for order 1003 that no accepted request created" (a false FAIL)."""
        def edit(s):
            with_ids(s)
            next(c for c in s['creates'] if c['reply']['order'] == 1003)['reply'] = {'outcome': 'UNKNOWN'}
        money, order = judge(variant(clean_sample(), edit))
        self.assertNotIn('FAIL', {money['status'], order['status']}, (money, order))
        self.assertIn('unresolved gateway reply (1)', rule(order, 'O1')['detail'])
        self.assertIn('unresolved gateway reply (1)', rule(money, 'M4')['detail'])

    def test_resolution_row_must_name_its_original(self):
        def edit(s):
            with_ids(s)
            s['creates'].append(dict(copy.deepcopy(s['creates'][0]), id=200, resolves=999))
        _, order = judge(variant(clean_sample(), edit))
        self.assertEqual(order['status'], 'INCONCLUSIVE', order)

    def test_w2_recorded_rows_resolve(self):
        """The W2 shape (evidence/w2/sample-a01-resolved): three UNKNOWN originals, two duplicate re-sends, one fresh."""
        rows = [
            {'id': 3, 'request': [1, 3], 'reply': {'outcome': 'UNKNOWN'}, 'resolved_by': 13},
            {'id': 5, 'request': [1, 5], 'reply': {'outcome': 'UNKNOWN'}, 'resolved_by': 14},
            {'id': 6, 'request': [1, 6], 'reply': {'outcome': 'UNKNOWN'}, 'resolved_by': 15},
            {'id': 7, 'request': [1, 7], 'reply': {'outcome': 'ACK', 'order': 1004, 'duplicate': False}},
            {'id': 13, 'request': [1, 3], 'reply': {'outcome': 'ACK', 'order': 1002, 'duplicate': True}, 'resolves': 3},
            {'id': 14, 'request': [1, 5], 'reply': {'outcome': 'ACK', 'order': 1009, 'duplicate': False}, 'resolves': 5},
            {'id': 15, 'request': [1, 6], 'reply': {'outcome': 'ACK', 'order': 1003, 'duplicate': True}, 'resolves': 6},
        ]
        effective, unresolved = resolve_requests(rows)
        self.assertEqual(unresolved, [])
        self.assertEqual([(r['id'], r['reply']['order']) for r in effective], [(3, 1002), (6, 1003), (7, 1004), (14, 1009)])
        self.assertTrue(all(not r['reply']['duplicate'] for r in effective))

    def test_amend_resolved_by_duplicate_counts_as_the_accepted_amend(self):
        """W0 answer 11: amends dedupe by requestId too. RED c781b4c: M5 INCONCLUSIVE "0 accepted amends but 1 AMEND"."""
        def edit(s):
            with_ids(s)
            amend = s['amends'][0]
            reply = dict(amend['reply'], duplicate=True)
            amend['reply'] = {'outcome': 'UNKNOWN'}
            amend['resolved_by'] = 300
            s['amends'].append({k: v for k, v in amend.items() if k != 'resolved_by'} | {'id': 300, 'resolves': amend['id'], 'reply': reply})
        money, order = judge(variant(clean_sample(), edit))
        self.assertEqual((money['status'], order['status']), ('PASS', 'PASS'), (money, order))


# ------------------------------------------------------------------ F-S15-25 and L8 item 4


class KindAndReleaseTest(unittest.TestCase):
    def test_release_id_dispatch_is_not_a_second_dispatch(self):
        """A12 / W0 F-S15-25. RED c781b4c: FAIL "dispatch tap saw command id twice as a new dispatch"."""
        def edit(s):
            create = next(r for r in s['dispatch_tap'] if r['seq'] == 3)
            s['dispatch_tap'].append(dict(create, seq=11, kind='RELEASE_ID'))
            s['core']['pending_dispatch']['head'] = 11
        money, order = judge(variant(clean_sample(), edit))
        self.assertEqual(order['status'], 'PASS', order)
        self.assertEqual(money['status'], 'PASS', money)

    def test_second_release_id_for_one_command_is_still_refused(self):
        def edit(s):
            create = next(r for r in s['dispatch_tap'] if r['seq'] == 3)
            s['dispatch_tap'] += [dict(create, seq=11, kind='RELEASE_ID'), dict(create, seq=12, kind='RELEASE_ID')]
            s['core']['pending_dispatch']['head'] = 12
        self.assertEqual(order_oracle.judge(variant(clean_sample(), edit))['status'], 'FAIL')

    def _released(self, leg=0, release=True):
        def edit(s):
            i = outcome_index(s, 1004, 0)
            if release:
                s['me_journal'].append({'type': 'release', 'journal_seq': None, 'me_epoch': None,
                                        'releases': [{'commandIdHigh': 1004, 'idLowFloor': 0, 'scope': 1, 'result': 0, 'removed': 2}]})
            s['me_journal'].append(dict(s['me_journal'][i], applied_position=88_888, leg=leg, result=7))
            s['counters']['released_late'] = 1      # Table D U1 (OrderEngine.unmatchedV3), not stale
        return variant(clean_sample(), edit)

    def test_o2_released_repeat_creates_nothing(self):
        """L8 item 4. RED c781b4c: O2 FAIL "repeat outcome differs from the first"."""
        sample = self._released()
        order = order_oracle.judge(sample)
        self.assertEqual(order['status'], 'PASS', order)
        self.assertEqual(len(Model(sample).released_repeats), 1)

    def test_released_repeat_with_a_leg_fails(self):
        self.assertEqual(order_oracle.judge(self._released(leg=5999))['status'], 'FAIL')

    def test_released_repeat_without_an_earlier_release_fails(self):
        result = order_oracle.judge(self._released(release=False))
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('without an earlier release', result['error'])


# ------------------------------------------------------------------ 5.7 tap continuity and backfill


def holed(seq):
    """The clean sample with dispatch seq ``seq`` lost by the tap (an AE leader change)."""
    return variant(clean_sample(), lambda s: s.__setitem__('dispatch_tap', [r for r in s['dispatch_tap'] if r['seq'] != seq]))


def backfilled(sample, pending=()):
    known = {c['reply']['order'] for c in sample['creates'] if c['reply'].get('outcome') == 'ACK'}
    rows, report = cd.backfill(sample['dispatch_tap'], list(pending), sample['me_journal'], known,
                               sample['core']['pending_dispatch']['head'])
    clone = copy.deepcopy(sample)
    clone['dispatch_tap'] = clone['dispatch_tap'] + rows
    return seal(clone), report


class TapContinuityTest(unittest.TestCase):
    def test_tap_gap_without_backfill_is_inconclusive_not_fail(self):
        """5.7 rule 3. RED c781b4c: O3 FAIL "ME outcome for command (1004, 5) the core never dispatched"."""
        order = order_oracle.judge(holed(6))
        self.assertEqual(rule(order, 'O3')['status'], 'INCONCLUSIVE', order)
        self.assertIn('tap gap [6, 6] not closed', rule(order, 'O3')['detail'])
        self.assertEqual(rule(order, 'O10')['status'], 'INCONCLUSIVE', order)
        self.assertNotEqual(order['status'], 'FAIL')

    def test_backfill_from_the_me_outcome_closes_the_gap(self):
        sample, report = backfilled(holed(6))
        self.assertEqual(report['gaps'], [[6, 6]])
        row = [r for r in sample['dispatch_tap'] if r.get('source') == 'backfill']
        self.assertEqual([(r['seq'], r['kind'], r['origin']) for r in row], [(None, 'CANCEL', 'me_outcome')])
        money, order = judge(sample)
        self.assertEqual((money['status'], order['status']), ('PASS', 'PASS'), (money, order))

    def test_backfilled_amend_pairs_in_amend_chain_and_o9_skips_it(self):
        """The AMEND of 1003 (seq 4) lost: amend_chain pairs the backfilled row (attempt order), O9 skips seq null."""
        sample, _ = backfilled(holed(4))
        money, order = judge(sample)
        self.assertEqual(rule(money, 'M5')['status'], 'PASS', money)
        self.assertEqual(rule(order, 'O9')['status'], 'PASS', order)
        self.assertEqual(order['status'], 'PASS', order)

    def test_missing_tail_against_the_core_head_is_a_gap(self):
        """A11 / W0 answer 12: the T1 capture went blind as a TAIL and still printed "dense"."""
        sample = variant(clean_sample(), lambda s: s['core']['pending_dispatch'].update(head=12))
        detail = rule(order_oracle.judge(sample), 'O3')['detail']
        self.assertIn('tap gap [11, 12] not closed', detail)

    def test_still_pending_dispatch_is_backfilled_with_its_seq(self):
        sample = holed(6)
        lost = next(r for r in clean_sample()['dispatch_tap'] if r['seq'] == 6)
        filled, _ = backfilled(sample, pending=[lost])
        rows = [r for r in filled['dispatch_tap'] if r.get('source') == 'backfill']
        self.assertEqual([(r['seq'], r['origin']) for r in rows], [(6, 'pending')])
        self.assertIsNone(Model(filled).tap_closed())

    def test_stray_backfill_row_is_inconclusive(self):
        sample = variant(clean_sample(), lambda s: s['dispatch_tap'].append(
            dict(s['dispatch_tap'][0], seq=None, source='backfill', id_low=9 << 2)))
        with self.assertRaisesRegex(Inconclusive, 'backfill rows without a seq'):
            Model(sample).tap_closed()

    def test_no_gap_no_backfill(self):
        rows, report = cd.backfill(clean_sample()['dispatch_tap'], [], clean_sample()['me_journal'], {1003}, 10)
        self.assertEqual((rows, report['gaps']), ([], []))

    def test_release_slots_are_rebuilt_only_with_a_verified_mapping(self):
        def tap_with_release(s):
            create = next(r for r in s['dispatch_tap'] if r['seq'] == 3)
            other = next(r for r in s['dispatch_tap'] if r['seq'] == 1)
            s['dispatch_tap'] += [dict(create, seq=11, kind='RELEASE_ID'), dict(other, seq=12, kind='RELEASE_ID')]
            s['me_journal'].append({'type': 'release', 'releases': [
                {'commandIdHigh': 1003, 'idLowFloor': 0, 'scope': 0, 'result': 0, 'removed': 1},
                {'commandIdHigh': 1001, 'idLowFloor': 0, 'scope': 0, 'result': 0, 'removed': 1}]})
            s['core']['pending_dispatch']['head'] = 12
        sample = variant(clean_sample(), tap_with_release)
        lost = variant(sample, lambda s: s.__setitem__('dispatch_tap', [r for r in s['dispatch_tap'] if r['seq'] != 12]))
        filled, report = backfilled(lost)
        self.assertEqual(report['release_mapping'], 'verified')
        self.assertIsNone(Model(filled).tap_closed())
        # the tap saw a RELEASE_ID that no ME release entry explains: the mapping is unverified, the slot stays open
        bad = variant(lost, lambda s: s['me_journal'][-1]['releases'].__setitem__(0, dict(s['me_journal'][-1]['releases'][0], idLowFloor=4)))
        filled, report = backfilled(bad)
        self.assertEqual(report['release_mapping'], 'unverified')
        self.assertEqual(Model(filled).tap_closed(), [12, 12])

    def test_o5_tap_loss_inside_an_event_window_is_inconclusive(self):
        """5.7 rule 4. RED c781b4c: O5 FAIL "order 1004 left the live set without a terminal event"."""
        sample = variant(clean_sample(), lambda s: s.__setitem__('core_events', [e for e in s['core_events'] if e['seq'] != 4]))
        result = rule(order_oracle.judge(sample), 'O5')
        self.assertEqual(result['status'], 'INCONCLUSIVE', result)
        self.assertIn('tap_loss', result['detail'])

    def test_o5_missing_terminal_outside_every_window_stays_fail(self):
        def edit(s):
            s['core_events'] = [e for e in s['core_events'] if e['seq'] != 4]
            for e in s['core_events']:
                if e['seq'] > 4:
                    e['seq'] -= 1
        result = rule(order_oracle.judge(variant(clean_sample(), edit)), 'O5')
        self.assertEqual(result['status'], 'FAIL', result)

    def test_o5_session_window_after_the_last_event_is_tap_loss(self):
        def edit(s):
            s['core_events'] = [e for e in s['core_events'] if e['seq'] != 9]       # 1001's FILLED is the last event
            s['tap_continuity'] = {'transitions': [{'event': 'new_leader', 'last_event_seq': 8, 'last_dispatch_seq': 10}]}
        result = rule(order_oracle.judge(variant(clean_sample(), edit)), 'O5')
        self.assertEqual(result['status'], 'INCONCLUSIVE', result)


# ------------------------------------------------------------------ 7 ordering exception


class OrderingExceptionTest(unittest.TestCase):
    def _inverted(self, window):
        def edit(s):
            a, b = outcome_index(s, 1006, 0), outcome_index(s, 1005, 1 << 2)
            s['me_journal'][a], s['me_journal'][b] = s['me_journal'][b], s['me_journal'][a]
            for n, event in enumerate(s['me_journal'], start=1):
                event['journal_seq'] = n          # the journal order is journalSeq order: 1006 is now applied at 15
            s['declared']['ordering_exception'] = window
        return variant(schema4_sample(), edit)

    def test_inversion_inside_the_window_is_counted_outside_is_fail(self):
        """F-S15-23 / D9: inside (seq 8 <= until_seq 8, first-applied at journalSeq >= 12) recorded; outside FAIL."""
        inside = rule(order_oracle.judge(self._inverted({'me_term': 2, 'until_seq': 8, 'from_journal_seq': 12})), 'O9')
        self.assertEqual(inside['status'], 'PASS', inside)
        self.assertEqual(inside['o9_exception_inversions'], 1)
        outside = rule(order_oracle.judge(self._inverted({'me_term': 2, 'until_seq': 7})), 'O9')
        self.assertEqual(outside['status'], 'FAIL', outside)
        before = rule(order_oracle.judge(self._inverted({'me_term': 2, 'until_seq': 8, 'from_journal_seq': 20})), 'O9')
        self.assertEqual(before['status'], 'FAIL', before)

    def test_no_window_judges_all(self):
        self.assertEqual(rule(order_oracle.judge(self._inverted(None)), 'O9')['status'], 'FAIL')


# ------------------------------------------------------------------ ledger, declared block, C4


def fwdrestart_witness(second_heal=True):
    ledger = cd.Ledger(clock=iter(range(1, 100)).__next__)
    for fwd in ('fwd0', 'fwd1'):
        row = ledger.open('kill', fwd, {'exit_code': 137})
        if fwd == 'fwd0' or second_heal:
            ledger.heal(row, 'restart', {'ready': True, 'resync_after': 1, 'peer_resync_delta': 0})
    return ledger


def witness(ledger, **kw):
    base = {'ledger': ledger.rows, 'snaps': {'before': {}, 'after': {}}, 'expect_cycles': 2, 'restarted': [],
            'released_repeats': 0, 'ae_leader_after': 'ae0', 'partition': {}, 'windows': {}, 'window_closures': {},
            'lifecycle_counts': {}, 'ae_commit_positions': {}}
    base.update(kw)
    return base


class FaultOpenTest(unittest.TestCase):
    def test_fault_open_resets_twice(self):
        """C4: two kill/restart cycles, each closed by an observed heal: fault_open false, the drill can PASS."""
        ledger = fwdrestart_witness()
        declared = cd.declared_block(ledger, 0x77)
        self.assertIs(declared['fault_open'], False)
        sample = variant(clean_sample(), lambda s: s['declared'].update(fault_open=declared['fault_open']))
        money, order = judge(sample)
        w = witness(ledger)
        lines = {n: cd.LINES[n](w) for n in ('fwd_restarts', 'fault_cycles')}
        self.assertTrue(all(l['holds'] for l in lines.values()), lines)
        v = cd.verdict(money, order, lines, {}, (), declared['fault_open'])
        self.assertEqual(v['status'], 'PASS', v)

    def test_fault_open_second_heal_missing_is_inconclusive_not_pass(self):
        """C4 sibling: the second restart was never observed ready: fault_open true, INCONCLUSIVE, never PASS."""
        ledger = fwdrestart_witness(second_heal=False)
        declared = cd.declared_block(ledger, 0x77)
        self.assertIs(declared['fault_open'], True)
        sample = variant(clean_sample(), lambda s: s['declared'].update(fault_open=True))
        money, order = judge(sample)
        w = witness(ledger)
        lines = {n: cd.LINES[n](w) for n in ('fwd_restarts', 'fault_cycles')}
        v = cd.verdict(money, order, lines, {}, (), declared['fault_open'])
        self.assertEqual(v['status'], 'INCONCLUSIVE', v)

    def test_open_fault_with_pending_work_keeps_o7_o10_inconclusive(self):
        sample = variant(clean_sample(), lambda s: (s['declared'].update(fault_open=True),
                                                     s['core']['pending_dispatch'].update(count=1)))
        order = order_oracle.judge(sample)
        self.assertEqual(rule(order, 'O7')['status'], 'INCONCLUSIVE')

    def test_heal_twice_is_refused_and_skipped_rows_never_open(self):
        ledger = cd.Ledger()
        row = ledger.open('kill', 'fwd0')
        ledger.heal(row, 'restart')
        with self.assertRaises(Violation):
            ledger.heal(row, 'restart')
        ledger.skip('kill', 'fwd1', 'control')
        self.assertFalse(ledger.fault_open())
        self.assertEqual(len(ledger.faults()), 1)

    def test_declared_block_is_section_7(self):
        d = cd.declared_block(cd.Ledger(), 0x77, {'me_term': 2, 'until_seq': 9})
        self.assertEqual(d['gate_sequence'], [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']])
        self.assertEqual(d['epochs'], [0x77])
        self.assertEqual([d[k] for k in ('settle_fault', 'settle_rejected', 'order_fault', 'quarantined')], [0, 0, 0, 0])
        self.assertIs(d['halt'], False)
        self.assertEqual(d['ordering_exception'], {'me_term': 2, 'until_seq': 9})


# ------------------------------------------------------------------ 8.4 non-vacuity lines, each with its control


def scrape(**roles):
    return {role: dict(values) for role, values in roles.items()}


class LinesTest(unittest.TestCase):
    def test_duplicates_delta_and_its_no_fault_control(self):
        dup = 'match_durable_duplicates_suppressed_total'
        before = scrape(me0={dup: 5.0}, me1={dup: 5.0}, me2={dup: 5.0})
        moved = scrape(me0={dup: 9.0}, me1={dup: 9.0}, me2={dup: 9.0})
        self.assertTrue(cd.line_duplicates_delta(witness(cd.Ledger(), snaps={'before': before, 'after': moved}))['holds'])
        self.assertFalse(cd.line_duplicates_delta(witness(cd.Ledger(), snaps={'before': before, 'after': before}))['holds'])

    def _bridges(self, branches):
        ledger = cd.Ledger()
        for bridge, (branch, hw) in zip(cd.BRIDGES, branches):
            ledger.heal(ledger.open('pause', bridge), branch, hw)
        return witness(ledger)

    def test_bridge_branches_and_the_pause3_control(self):
        a = ('A', {'exit_code': 70, 'ready': True})
        b = ('B', {'saw_down': True, 'reconnect_delta': 1, 'ready': True})
        self.assertTrue(cd.line_bridge_branches(self._bridges([a, b]))['holds'])
        none = ('none', {'saw_down': False, 'reconnect_delta': 0, 'ready': True})
        self.assertFalse(cd.line_bridge_branches(self._bridges([a, none]))['holds'])
        self.assertFalse(cd.line_bridge_branches(self._bridges([a, ('B', {'saw_down': False, 'reconnect_delta': 1})]))['holds'])

    def _pauses(self, heals):
        ledger = cd.Ledger()
        for branch, hw in heals:
            row = ledger.open('pause', 'fwd0')
            if branch:
                ledger.heal(row, branch, hw)
        return witness(ledger)

    def test_pause_branches_both_pauses(self):
        a = ('A', {'exit_code': 70, 'exit_after_thaw_s': 0.5, 'resync_delta': 1})
        b = ('B', {'reconnect_delta_by_cluster': {'core': 1, 'me': 1}, 'resync_delta': 2})
        self.assertTrue(cd.line_pause_branches(self._pauses([a, b]))['holds'])
        late = ('A', {'exit_code': 70, 'exit_after_thaw_s': 9.0, 'resync_delta': 1})
        self.assertFalse(cd.line_pause_branches(self._pauses([a, late]))['holds'])
        self.assertFalse(cd.line_pause_branches(self._pauses([a, ('none', {})]))['holds'])        # pause 3 s control
        self.assertFalse(cd.line_pause_branches(self._pauses([a]))['holds'])                       # one pause is not C4
        half = ('B', {'reconnect_delta_by_cluster': {'core': 1, 'me': 0}, 'resync_delta': 2})
        self.assertFalse(cd.line_pause_branches(self._pauses([a, half]))['holds'])

    def test_released_outcome_line(self):
        stale = 'assets_release_confirm_stale_total'
        before, after = scrape(ae0={stale: 2.0}), scrape(ae0={stale: 3.0})
        snaps = {'before': before, 'after': after}
        self.assertTrue(cd.line_released_outcome(witness(cd.Ledger(), released_repeats=1, released_after_thaw=[1, 0], snaps=snaps))['holds'])
        self.assertFalse(cd.line_released_outcome(witness(cd.Ledger(), released_repeats=0, released_after_thaw=[0, 0], snaps=snaps))['holds'])
        self.assertFalse(cd.line_released_outcome(witness(cd.Ledger(), released_repeats=1, released_after_thaw=[1],
                                                          snaps={'before': before, 'after': before}))['holds'])
        # review FIX-5: repeats outside the pause window (a no-pause run has them too) do not hold the line
        self.assertFalse(cd.line_released_outcome(witness(cd.Ledger(), released_repeats=9, released_after_thaw=[0, 0], snaps=snaps))['holds'])
        self.assertFalse(cd.line_released_outcome(witness(cd.Ledger(), released_repeats=9, snaps=snaps))['holds'])

    def test_late_copies_after_thaw_counts_only_what_fwd0_can_have_sent(self):
        out = lambda seq: {'journal_seq': seq}
        first = {'a': out(150), 'b': out(50), 'c': out(120)}
        model = types.SimpleNamespace(first_outcome=first, outcome_copies={
            'a': [out(150), out(260)], 'b': [out(50), out(260)], 'c': [out(120), out(130)]})
        rows = [{'kind': 'pause', 'target': 'fwd0', 'witness': {'me_seq_pause': 100, 'me_seq_thaw': 200}}]
        # a: first inside the pause, copy after the thaw -> counted; b: first before the pause; c: copy inside the pause
        self.assertEqual(cd.late_copies_after_thaw(model, rows), [1])
        self.assertIsNone(cd.late_copies_after_thaw(model, []))

    def test_released_after_thaw_attributes_to_the_pause_window(self):
        def row(lo, hi, target='fwd0'):
            return {'kind': 'pause', 'target': target, 'witness': {'me_seq_pause': lo, 'me_seq_thaw': hi}}
        release = lambda seq, high, scope='ORDER': {'type': 'release', 'journal_seq': seq, 'releases': [{'commandIdHigh': high, 'scope': scope}]}
        repeat = lambda seq, high: {'type': 'outcome', 'journal_seq': seq, 'command_id_high': high, 'command_id_low': 5}
        model = types.SimpleNamespace(
            journal=[release(50, 7), release(150, 8), release(160, 9, 'UP_TO'), release(5, 3)],
            released_repeats=[repeat(120, 7), repeat(210, 7), repeat(220, 8), repeat(230, 9), repeat(240, 3)])
        # pause (100, 200]: the ORDER release of 8 is inside; 7 was released before the pause, 9 is UP_TO, 3 long before
        self.assertEqual(cd.released_after_thaw(model, [row(100, 200)]), [1])
        self.assertEqual(cd.released_after_thaw(model, [row(100, 200), row(100, 200, 'fwd1')]), [1])
        self.assertIsNone(cd.released_after_thaw(model, [row(None, 200)]))
        self.assertIsNone(cd.released_after_thaw(model, []))

    def test_leader_changes_and_resyncs_with_the_no_fault_control(self):
        ledger = cd.Ledger()
        ledger.open('kill', 'ae1', {'was_leader': True, 'new_leader': 'ae2', 'election_s': 2.7})
        self.assertTrue(cd.line_ae_leader_changed(witness(ledger))['holds'])
        self.assertFalse(cd.line_ae_leader_changed(witness(cd.Ledger()))['holds'])
        same = cd.Ledger(); same.open('kill', 'ae1', {'was_leader': True, 'new_leader': None})
        self.assertFalse(cd.line_ae_leader_changed(witness(same))['holds'])
        me = cd.Ledger(); me.open('kill', 'me0', {'was_leader': True, 'new_leader': 'me1'})
        self.assertTrue(cd.line_me_leader_changed(witness(me))['holds'])
        self.assertFalse(cd.line_me_leader_changed(witness(ledger))['holds'])
        t1, t2 = 'forwarder_resync_total{reason="T1"}', 'forwarder_resync_total{reason="T2"}'
        before = scrape(fwd0={t1: 1.0, t2: 0.0}, fwd1={t1: 1.0, t2: 0.0})
        after = scrape(fwd0={t1: 2.0, t2: 1.0}, fwd1={t1: 2.0, t2: 0.0})
        snaps = {'before': before, 'after': after}
        self.assertTrue(cd.line_resync_t1_both(witness(ledger, snaps=snaps))['holds'])
        self.assertTrue(cd.line_resync_t2(witness(ledger, snaps=snaps))['holds'])
        quiet = {'before': before, 'after': before}
        self.assertFalse(cd.line_resync_t1_both(witness(ledger, snaps=quiet))['holds'])
        self.assertFalse(cd.line_resync_t2(witness(ledger, snaps=quiet))['holds'])
        one = {'before': before, 'after': scrape(fwd0={t1: 2.0}, fwd1={t1: 1.0})}
        self.assertFalse(cd.line_resync_t1_both(witness(ledger, snaps=one))['holds'])

    def test_member_caught_up(self):
        ledger = cd.Ledger()
        ledger.heal(ledger.open('kill', 'ae1', {'was_leader': True}), 'restart', {'ready': True})
        ok = witness(ledger, ae_leader_after='ae2', ae_commit_positions={'ae0': 9, 'ae1': 9, 'ae2': 9})
        self.assertTrue(cd.line_member_caught_up(ok)['holds'])
        behind = witness(ledger, ae_leader_after='ae2', ae_commit_positions={'ae0': 9, 'ae1': 7, 'ae2': 9})
        self.assertFalse(cd.line_member_caught_up(behind)['holds'])

    def test_member_caught_up_tolerates_idle_log_growth_between_sequential_reads(self):
        ledger = cd.Ledger()
        ledger.heal(ledger.open('kill', 'ae0', {'was_leader': True}), 'restart', {'ready': True})
        # the first S15 coreleader run: ae0 restarted, leader ae2, three sequential reads of a growing idle log
        run = witness(ledger, ae_leader_after='ae2', ae_commit_positions={'ae0': 12528576, 'ae1': 12529216, 'ae2': 12529984},
                      ae_commit_leader_window=[12528512, 12530112])
        self.assertTrue(cd.line_member_caught_up(run)['holds'])
        lagging = witness(ledger, ae_leader_after='ae2', ae_commit_positions={'ae0': 12528576 - 1_000_000, 'ae1': 12529216, 'ae2': 12529984},
                          ae_commit_leader_window=[12528512, 12530112])
        self.assertFalse(cd.line_member_caught_up(lagging)['holds'])

    def test_member_not_ready_is_not_caught_up(self):
        ledger = cd.Ledger()
        ledger.heal(ledger.open('kill', 'ae0', {'was_leader': True}), 'restart', {'ready': False})
        run = witness(ledger, ae_leader_after='ae2', ae_commit_positions={'ae0': 9, 'ae2': 9}, ae_commit_leader_window=[9, 9])
        self.assertFalse(cd.line_member_caught_up(run)['holds'])

    def test_fwd_restarts_and_the_kill_skipped_control(self):
        self.assertTrue(cd.line_fwd_restarts(witness(fwdrestart_witness()))['holds'])
        skipped = cd.Ledger()
        for fwd in cd.FORWARDERS:
            skipped.skip('kill', fwd, 'control fwdrestart-nokill (8.4)')
        self.assertFalse(cd.line_fwd_restarts(witness(skipped))['holds'])
        peer = cd.Ledger()
        for fwd in cd.FORWARDERS:
            peer.heal(peer.open('kill', fwd, {'exit_code': 137}), 'restart', {'ready': True, 'resync_after': 1, 'peer_resync_delta': 1})
        self.assertFalse(cd.line_fwd_restarts(witness(peer))['holds'])

    def test_partition_lines_and_the_drop_skipped_control(self):
        samples = [{'t': 0.0, 'me_seq': 10, 'core_head': 5}, {'t': 2.0, 'me_seq': 10, 'core_head': 40},
                   {'t': 4.0, 'me_seq': 10, 'core_head': 90}, {'t': 4.5, 'me_seq': 30, 'core_head': 95}]
        self.assertEqual(cd.me_stall(samples), 4.0)     # FIX-4: lower bound, first to last read at the stalled seq
        self.assertEqual(cd.me_stall(samples, upper=True), 4.5)     # review B1: the outer bracket
        self.assertEqual(cd.me_stall([dict(s, me_seq=10 + i) for i, s in enumerate(samples)]), 0.0)
        phase2 = {'fwd0': {'reconnect_core': 1, 'new_leader_core': 0}, 'fwd1': {'reconnect_core': 0, 'new_leader_core': 1}}
        held = witness(cd.Ledger(), partition={'me_stall_s': 4.0, 'phase2': phase2})
        self.assertTrue(cd.line_partition_phase1(held)['holds'])
        self.assertTrue(cd.line_partition_phase2(held)['holds'])
        skipped = witness(cd.Ledger(), partition={'phase2': {'fwd0': {'reconnect_core': 0, 'new_leader_core': 0},
                                                             'fwd1': {'reconnect_core': 0, 'new_leader_core': 0}}})
        self.assertFalse(cd.line_partition_phase1(skipped)['holds'])
        self.assertFalse(cd.line_partition_phase2(skipped)['holds'])

    def _kills(self, second_identity, exit_code=70, waited=4.6):
        ledger = cd.Ledger()
        first_new = {'cnc_mtime': '2.0', 'started_at': 'T2'}
        r1 = ledger.open('exec_kill', 'fwd0', {'identity_before': {'cnc_mtime': '1.0', 'started_at': 'T1'}})
        ledger.heal(r1, 'restart', {'exit': {'exit_code': 70, 'waited_s': 4.7}, 'restart': {'driver': {'new': first_new}}})
        r2 = ledger.open('exec_kill', 'fwd0', {'identity_before': second_identity or first_new})
        ledger.heal(r2, 'restart', {'exit': {'exit_code': exit_code, 'waited_s': waited}, 'restart': {}})
        return witness(ledger)

    def test_driver_kills_second_kill_hits_the_new_driver(self):
        self.assertTrue(cd.line_driver_kills(self._kills(None))['holds'])
        self.assertFalse(cd.line_driver_kills(self._kills({'cnc_mtime': '1.0', 'started_at': 'T1'}))['holds'])
        self.assertFalse(cd.line_driver_kills(self._kills(None, exit_code=137))['holds'])
        self.assertFalse(cd.line_driver_kills(self._kills(None, waited=7.5))['holds'])

    def test_lifecycle_counts_from_the_core_events_and_the_without_iceberg_control(self):
        """The clean sample carries one refill, one replace and one stop trigger; the iceberg-less variant none."""
        counts = cd.lifecycle_counts(clean_sample())
        self.assertEqual((counts['slices_refilled'], counts['replace_windows'], counts['stop_trigger']), (1, 1, 1))
        self.assertFalse(cd.line_lifecycle_story(witness(cd.Ledger(), lifecycle_counts=counts))['holds'])
        self.assertTrue(cd.line_lifecycle_story(witness(cd.Ledger(), lifecycle_counts=dict(cd.LIFECYCLE_EXPECTED)))['holds'])
        no_iceberg = variant(clean_sample(), lambda s: (s['creates'].__setitem__(4, dict(s['creates'][4], type='LIMIT'))))
        self.assertEqual(cd.lifecycle_counts(no_iceberg)['slices_refilled'], 0)

    def test_window_lines(self):
        windows = {'slice1': {'held': True, 'killed': 'ae0', 'order': 1005}, 'replace': {'held': True, 'killed': 'me0', 'order': 1003}}
        closures = cd.window_closures(clean_sample(), windows)
        self.assertEqual(closures, {'slice1': 0, 'replace_replaced': 1, 'replace_terminals': 0})
        good = {'slice1': 1, 'replace_replaced': 1, 'replace_terminals': 1}
        self.assertTrue(cd.line_window_lines(witness(cd.Ledger(), windows=windows, window_closures=good))['holds'])
        missed = dict(windows, replace={'held': False, 'killed': None})
        self.assertFalse(cd.line_window_lines(witness(cd.Ledger(), windows=missed, window_closures=good))['holds'])
        self.assertFalse(cd.line_window_lines(witness(cd.Ledger(), windows=windows,
                                                      window_closures=dict(good, replace_terminals=2)))['holds'])

    def test_iceberg_slice_predicate(self):
        events = [{'type': 'trade', 'maker_order': 7, 'taker_order': 8, 'quantity': 4 * FP},
                  {'type': 'trade', 'maker_order': 7, 'taker_order': 9, 'quantity': 6 * FP}]
        self.assertFalse(cd.iceberg_slice_journaled(events, 7))
        self.assertTrue(cd.iceberg_slice_journaled(events + [{'type': 'terminal', 'order': 7}], 7))


# ------------------------------------------------------------------ verdicts, controls, REDs, O-F rows


PASS = {'status': 'PASS', 'rules': {}}


class PartitionPhase1Test(unittest.TestCase):
    """Review B1: phase 1's witness covers the heal. A stall measured only inside the 3 s drop cannot exceed 3 s by the
    property (only by scrape overhead); bracketed through the heal, a 3 s drop gives a gap > 3 s, and the nodrop control
    stays far below it."""

    @staticmethod
    def reads(points):
        return [{'t0': t, 't1': t + 0.05, 'phase': ph, 'me_seq': seq, 'core_head': head} for t, ph, seq, head in points]

    def test_drop_3s_heal_at_4_2_holds_and_reads_that_stop_at_3_do_not(self):
        through = self.reads([(0.0, 'pre', 100, 50), (0.3, 'drop', 105, 52), (1.0, 'drop', 105, 60), (2.0, 'drop', 105, 70),
                              (3.0, 'drop', 105, 80), (3.4, 'heal', 105, 82), (4.2, 'heal', 130, 84)])
        self.assertEqual(cd.me_stall(through, upper=True), 4.25)    # 0.0 (the read before the stand-still) to 4.25 (t1 of the 4.2 read)
        self.assertEqual(cd.me_stall(through), 3.05)    # FIX-4: t0 3.4 of the last stalled read minus t1 0.35 of the first
        self.assertTrue(cd.line_partition_phase1(witness(cd.Ledger(), partition={'me_stall_s': cd.me_stall(through)}))['holds'])
        stopped = [r for r in through if r['phase'] != 'heal']   # c781b4c's window: the drop only
        self.assertEqual(cd.me_stall(stopped), 0.0)
        self.assertFalse(cd.line_partition_phase1(witness(cd.Ledger(), partition={'me_stall_s': cd.me_stall(stopped)}))['holds'])

    def test_a_stand_still_without_core_progress_or_seen_once_counts_nothing(self):
        flat = self.reads([(0.0, 'pre', 100, 50), (1.0, 'drop', 105, 50), (3.0, 'drop', 105, 50), (4.0, 'heal', 130, 50)])
        self.assertEqual(cd.me_stall(flat), 0.0)                  # the core minted nothing: no first-apply gap to judge
        once = self.reads([(0.0, 'pre', 100, 50), (3.5, 'drop', 105, 60), (4.0, 'heal', 130, 70)])
        self.assertEqual(cd.me_stall(once), 0.0)                  # one read is no stand-still

    def test_core_pending_rise_counts_as_the_core_moving_when_the_forwarder_head_freezes(self):
        """First S15 partition run: the cut forwarders' own core_head froze (2121) for the whole drop while the ME seq
        stood still; the AE leader's pending-command gauge rose, which is the core side of the witness."""
        def read(t0, t1, phase, seq, head, pending):
            return {'t0': t0, 't1': t1, 'phase': phase, 'me_seq': seq, 'core_head': head, 'core_pending': pending}
        samples = [read(0.0, 0.4, 'pre', 3929, 2121, 5), read(2.36, 2.7, 'drop', 4612, 2121, 40), read(3.4, 3.8, 'drop', 4612, 2121, 160),
                   read(5.0, 5.4, 'drop', 4612, 2121, 330), read(7.35, 7.7, 'heal', 7055, 4947, 12)]
        self.assertEqual(cd.me_stall(samples), 2.3)      # lower bound: the first read at the seq ended 2.7, the last began 5.0
        dipped = [dict(s, core_pending=p) for s, p in zip(samples, (5, 40, 330, 2, 12))]   # f-s15-partition-3: the gauge clears at the heal
        self.assertEqual(cd.me_stall(dipped), 2.3)
        flat = [dict(s, core_pending=40) for s in samples]
        self.assertEqual(cd.me_stall(flat), 0.0)          # nothing moved on the core side either: the line stays false

    def sampler(self, me_seq_at, drop_effect=True):
        """sample_me_progress on a stub: a fake monotonic clock that the stub sleep and every read advance."""
        clock = {'t': 100.0}
        f = types.SimpleNamespace(m={'ports': {'me_metrics': 9101, 'forwarder_http': 9700}})
        calls = []

        def metrics(role, port):
            clock['t'] += 0.05
            if role.startswith('fwd'):
                return {'forwarder_dispatch_seq{point="core_head"}': 10 + int(clock['t'] * 10)}
            return {'match_engine_next_journal_seq': me_seq_at(clock['t'], calls)}
        f.metrics = metrics
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.f, run.sleep = f, lambda s: clock.__setitem__('t', clock['t'] + s)

        def sync(fn):                  # the helper call runs to completion before the next read (no threads on a fake clock)
            fn()
            return types.SimpleNamespace(is_alive=lambda: False, join=lambda: None, errors=[])
        run.background = sync
        add = lambda: calls.append(('add', clock['t']))
        delete = lambda: calls.append(('delete', clock['t']))
        with mock.patch.object(cd.time, 'monotonic', lambda: clock['t']):
            samples = run.sample_me_progress('me1', cd.PARTITION1_DROP_S, add, delete)
        return samples, calls

    def test_sampler_reads_through_the_heal_until_the_seq_moves(self):
        def seq(t, calls):
            added = next((at for k, at in calls if k == 'add'), None)
            deleted = next((at for k, at in calls if k == 'delete'), None)
            if added is None:
                return int(t * 100)
            if deleted is None or t < deleted + 0.4:              # nothing applied until 0.4 s after the heal
                return int(added * 100)
            return int(t * 100)
        samples, calls = self.sampler(seq)
        self.assertEqual([k for k, _ in calls], ['add', 'delete'])
        self.assertEqual(samples[0]['phase'], 'pre')
        self.assertEqual(samples[-1]['phase'], 'heal')
        self.assertNotEqual(samples[-1]['me_seq'], cd._stalled_seq(samples))
        self.assertGreaterEqual(calls[1][1] - calls[0][1], cd.PARTITION1_DROP_S)
        self.assertGreater(cd.me_stall(samples), cd.PARTITION1_DROP_S)

    def test_nodrop_control_samples_the_same_way_and_stays_below(self):
        samples, _ = self.sampler(lambda t, calls: int(t * 100))   # the seq moves on every read: nothing dropped
        self.assertLess(cd.me_stall(samples), 1.0)
        self.assertFalse(cd.line_partition_phase1(witness(cd.Ledger(), partition={'me_stall_s': cd.me_stall(samples)}))['holds'])

    def test_heal_never_seen_is_bounded_and_counts_nothing(self):
        samples, _ = self.sampler(lambda t, calls: 5 if calls else int(t * 100))
        self.assertEqual(samples[-1]['phase'], 'heal')
        self.assertGreaterEqual(samples[-1]['t0'], cd.PARTITION1_HEAL_BOUND_S)
        self.assertEqual(cd.me_stall(samples), 0.0)


class BridgeWatchTest(unittest.TestCase):
    """Review F1: RED-2's 'ready and not halted throughout' is watched during the load (post_load), not only after it."""

    def test_post_load_watches_the_bridges_while_the_story_runs(self):
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.red, run.bridge_watch, run.spec = 'red2', [], cd.DRILLS['lifecycle']
        run.ledger = cd.Ledger()
        ticks = {'n': 0}
        run.f = types.SimpleNamespace(root=Path('/nonexistent'), ready_body=lambda b: (200, ''))
        exit_file = mock.MagicMock()
        exit_file.exists = lambda: ticks['n'] >= 3
        run.story_paths = {'exit': exit_file}
        run.markers = lambda: []
        run.sleep = lambda s: ticks.__setitem__('n', ticks['n'] + 1)
        gate = mock.MagicMock()
        with mock.patch.object(cd.core_scenarios, 'barrier_scrape', lambda f: scrape(bridge0={'bridge_halted': 0.0},
                                                                                       bridge1={'bridge_halted': 0.0})), \
                mock.patch.object(cd, 'Path', lambda *a: gate):
            run.f.root = gate
            run.post_load()
        self.assertEqual(len(run.bridge_watch), 3)               # one row per wait tick during the load
        self.assertEqual(run.bridge_watch[0]['bridge0'], {'ready': 200, 'halted': 0.0})

    def test_watch_span_covers_the_story_or_says_why_not(self):
        t0, exit_ns = 1_000 * 10**9, 1_030 * 10**9
        rows = [{'at_ns': t0 + int(s * 1e9)} for s in (1, 4, 9, 15, 22, 30)]
        span = cd.watch_span(rows, t0, exit_ns)
        self.assertTrue(span['covers_the_story'])
        self.assertEqual((span['rows'], span['first_at_ns'], span['last_at_ns']), (6, rows[0]['at_ns'], rows[-1]['at_ns']))
        self.assertFalse(cd.watch_span(rows[1:], t0 - 2 * 10**9, exit_ns)['covers_the_story'])   # started late
        self.assertFalse(cd.watch_span(rows[:-1], t0, exit_ns)['covers_the_story'])              # ended before the exit
        self.assertFalse(cd.watch_span([rows[0], rows[-1]], t0, exit_ns)['covers_the_story'])    # a 29 s hole
        self.assertFalse(cd.watch_span([], t0, exit_ns)['covers_the_story'])

    def test_red2_precondition_needs_the_covered_span(self):
        self.assertIn('bridge_watch_covers_the_story', Path(cd.__file__).read_text())
        verdict = cd.red_verdict('red2', {'status': 'PASS', 'rules': {'M7': {'status': 'PASS'}, 'M8': {'status': 'PASS'}}},
                                 {'status': 'FAIL', 'rules': {'O4': {'status': 'FAIL', 'detail': 'ME leg 5 core says none'}}},
                                 {'settle_rows': True, 'bridges_ready_and_not_halted_throughout': True,
                                  'bridge_watch_covers_the_story': False})
        self.assertEqual(verdict['status'], 'INCONCLUSIVE')


class BridgeReadyThroughoutTest(unittest.TestCase):
    """S15 W5 (F-S15-32): the real ct-bridge flaps /ready 503 no_source_attached for single rows."""

    @staticmethod
    def row(b0=(200, 0.0, ''), b1=(200, 0.0, '')):
        return {'at_ns': 0, 'bridge0': {'ready': b0[0], 'halted': b0[1], 'ready_body': b0[2]},
                'bridge1': {'ready': b1[0], 'halted': b1[1], 'ready_body': b1[2]}}

    NSA = (503, 0.0, 'not ready: no_source_attached\n')

    def test_single_no_source_attached_rows_are_tolerated(self):
        rows = [self.row(), self.row(b0=self.NSA), self.row(), self.row(b1=self.NSA), self.row(), self.row(b0=self.NSA, b1=self.NSA), self.row()]
        self.assertTrue(cd.bridges_ready_throughout(rows))
        self.assertEqual(len(cd.ready_transients(rows)), 4)

    def test_two_consecutive_503_rows_fail(self):
        self.assertFalse(cd.bridges_ready_throughout([self.row(), self.row(b0=self.NSA), self.row(b0=self.NSA), self.row()]))

    def test_another_503_reason_fails(self):
        self.assertFalse(cd.bridges_ready_throughout([self.row(b1=(503, 0.0, 'not ready: stalled\n'))]))
        self.assertFalse(cd.bridges_ready_throughout([self.row(b1=(503, 0.0, ''))]))

    def test_a_halt_fails_even_with_a_200(self):
        self.assertFalse(cd.bridges_ready_throughout([self.row(), self.row(b0=(200, 1.0, ''))]))

    def test_an_empty_watch_fails(self):
        self.assertFalse(cd.bridges_ready_throughout([]))


class MemberLivesTest(unittest.TestCase):
    """S15 W5 (F-S15-31): a restarted ME member journals the replayed log again into a new recording."""

    @staticmethod
    def event(seq, recording, **more):
        return dict({'type': 'outcome', 'journal_seq': seq, 'recording': recording, 'source': 'me2', 'position': seq * 100,
                     'command_id_high': seq}, **more)

    def test_a_second_recording_that_repeats_the_log_counts_once(self):
        import core_scenarios
        events = [self.event(1, 0), self.event(2, 0), self.event(1, 1), self.event(2, 1), self.event(3, 1)]
        merged = core_scenarios.merge_member_lives(events, True)
        self.assertEqual([e['journal_seq'] for e in merged], [1, 2, 3])
        self.assertTrue(all('recording' not in e and 'position' not in e and 'source' not in e for e in merged))

    def test_the_same_seq_with_other_content_is_a_divergence(self):
        import core_scenarios
        events = [self.event(1, 0), self.event(1, 1, command_id_high=99)]
        with self.assertRaises(Violation):
            core_scenarios.merge_member_lives(events, True)

    def test_one_recording_and_legacy_profiles_are_left_alone(self):
        import core_scenarios
        one = [self.event(1, 0), self.event(2, 0)]
        self.assertEqual(len(core_scenarios.merge_member_lives(one, True)), 2)
        legacy = [{'type': 'outcome', 'recording': 0}, {'type': 'outcome', 'recording': 1}]
        self.assertEqual(len(core_scenarios.merge_member_lives(legacy, False)), 2)


class Red2StoryBoundTest(unittest.TestCase):
    """W5: with the outcome records dropped every a02 await runs its full 30 s, so only the red2 builds get a longer story."""

    def test_only_red2_runs_get_extra_story_time(self):
        self.assertEqual(cd.story_extra_s(None), 0)
        self.assertEqual(cd.story_extra_s('red1'), 0)
        self.assertEqual(cd.story_extra_s('red2'), cd.RED2_AWAITS * cd.RED2_AWAIT_S)
        self.assertEqual(cd.story_extra_s('red2-negctl'), cd.RED2_AWAITS * cd.RED2_AWAIT_S)

    def test_the_tap_covers_the_longer_story(self):
        spec = cd.DRILLS['lifecycle']
        base = cd.plan_for(spec, 1)['tap_ms']
        self.assertEqual(cd.plan_for(spec, 1, cd.story_extra_s('red2'))['tap_ms'] - base, cd.RED2_STORY_EXTRA_S * 1000)


class HeldOrderTest(unittest.TestCase):
    def test_the_window_order_comes_from_the_hold_marker(self):
        """Review F6: the parent of window 1 is the order the story names in hold_ready, never 'the first market-1 CREATE
        with quantity 10' (an a02 SELL has that shape too)."""
        self.assertEqual(cd.held_order({'hold': 'slice1_exhausting_fill', 'order': 41, 'row': 1}), 41)
        for bad in ({'hold': 'slice1_exhausting_fill'}, {'hold': 'x', 'order': None}, {'hold': 'x', 'order': 0},
                    {'hold': 'x', 'order': True}, {'hold': 'x', 'order': '41'}):
            with self.subTest(bad=bad), self.assertRaisesRegex(Inconclusive, 'names no held order'):
                cd.held_order(bad)
        self.assertFalse(hasattr(cd.DrillRun, 'iceberg_parent'))


class VerdictTest(unittest.TestCase):
    def test_order_fail_dominates(self):
        held = {'x': {'holds': True}}
        self.assertEqual(cd.verdict(PASS, {'status': 'FAIL', 'rules': {'O2': {'status': 'FAIL'}}}, held, {})['status'], 'FAIL')
        self.assertEqual(cd.verdict(PASS, PASS, {'x': {'holds': False}}, {})['status'], 'FAIL')
        self.assertEqual(cd.verdict(PASS, PASS, held, {}, ['window not held'])['status'], 'FAIL')
        self.assertEqual(cd.verdict(PASS, PASS, held, {'O-F5': {'holds': False, 'inconclusive_when_failing': True}})['status'],
                         'INCONCLUSIVE')
        self.assertEqual(cd.verdict(PASS, {'status': 'INCONCLUSIVE', 'rules': {}}, held, {})['status'], 'INCONCLUSIVE')
        self.assertEqual(cd.verdict(PASS, PASS, held, {'O-F1': {'holds': True}})['status'], 'PASS')

    def test_control_passes_only_when_its_line_fails(self):
        self.assertEqual(cd.control_verdict(PASS, PASS, {'l': {'holds': False}}, ['l'])['status'], 'PASS')
        self.assertEqual(cd.control_verdict(PASS, PASS, {'l': {'holds': True}}, ['l'])['status'], 'FAIL')
        self.assertNotEqual(cd.control_verdict(PASS, {'status': 'INCONCLUSIVE'}, {'l': {'holds': False}}, ['l'])['status'], 'PASS')

    def test_red1_needs_the_o10_text_and_live_nc_forwarders(self):
        """8.1 on a recorded sample: the clean stream with 1003's create never applied (what nc_noresync leaves)."""
        sample = variant(clean_sample(), lambda s: s['me_journal'].__delitem__(outcome_index(s, 1003, 0)))
        money, order = judge(sample)
        ok = cd.red_verdict('red1', money, order, {'fwd0_running_health_200': True, 'fwd1_running_health_200': True})
        self.assertEqual((ok['status'], ok['red']), ('PASS', 'RED'), ok)
        crashed = cd.red_verdict('red1', money, order, {'fwd0_running_health_200': False})
        self.assertEqual(crashed['status'], 'INCONCLUSIVE')
        green = cd.red_verdict('red1', *judge(clean_sample()), {'fwd0_running_health_200': True})
        self.assertEqual((green['status'], green['red']), ('FAIL', 'GREEN'))

    def test_red2_needs_the_trade_path_and_an_outcome_rule(self):
        """8.2: an extra ME resting leg the core does not list (O4 "ME only") with M7/M8 PASS is RED-2."""
        sample = variant(clean_sample(), lambda s: s['me_open_legs'].append({'leg': 5999, 'order': 1004, 'user': SELLER, 'market': 1}))
        money, order = judge(sample)
        v = cd.red_verdict('red2', money, order, {'settle_rows': True, 'bridges_ready_and_not_halted_throughout': True})
        self.assertEqual((v['status'], v['named']), ('PASS', ['O4']), v)
        halted = cd.red_verdict('red2', money, order, {'settle_rows': True, 'bridges_ready_and_not_halted_throughout': False})
        self.assertEqual(halted['status'], 'INCONCLUSIVE')
        # negctl (W0 answer 8): the trade translation never ran, M8 FAILs: not an accepted RED-2
        no_settle = variant(sample, lambda s: s.__setitem__('money_journal', [r for r in s['money_journal'] if r['kind'] != 'settle']))
        m2, o2 = judge(no_settle)
        self.assertNotEqual(cd.red_verdict('red2', m2, o2, {'settle_rows': False, 'bridges_ready_and_not_halted_throughout': True})['status'], 'PASS')
        only_o7 = variant(clean_sample(), lambda s: s['core']['pending_dispatch'].update(count=1))
        self.assertNotEqual(cd.red_verdict('red2', *judge(only_o7), {'settle_rows': True,
                                                                     'bridges_ready_and_not_halted_throughout': True})['status'], 'PASS')

    def test_of_rows(self):
        sample = clean_sample()
        after = scrape(me0={**{n: 0.0 for n in cd.ME_REFUSALS}, 'match_cluster_role': 2.0, 'match_command_ledger_size': 7.0},
                       me1={}, me2={}, ae0={'assets_cluster_role': 2.0, 'assets_pending_commands': 0.0,
                                            'assets_release_backlog': 0.0, 'assets_me_ledger_size': 7.0},
                       bridge0={'bridge_halted': 0.0}, bridge1={'bridge_halted': 0.0})
        rows = cd.of_rows(after, sample)
        self.assertTrue(all(r['holds'] for r in rows.values()), rows)
        refused = copy.deepcopy(after); refused['me1']['match_ingress_unauthorized_total'] = 1.0
        self.assertFalse(cd.of_rows(refused, sample)['O-F1']['holds'])
        drift = copy.deepcopy(after); drift['ae0']['assets_me_ledger_size'] = 8.0
        self.assertFalse(cd.of_rows(drift, sample)['O-F4']['holds'])
        self.assertFalse(cd.of_rows(after, holed(6))['O-F5']['holds'])
        halted = copy.deepcopy(after); halted['bridge1']['bridge_halted'] = 1.0
        self.assertFalse(cd.of_rows(halted, sample)['bridges_not_halted']['holds'])


# ------------------------------------------------------------------ drill table, plans, scenario dispatch


class StubFixture:
    def __init__(self, slots=None, artifacts=None):
        self.m = {'seed': 0x1234, 'slot_artifacts': slots or {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge',
                                                               'bridge1': 'bridge', 'shadow0': None},
                  'artifacts': artifacts or {'forwarder': {'driver': 'external'}, 'bridge': {'driver': 'external'},
                                             'forwarder_b': None, 'bridge_b': None}}


class TableTest(unittest.TestCase):
    def test_every_drill_has_a_schedule_and_known_lines(self):
        self.assertEqual(set(cd.DRILLS), {'lostack', 'coreleader', 'meleader', 'fwdrestart', 'fwdpause', 'partition',
                                          'driverkill', 'lifecycle', 'lifecycle-faults'})
        for name, spec in cd.DRILLS.items():
            self.assertTrue(hasattr(cd.DrillRun, 'faults_' + spec['faults']), name)
            for line in spec['lines']:
                self.assertIn(line, cd.LINES, (name, line))
        for control, (drill, _, lines) in cd.CONTROLS.items():
            self.assertIn(drill, cd.DRILLS)
            self.assertTrue(set(lines) <= set(cd.DRILLS[drill]['lines']), control)
        self.assertEqual({k for k, v in cd.DRILLS.items() if v.get('ordering_exception')}, {'meleader', 'lifecycle-faults'})

    def test_c4_twice_where_the_contract_says_twice(self):
        for name in ('fwdrestart', 'fwdpause', 'driverkill'):
            self.assertEqual(cd.DRILLS[name]['cycles'], 2, name)

    def test_plans_fit_the_per_user_cap_and_the_tap_covers_the_run(self):
        for name, spec in cd.DRILLS.items():
            story = spec['story']
            plan = cd.plan_for(spec, 1)
            self.assertEqual(plan['funding_for'], story['script'])
            if story['script'] == 'a01-mix':
                requests = (story['rate'] + story['rate'] // 5) * story['seconds']
                self.assertLessEqual(requests / len(story['users']), 256, name)    # A7 RequestTable.PER_USER_CAP
                self.assertEqual(len(story['users']) % 2, 0)
            self.assertGreaterEqual(plan['tap_ms'] / 1000, story['seconds'] + cd.PRE_BARRIER_S + 60, name)
            self.assertGreaterEqual(plan['risk']['per_sec'], 2 * story['rate'])

    def test_scenario_refuses_unknown_and_mismatched_runs(self):
        with self.assertRaisesRegex(Inconclusive, 'not implemented'):
            cd.scenario(StubFixture(), 'core-drill-nope', '/nonexistent')
        with self.assertRaisesRegex(Inconclusive, 'unknown control'):
            cd.scenario(StubFixture(), 'core-control-nope', '/nonexistent')
        with self.assertRaisesRegex(Inconclusive, 'needs the negative build forwarder_b'):
            cd.scenario(StubFixture(), 'core-red-1', '/nonexistent')
        red = StubFixture(slots={'fwd0': 'forwarder_b', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge'},
                          artifacts={'forwarder_b': {'driver': 'external'}, 'forwarder': {'driver': 'external'}})
        with self.assertRaisesRegex(Inconclusive, 'GREEN drills run the real binaries only'):
            cd.scenario(red, 'core-drill-lostack', '/nonexistent')

    def test_story_args_carry_the_resolution_gate_and_the_holds(self):
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.spec, run.variant, run.seed = cd.DRILLS['lifecycle-faults'], {}, 7
        kv = run.story_args()
        self.assertEqual(kv['hold'], 'slice1_exhausting_fill,' + cd.WINDOW2_HOLD)
        self.assertEqual(kv['resolve_gate'], '/data/resolve.go')
        run.spec, run.variant = cd.DRILLS['lifecycle'], {'without': 'iceberg'}
        self.assertEqual(run.story_args()['without'], 'iceberg')
        self.assertNotIn('hold', run.story_args())

    def test_value_and_delta_helpers(self):
        s = scrape(fwd0={'forwarder_resync_total{reason="T1"}': 2.0, 'forwarder_resync_total{reason="T2"}': 3.0})
        self.assertEqual(cd.value(s, 'fwd0', 'forwarder_resync_total'), 5.0)
        self.assertIsNone(cd.value({'fwd0': {'unavailable': 'x'}}, 'fwd0', 'forwarder_resync_total'))
        self.assertEqual(cd.delta(scrape(f={'c': 5.0}), scrape(f={'c': 2.0}), 'f', 'c'), 2.0)            # restarted, reset
        self.assertEqual(cd.delta(scrape(f={'c': 5.0}), scrape(f={'c': 7.0}), 'f', 'c'), 2.0)
        self.assertEqual(cd.leader_of(scrape(ae0={'assets_cluster_role': 1.0}, ae1={'assets_cluster_role': 2.0}), 'ae'), 'ae1')


# ------------------------------------------------------------------ the heal observer on a stub fixture (5.5, 8.4)


class BranchObserverTest(unittest.TestCase):
    """await_branches against a stub fixture: no docker, the container state and the scrapes are scripted."""

    def run_branch(self, role, state, scrapes, thawed_ago_s=0.0, ready=200, health=None, due=None):
        calls = []
        f = types.SimpleNamespace(registry={'containers': {role: 'cid'}}, clock=time.time, sleep=lambda s: None,
                                  m={'seed': 1, 'ports': {'forwarder_http': 9700, 'bridge_http': 9600}})
        f.inspect = lambda kind, cid: {'State': state}
        f.ready_target = lambda r: (9700, '/ready')
        f.ready_body = lambda r: (ready, '')
        f.http = lambda r, port, path: {'status': 200, 'body': json.dumps(health or {'aeConnected': True})}
        f.restart = lambda r, readiness=None: calls.append(('restart', r)) or {'kind': 'restart', 'target': r}
        f.close_fault = lambda r: calls.append(('close', r))
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.f, run.ledger, run.extra, run.restarted, run.sleep = f, cd.Ledger(), {}, set(), f.sleep
        row = run.ledger.open('pause', role)
        feed = iter(scrapes)
        with mock.patch.object(cd.core_scenarios, 'barrier_scrape', lambda fixture: next(feed)):
            run.due_ran = run.await_branches({role: row}, scrapes[0], time.time_ns() - int(thawed_ago_s * 1e9), due=due)
        return row, calls, run

    def test_branch_a_exit_70_then_restart(self):
        t1 = 'forwarder_resync_total{reason="T1"}'
        row, calls, _ = self.run_branch('fwd0', {'Running': False, 'ExitCode': 70},
                                        [scrape(fwd0={t1: 0.0}), scrape(fwd0={t1: 1.0})])
        self.assertEqual(row['heal']['branch'], 'A')
        self.assertEqual(row['heal']['witness']['resync_delta'], 1.0)
        self.assertEqual(calls, [('restart', 'fwd0')])

    def test_branch_b_reconnect_counters_moved(self):
        rc, mc = 'forwarder_session_reconnect_total{cluster="core"}', 'forwarder_session_reconnect_total{cluster="me"}'
        before = scrape(fwd0={rc: 0.0, mc: 0.0})
        row, calls, _ = self.run_branch('fwd0', {'Running': True}, [before, scrape(fwd0={rc: 1.0, mc: 1.0})])
        self.assertEqual(row['heal']['branch'], 'B')
        self.assertEqual(row['heal']['witness']['reconnect_delta_by_cluster'], {'core': 1.0, 'me': 1.0})
        self.assertEqual(calls, [('close', 'fwd0')])

    def test_no_session_loss_heals_as_none_and_fails_its_line(self):
        sc = 'bridge_client_sessions_opened_total'
        row, _, _ = self.run_branch('bridge0', {'Running': True}, [scrape(bridge0={sc: 1.0}), scrape(bridge0={sc: 1.0})],
                                    thawed_ago_s=cd.NO_LOSS_AFTER_S + 1)
        self.assertEqual(row['heal']['branch'], 'none')

    def test_unexpected_exit_after_thaw_is_inconclusive(self):
        with self.assertRaisesRegex(Inconclusive, 'exited 137 after the thaw'):
            self.run_branch('fwd0', {'Running': False, 'ExitCode': 137}, [scrape(fwd0={})])

    def test_due_action_runs_at_its_time_while_a_branch_is_still_pending(self):
        """Review F9: lostack restarts the forwarders at t=37 whatever branch the bridges are still in; the action runs
        once, between two observations of a branch that has not resolved."""
        sc = 'bridge_client_sessions_opened_total'
        fired = []
        row, _, run = self.run_branch('bridge0', {'Running': True}, [scrape(bridge0={sc: 1.0})] * 4,
                                      thawed_ago_s=cd.HEAL_BOUND_S + 1, ready=503,
                                      due=(time.time_ns() - 1, lambda: fired.append(1)))
        self.assertTrue(run.due_ran)
        self.assertEqual(fired, [1])
        self.assertIsNone(row['heal'])                        # the branch had not resolved when the action ran
        later = []
        _, _, run = self.run_branch('bridge0', {'Running': True}, [scrape(bridge0={sc: 1.0})] * 4,
                                    thawed_ago_s=cd.HEAL_BOUND_S + 1, ready=503,
                                    due=(time.time_ns() + 3600 * 10**9, lambda: later.append(1)))
        self.assertFalse(run.due_ran)                         # not due yet: faults_lostack runs it after at(37)
        self.assertEqual(later, [])
        _, _, run = self.run_branch('bridge0', {'Running': True}, [scrape(bridge0={sc: 1.0})] * 4,
                                    thawed_ago_s=cd.HEAL_BOUND_S + 1, ready=503)
        self.assertTrue(run.due_ran)                          # no action: nothing to wait for

    def test_lostack_restarts_the_forwarders_at_37_not_after_the_branches(self):
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.variant, run.extra, run.ledger, run.restarted = {}, {}, cd.Ledger(), set()
        run.t0 = time.time_ns() - 40 * 10**9                 # t=40: every at() returns at once
        order = []
        run.snap = lambda label: {}
        run.at = lambda seconds: order.append(('at', seconds))
        run.pause = lambda role, s: run.ledger.open('pause', role)
        run.kill = lambda role: run.ledger.open('kill', role)
        run.f = types.SimpleNamespace(unpause=lambda b: order.append(('unpause', b)))
        run.restart = lambda row, readiness=None: order.append(('restart', row['target']))

        def await_branches(rows, before, thawed, due=None):
            order.append(('branches_start',))
            due[1]()                                          # due at t=37 < now: it runs inside the observation
            order.append(('branches_end',))
            return True
        run.await_branches = await_branches
        run.faults_lostack()
        i = order.index(('branches_start',))
        self.assertEqual(order[i + 1:i + 3], [('restart', 'fwd0'), ('restart', 'fwd1')])
        self.assertEqual(run.extra['lostack_forwarder_restart']['planned_s'], 37)
        self.assertGreaterEqual(run.extra['lostack_forwarder_restart']['fwd0_at_s'], 40)
        kills = cd._rows({'ledger': run.ledger.rows}, 'kill')
        self.assertTrue(all('restart_at_s' in r['witness'] for r in kills))

    def test_heal_never_observed_leaves_the_row_open(self):
        _, _, run = self.run_branch('fwd0', {'Running': True}, [scrape(fwd0={})] * 3, thawed_ago_s=cd.HEAL_BOUND_S + 1,
                                    ready=503)
        self.assertTrue(run.ledger.fault_open())
        self.assertEqual(run.extra['heal_not_observed'], ['fwd0'])


# ------------------------------------------------------------------ the recorded forwarder run (W3 smoke, 2026-11-02)

RECORDED = Path(__file__).with_name('samples') / 'w3-smoke-a01-n2.json'


def recorded():
    """A real barrier sample: fixture v3 genesis, ct-forwarder x2 and ct-bridge x2 external, a 3 s a01-mix story at 10/s,
    no fault (W3 wiring smoke). 30 creates, 5 cancels, 78 dispatches (43 of them RELEASE_ID), 12 trades."""
    return json.loads(RECORDED.read_text())


class RecordedRunTest(unittest.TestCase):
    def test_recorded_forwarder_run_passes_both_oracles(self):
        """RED c781b4c on this sample: FAIL "dispatch tap saw command id twice as a new dispatch: (1, 0)" (F-S15-25);
        with that fixed alone, M8 FAIL (settle rows carry no meEpoch), O1 FAIL "dispatch for order 0" (RELEASE_ID rows
        carry order 0) and O11 FAIL "stale + redundant outcomes 15 != duplicate ME outcome records 0"."""
        money, order = judge(recorded())
        self.assertEqual((money['status'], order['status']), ('PASS', 'PASS'), (money, order))
        self.assertEqual(rule(order, 'O11')['preempted'], 15)

    def test_recorded_o11_counts_each_unmatched_outcome_once(self):
        sample = recorded()
        sample['counters']['redundant_outcomes'] += 1
        self.assertEqual(rule(order_oracle.judge(sample), 'O11')['status'], 'FAIL')

    def test_recorded_lost_create_and_release_dispatch_are_backfilled(self):
        """A tap hole over one CREATE and one RELEASE_ID: INCONCLUSIVE until backfilled; the release mapping is verified
        on this run's own 43 RELEASE_ID rows (commandIdHigh, idLowFloor == id_high, id_low)."""
        sample = recorded()
        create = next(r for r in sample['dispatch_tap'] if r['kind'] == 'CREATE' and r['seq'] > 10)
        release = next(r for r in sample['dispatch_tap'] if r['kind'] == 'RELEASE_ID' and r['seq'] > create['seq'])
        sample['dispatch_tap'] = [r for r in sample['dispatch_tap'] if r['seq'] not in {create['seq'], release['seq']}]
        holed_sample = seal(copy.deepcopy(sample))
        self.assertEqual(rule(order_oracle.judge(holed_sample), 'O3')['status'], 'INCONCLUSIVE')
        filled, report = backfilled(holed_sample)
        self.assertEqual(report['release_mapping'], 'verified')
        self.assertEqual(sorted(r['kind'] for r in filled['dispatch_tap'] if r.get('source') == 'backfill'), ['CREATE', 'RELEASE_ID'])
        self.assertEqual(order_oracle.judge(filled)['status'], 'PASS')

    def test_recorded_settle_rows_take_the_single_declared_epoch(self):
        sample = recorded()
        sample['declared']['epochs'] = [sample['declared']['epochs'][0], 99]
        self.assertEqual(rule(core_oracle.judge(sample), 'M8')['status'], 'INCONCLUSIVE')


if __name__ == '__main__':
    unittest.main()
