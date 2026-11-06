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

import core_contracts
import core_drills as cd
import core_oracle
import core_scenarios
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
    clock, sleep = staticmethod(time.time), staticmethod(lambda s: None)

    def __init__(self, slots=None, artifacts=None):
        self.m = {'seed': 0x1234, 'slot_artifacts': slots or {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge',
                                                               'bridge1': 'bridge', 'shadow0': None},
                  'artifacts': artifacts or {'forwarder': {'driver': 'external'}, 'bridge': {'driver': 'external'},
                                             'forwarder_b': None, 'bridge_b': None}}


class TableTest(unittest.TestCase):
    def test_every_drill_has_a_schedule_and_known_lines(self):
        self.assertTrue({'lostack', 'coreleader', 'meleader', 'fwdrestart', 'fwdpause', 'partition', 'driverkill', 'lifecycle',
                         'lifecycle-faults'} <= set(cd.DRILLS))           # S16 adds its nine (S16TableTest)
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
            self.assertEqual(plan['funding_for'], cd.funding_script(story))     # S16: a03-fill funds as a01-mix
            if story['script'] == 'a01-mix':
                requests = (story['rate'] + story['rate'] // 5) * story['seconds']
                self.assertLessEqual(requests / len(story['users']), 256, name)    # A7 RequestTable.PER_USER_CAP
                self.assertEqual(len(story['users']) % 2, 0)
            self.assertGreaterEqual(plan['tap_ms'] / 1000, cd.story_seconds(story) + cd.PRE_BARRIER_S + 60, name)
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


# ================================================================== RC2 S16 W3: the nine drills, lines, REDs (contract 5.4, 7, 8, 9)
# No S16 drill has run yet (W5/W6): every line is proven on synthesized witnesses with the shapes of the W0 dry-run
# evidence (S16/evidence/dry-run/), each with its control (the same witness with the fault switched off).


def S(t, **roles):
    """One 1 s sampler row: wall seconds and per-role metric values (the sampler's shape)."""
    return {'t0': t, 't1': t, 'roles': {r: dict(v) for r, v in roles.items()}}


def lead(engine, value=2.0):
    return {('assets_cluster_role' if engine == 'ae' else 'match_cluster_role'): value}


def release_event(seq, entries, epoch=7):
    return {'type': 'release', 'journal_seq': seq, 'me_epoch': epoch,
            'releases': [dict({'scope': 'UP_TO', 'result': 'APPLIED', 'removed': 1}, **e) for e in entries]}


class DeclaredS16Test(unittest.TestCase):
    def test_declared_blocks_per_drill_section_7(self):
        """RED 6380b01: declared_block takes no gate_sequence / halt / order_fault (one constant block, CD:182-186)."""
        g = cd.GATE_SEQUENCE
        self.assertEqual(cd.declared_for('a03-lifetime', {}, 1)['gate_sequence'],
                         g + [['SUSPENDED', 'ME_CAPACITY'], ['OPEN', 'ADMIN']])
        life1 = cd.declared_for('a04-regenesis', {}, 1)
        self.assertEqual((life1['gate_sequence'], life1['halt'], life1['order_fault']),
                         (g + [['SUSPENDED', 'BRIDGE_HALT']], True, 1))
        life2 = cd.declared_for('a04-regenesis', {}, 2)
        self.assertEqual((life2['gate_sequence'], life2['halt'], life2['order_fault']), (g, False, 0))
        for name in ('a04-one-bridge-halt', 'a05-fwd-upgrade', 'a05-fwd-kill', 'a05-bridge-upgrade',
                     'a06-two-forwarders-ticks', 'a01-fwdring', 'c13-enginedriverkill'):
            self.assertEqual(cd.declared_for(name, {}, 1), {'gate_sequence': g, 'halt': False, 'order_fault': 0}, name)
        # the controls that switch the close / the halt off declare the two-step sequence, so the oracles can PASS
        self.assertEqual(cd.declared_for('a03-lifetime', {'ledger_capacity': 100_000}, 1)['gate_sequence'], g)
        self.assertEqual(cd.declared_for('a03-lifetime', {'hold': False}, 1)['gate_sequence'], g)
        self.assertEqual(cd.declared_for('a04-regenesis', {'regen': False}, 1), {'gate_sequence': g, 'halt': False, 'order_fault': 0})
        d = cd.declared_block(cd.Ledger(), 0x99, **cd.declared_for('a04-regenesis', {}, 1))
        self.assertEqual((d['halt'], d['order_fault'], d['epochs']), (True, 1, [0x99]))

    def test_two_lives_each_reset_the_declared_block(self):
        """C4: a life-1 ledger with a healed regenesis row and a fresh life-2 ledger: each life declares from its own
        ledger and its own genesis id, never the other life's."""
        one, two = cd.Ledger(), cd.Ledger()
        row = one.open('regenesis', 'me')
        d1 = cd.declared_block(one, 0x11, **cd.declared_for('a04-regenesis', {}, 1))
        self.assertTrue(d1['fault_open'])
        one.heal(row, 'halt_barrier')
        d1 = cd.declared_block(one, 0x11, **cd.declared_for('a04-regenesis', {}, 1))
        d2 = cd.declared_block(two, 0x13, **cd.declared_for('a04-regenesis', {}, 2))
        self.assertEqual((d1['fault_open'], d1['epochs'], d2['fault_open'], d2['epochs']), (False, [0x11], False, [0x13]))


class LatencyTest(unittest.TestCase):
    """5.4 / 20.1 line 9: per-id first apply from the dispatch's cluster ms to the ME record-3 timestamp."""

    def journal(self):
        return [{'type': 'outcome', 'journal_seq': 1, 'command_id_high': 1, 'command_id_low': 0, 'timestamp': 1005},
                {'type': 'outcome', 'journal_seq': 2, 'command_id_high': 2, 'command_id_low': 0, 'timestamp': 1012},
                {'type': 'outcome', 'journal_seq': 3, 'command_id_high': 1, 'command_id_low': 0, 'timestamp': 1020}]

    def test_first_apply_skips_release_rows_and_backfilled_rows(self):
        """RED 6380b01: no latency_table. A RELEASE_ID row repeats its create's id after the outcome; matching it gives the
        negative values W0 saw (answers-14.2 item 6: 41 percent), so it never enters the table; backfill rows (seq null)
        have no dispatch time."""
        tap = [{'seq': 1, 'id_high': 1, 'id_low': 0, 'kind': 'CREATE', 'at_ms': 1001},
               {'seq': 2, 'id_high': 2, 'id_low': 0, 'kind': 'CREATE', 'at_ms': 1002},
               {'seq': 3, 'id_high': 1, 'id_low': 0, 'kind': 'RELEASE_ID', 'at_ms': 1030},
               {'seq': None, 'id_high': 3, 'id_low': 0, 'kind': 'CREATE', 'at_ms': None, 'source': 'backfill'}]
        table = cd.latency_table(tap, self.journal())
        self.assertEqual(table, [{'seq': 1, 'id': [1, 0], 'dispatch_ms': 1001, 'first_apply_ms': 1005, 'ms': 4},
                                 {'seq': 2, 'id': [2, 0], 'dispatch_ms': 1002, 'first_apply_ms': 1012, 'ms': 10}])

    def test_window_summaries_and_nearest_rank_percentiles(self):
        table = [{'dispatch_ms': 1000 + i, 'ms': i % 10} for i in range(1000)]
        out = cd.window_summaries(table, {'all': [(1000, 2000)], 'none': [(5000, 6000)], 'two': [(1000, 1010), (1990, 2000)]})
        self.assertEqual(out['all'], {'count': 1000, 'p50': 4, 'p99': 9, 'p99.9': 9, 'max': 9})
        self.assertEqual(out['none']['count'], 0)
        self.assertEqual(out['two']['count'], 20)

    def w(self, base_ms, swap_ms, windows_s=((30.0, 31.6), (50.0, 51.5))):
        t0 = 1_000_000
        table = [{'dispatch_ms': t0 + 10_000 + i * 10, 'ms': base_ms[i % len(base_ms)]} for i in range(2000)]
        swaps = []
        for n, (a, b) in enumerate(windows_s):
            table += [{'dispatch_ms': t0 + int(a * 1000) + i * 10, 'ms': swap_ms[i % len(swap_ms)]} for i in range(int((b - a) * 100))]
            swaps.append({'slot': f'fwd{n}', 'start_s': a, 'ready_s': b})
        return {'latency': table, 't0_ms': t0, 'swaps': swaps, 'settings': dict(cd.SETTINGS)}

    def test_no_delay_rule_a_and_its_n1_control(self):
        ok = cd.line_no_delay(self.w([3, 4, 12, 55], [3, 5, 14, 18]))
        self.assertTrue(ok['holds'], ok)
        slow = cd.line_no_delay(self.w([3, 4, 12, 55], [3, 400, 900, 1500]))     # a05-fwd-upgrade-n1: no survivor
        self.assertFalse(slow['holds'])
        self.assertFalse(slow.get('inconclusive'))
        empty = self.w([3], [3]); empty['latency'] = [r for r in empty['latency'] if r['dispatch_ms'] < 1_030_000]
        self.assertTrue(cd.line_no_delay(empty).get('inconclusive'))    # no swap-window row: a gap, never PASS


class A03LinesTest(unittest.TestCase):
    CAP = 2000

    def samples(self, peak=1600, after=0, reasons=16.0):
        rows = []
        for i, est in enumerate([0, 400, 800, 1200, peak, peak, after, after]):
            rows.append(S(100 + i, ae1=dict(lead('ae'), assets_me_capacity_estimate=float(est), assets_release_backlog=float(est),
                                            assets_order_entry_gate_reasons=reasons if est >= 0.8 * self.CAP else 0.0),
                          me0=dict(lead('me'), match_command_ledger_size=float(est))))
        return rows

    def w(self, **kw):
        admission = [{'market': 0, 'state': 'SUSPENDED', 'reason': 'GENESIS'}, {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN'},
                     {'market': 0, 'state': 'SUSPENDED', 'reason': 'ME_CAPACITY'}, {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN'}]
        tap = [{'seq': 10 + i, 'id_high': 100 + i, 'id_low': 0, 'kind': 'RELEASE_ID', 'at_ms': 1} for i in range(3)]
        journal = [{'type': 'outcome', 'journal_seq': 1}, release_event(900, [{'commandIdHigh': 100 + i, 'idLowFloor': 0,
                                                                                'removed': 600} for i in range(3)])]
        base = {'capacity': self.CAP, 'samples': self.samples(), 'admission': admission, 'tap_dispatch': tap,
                'me_journal': journal, 'order_terminals': 0,
                'hold': {'swap_me_seq': 500, 'swap_dispatch_seq': 20, 'backlog_at_swap': 1600, 'kill_in_closed_window': True,
                         'restarted': True},
                'a03': {'created': 1600, 'rejected_gate': 1400, 'cancelled': 0, 'reopen_acked': 1000, 'closed': True, 'opened': True},
                'snaps': {'before': scrape(me0={'match_durable_capacity_total': 0.0}),
                          'after': scrape(me0={'match_durable_capacity_total': 0.0})}}
        base.update(kw)
        return base

    def test_capacity_cycle_and_the_cap100k_control(self):
        """RED 6380b01: no line_capacity_cycle."""
        self.assertTrue(cd.line_capacity_cycle(self.w())['holds'])
        cap = self.w(capacity=100_000, samples=self.samples(peak=3000, after=0, reasons=0.0),
                     admission=self.w()['admission'][:2])
        line = cd.line_capacity_cycle(cap)
        self.assertFalse(line['holds'])
        self.assertIn('no close observed', json.dumps(line['detail']))

    def test_release_once_and_red_a03(self):
        self.assertTrue(cd.line_release_once(self.w())['holds'])
        red = cd.line_release_once(self.w(me_journal=[{'type': 'outcome', 'journal_seq': 1}]))
        self.assertFalse(red['holds'])
        self.assertIn('no release journaled', red['detail'])
        twice = self.w(); twice['me_journal'].append(release_event(901, [{'commandIdHigh': 100, 'idLowFloor': 0, 'removed': 1}]))
        self.assertFalse(cd.line_release_once(twice)['holds'])          # removed twice: applied more than once
        cap = self.w(snaps={'before': scrape(me0={'match_durable_capacity_total': 0.0}),
                            'after': scrape(me0={'match_durable_capacity_total': 2.0})})
        self.assertFalse(cd.line_release_once(cap)['holds'])

    def test_empty_sampler_series_is_inconclusive_never_fail(self):
        """V4. RED f42a1c6: capacity_cycle and release_once FAILed on a sampler that never answered."""
        dead = [S(100 + i, ae1={'unavailable': 'refused'}, me0={'unavailable': 'refused'}) for i in range(5)]
        for name in ('capacity_cycle', 'release_once'):
            line = cd.LINES[name](self.w(samples=dead))
            self.assertFalse(line['holds'], name)
            self.assertTrue(line.get('inconclusive'), (name, line))
        self.assertEqual(cd.verdict({'status': 'PASS', 'rules': {}}, {'status': 'PASS', 'rules': {}},
                                    {'capacity_cycle': cd.line_capacity_cycle(self.w(samples=[]))}, {})['status'], 'INCONCLUSIVE')

    def test_release_resent_and_the_nokill_control(self):
        self.assertTrue(cd.line_release_resent(self.w())['holds'])
        live = self.w(me_journal=[release_event(300, [{'commandIdHigh': 100 + i, 'idLowFloor': 0, 'removed': 1}
                                                      for i in range(3)])])     # a03-nokill: relayed live, inside W
        self.assertFalse(cd.line_release_resent(live)['holds'])
        first = self.w(me_journal=[release_event(500, [{'commandIdHigh': 100 + i, 'idLowFloor': 0, 'removed': 1} for i in range(3)])])
        self.assertTrue(cd.line_release_resent(first)['holds'])    # W5: swap_me_seq is the NEXT seq, so the first record after the swap is AT it
        before = self.w(me_journal=[release_event(499, [{'commandIdHigh': 100 + i, 'idLowFloor': 0, 'removed': 1} for i in range(3)])])
        self.assertFalse(cd.line_release_resent(before)['holds'])
        none = cd.line_release_resent(self.w(tap_dispatch=[]))
        self.assertTrue(none.get('inconclusive'), none)                          # no release in the window
        noswap = cd.line_release_resent(self.w(hold=None))
        self.assertTrue(noswap.get('inconclusive'), noswap)

    def test_reopen_admits_and_the_cap100k_control(self):
        self.assertTrue(cd.line_reopen_admits(self.w())['holds'])
        cap = self.w(a03=dict(self.w()['a03'], opened=False, closed=False, reopen_acked=1000),
                     hold=dict(self.w()['hold'], kill_in_closed_window=False))
        self.assertFalse(cd.line_reopen_admits(cap)['holds'])


class A04LinesTest(unittest.TestCase):
    G1 = 15112027

    def health(self, reason='SOURCE_SCHEMA', status=503, epoch=None):
        return (status, {'halted': reason != 'NONE', 'haltReason': reason, 'meEpoch': epoch or self.G1})

    def w(self, **kw):
        base = {'g1': self.G1,
                'bridge_health': {b: self.health() for b in cd.BRIDGES},
                'halt_scrape': scrape(bridge0={'bridge_halt_reason': 3.0}, bridge1={'bridge_halt_reason': 3.0},
                                      ae0=dict(lead('ae'), assets_feed_latch_reason=3.0)),
                'core': {'feed_halted': True, 'halt_reason': 'SOURCE_SCHEMA', 'bound_me_epoch': self.G1},
                'settle_rejected': 0,
                'open_gate': {'meaning': 'REFUSED', 'reply': {'replies': [{'t': 'AdminAck', 'result': 'REJECTED', 'reason': 40}]}},
                'life2_gate_open': True,
                'halt_funding': [{'kind': 'deposit', 'outcome': 'ACK', 'gate': 'SUSPENDED'}] * 4
                                + [{'kind': 'withdraw', 'outcome': 'ACK', 'gate': 'SUSPENDED'}] * 2,
                'halt_create': {'reply': {'outcome': 'REJECT', 'reason': 'GATE_CLOSED'}},
                'fence': {f: {'exit_code': 78, 'after_first_me_start_s': 3.7, 'reason': 'F8_EPOCH'} for f in cd.FORWARDERS}}
        base.update(kw)
        return base

    def test_halt_local_and_red_a04(self):
        """RED 6380b01: no line_halt_local."""
        self.assertTrue(cd.line_halt_local(self.w())['holds'])
        red = self.w(bridge_health={b: self.health('NONE', 200) for b in cd.BRIDGES},
                     halt_scrape=scrape(bridge0={'bridge_halt_reason': 0.0}, bridge1={'bridge_halt_reason': 0.0},
                                        ae0=dict(lead('ae'), assets_feed_latch_reason=0.0)),
                     core={'feed_halted': False, 'halt_reason': 'NONE', 'bound_me_epoch': self.G1})
        self.assertFalse(cd.line_halt_local(red)['holds'])
        mismatch = self.w(halt_scrape=scrape(bridge0={'bridge_halt_reason': 2.0}, bridge1={'bridge_halt_reason': 3.0},
                                             ae0=dict(lead('ae'), assets_feed_latch_reason=3.0)))
        self.assertFalse(cd.line_halt_local(mismatch)['holds'])          # EPOCH_MISMATCH is not the declared reason

    def test_open_refused_money_while_halted_fenced_and_the_noregen_control(self):
        w = self.w()
        for name in ('open_refused', 'money_while_halted', 'fenced_forwarders'):
            self.assertTrue(cd.LINES[name](w)['holds'], name)
        noregen = self.w(open_gate={'meaning': 'ANSWERED', 'reply': {'replies': [{'t': 'AdminAck', 'result': 'APPLIED'}]}},
                         halt_funding=[dict(r, gate='OPEN') for r in w['halt_funding']],
                         halt_create={'reply': {'outcome': 'ACK', 'order': 9}},
                         fence={f: {'exit_code': None, 'after_first_me_start_s': None, 'reason': None} for f in cd.FORWARDERS},
                         life2_gate_open=None)
        for name in ('open_refused', 'money_while_halted', 'fenced_forwarders'):
            self.assertFalse(cd.LINES[name](noregen)['holds'], name)
        late = self.w(fence=dict(w['fence'], fwd1={'exit_code': 78, 'after_first_me_start_s': 16.0, 'reason': 'F8_EPOCH'}))
        self.assertFalse(cd.line_fenced_forwarders(late)['holds'])

    def test_second_life_exact(self):
        g2 = self.G1 + 2
        good = {'life2': {'money': {'status': 'PASS'}, 'order': {'status': 'PASS'}, 'epochs': [g2], 'g2': g2,
                          'bound_me_epoch': g2, 'last_applied_trade_id': 40, 'max_epoch2_trade': 40}}
        self.assertTrue(cd.line_second_life_exact(good)['holds'])
        self.assertFalse(cd.line_second_life_exact({'life2': dict(good['life2'], bound_me_epoch=self.G1)})['holds'])
        self.assertTrue(cd.line_second_life_exact({'life2': None}).get('inconclusive'))
        # V8: the epochs are observed in the life-2 journal; a g1 record in it FAILs, none observed is INCONCLUSIVE
        self.assertFalse(cd.line_second_life_exact({'life2': dict(good['life2'], epochs=[self.G1, g2])})['holds'])
        self.assertTrue(cd.line_second_life_exact({'life2': dict(good['life2'], epochs=[])}).get('inconclusive'))

    # W5 w5-a04-one-bridge-halt: kill seq 7592, bridge0's sync cursor 9871 = skipped 9871, read at STREAMING last 10152
    GREEN = {'me_seq_at_kill': 7592.0, 'peer_cursor_at_restart': 9604, 'restart_after_kill_s': 5.492, 'skipped_delta': 9871.0,
             'health_first': {'cursor': 9871, 'expected': 9890, 'last': 9889, 'state': 'STREAMING'},
             'health_after': {'cursor': 9871, 'expected': 10153, 'last': 10152, 'state': 'STREAMING'}}

    def test_cold_restart_skips_reads_the_sync_cursor_not_the_live_position(self):
        """S16 fix round V5. RED f42a1c6: the W5 GREEN run FAILs (expected 10153 != cursor 9871 + 1): the report's C is
        the sync cursor, the bridge's live position ran on under load. The first forward is judged at the sync."""
        line = cd.line_cold_restart_skips({'cold': self.GREEN})
        self.assertTrue(line['holds'], line)
        self.assertEqual((line['detail']['start_cursor'], line['detail']['backlog']), (9871, 2279.0))
        # a cold read that forwarded at or below the cursor (skipped short of it) FAILs
        self.assertFalse(cd.line_cold_restart_skips({'cold': dict(self.GREEN, skipped_delta=9000.0)})['holds'])
        # not streaming from the cursor: expected != last + 1, or last below the sync cursor
        bad = dict(self.GREEN, health_first={'cursor': 9871, 'expected': 9870, 'last': 9870, 'state': 'STREAMING'})
        self.assertFalse(cd.line_cold_restart_skips({'cold': bad})['holds'])
        missing = cd.line_cold_restart_skips({'cold': dict(self.GREEN, health_first=None)})
        self.assertTrue(missing.get('inconclusive'))

    def test_earlyrestart_control_fails_clause_a_for_its_named_reason(self):
        """S16 fix round V2. W5 w5-ctl-a04-earlyrestart (no peer freeze): bridge1 streamed live, so bridge0's sync cursor
        9530 was 1938 past the kill seq after a 1.08 s restart: the redefined line HOLDS on it (an early restart alone
        does not show that timing matters). The control now freezes bridge1: the sync cursor sits at about the kill seq,
        bridge0 forwards the backlog itself, clause (a) FAILs with its reason."""
        unfrozen = dict(self.GREEN, peer_cursor_at_restart=None, restart_after_kill_s=1.078, skipped_delta=9530.0,
                        health_first={'cursor': 9530, 'expected': 9550, 'last': 9549, 'state': 'STREAMING'})
        self.assertTrue(cd.line_cold_restart_skips({'cold': unfrozen})['holds'])
        frozen = dict(unfrozen, skipped_delta=7580.0, me_seq_at_restart=8700.0, peer_paused_s=2.6, early=True,
                      health_first={'cursor': 7580, 'expected': 7901, 'last': 7900, 'state': 'STREAMING'})
        line = cd.line_cold_restart_skips({'cold': frozen})
        self.assertFalse(line['holds'])
        self.assertFalse(line.get('inconclusive'))
        self.assertEqual(line['detail']['clauses'], {'peer_delivered_backlog': False, 'skipped_to_cursor': True,
                                                     'streaming_from_cursor': True})
        self.assertIn('the peer had not delivered the backlog', line['detail']['why'])
        self.assertIn('bridge0 forwarded 320 records from 7581 itself', line['detail']['why'])

    def test_bridge_never_halted(self):
        rows = [S(1, bridge0={'bridge_halted': 0.0}, bridge1={'bridge_halted': 0.0})] * 3
        halted = {'samples': rows + [S(9, bridge0={'bridge_halted': 1.0}, bridge1={'bridge_halted': 0.0})]}
        self.assertFalse(cd.line_bridge_never_halted(halted)['holds'])
        self.assertTrue(cd.line_bridge_never_halted({'samples': rows})['holds'])
        empty = cd.line_bridge_never_halted({'samples': [S(1, bridge0={'unavailable': 0})]})
        self.assertTrue(empty.get('inconclusive'))                      # V4: no row is no witness, never a FAIL

    def test_open_refused_needs_the_life2_open(self):
        """V7. RED f42a1c6: life2_gate_open None held the line."""
        self.assertTrue(cd.line_open_refused(self.w())['holds'])
        pending = cd.line_open_refused(self.w(life2_gate_open=None))
        self.assertFalse(pending['holds']); self.assertTrue(pending.get('inconclusive'))
        closed = cd.line_open_refused(self.w(life2_gate_open=False))
        self.assertFalse(closed['holds']); self.assertFalse(closed.get('inconclusive'))
        noregen = cd.line_open_refused(self.w(open_gate={'meaning': 'ANSWERED', 'reply': {'replies': [{'result': 'APPLIED'}]}},
                                              life2_gate_open=None))
        self.assertFalse(noregen['holds']); self.assertFalse(noregen.get('inconclusive'))   # the control still FAILs

    def test_engine_polite_stop_after_w9(self):
        """Post-W9 polite stop (20.1 line 4, verifier note). W5: SIGTERM -> 143 in 0.17-0.29 s on all six engines."""
        stops = [{'kind': 'stop', 'target': f'me{i}', 'exit_code': 143, 'elapsed_s': t} for i, t in enumerate((0.286, 0.212, 0.283))]
        self.assertTrue(cd.line_engine_polite_stop({'engine_stops': stops})['holds'])
        hung = stops[:2] + [dict(stops[2], exit_code=137, elapsed_s=15.0)]     # pre-W9: escalated at the 15 s bound
        self.assertFalse(cd.line_engine_polite_stop({'engine_stops': hung})['holds'])
        slow = stops[:2] + [dict(stops[2], elapsed_s=cd.SETTINGS['ENGINE_SHUTDOWN_TIMEOUT_S'] + cd.SETTINGS['ENGINE_STOP_SLACK_S'] + 0.1)]
        self.assertFalse(cd.line_engine_polite_stop({'engine_stops': slow})['holds'])
        zero = stops[:2] + [dict(stops[2], exit_code=0)]
        self.assertFalse(cd.line_engine_polite_stop({'engine_stops': zero})['holds'])
        self.assertTrue(cd.line_engine_polite_stop({'engine_stops': []}).get('inconclusive'))
        faults = [{'kind': 'stop', 'target': 'bridge0', 'exit_code': 0}, stops[0], {'kind': 'kill', 'target': 'me1'}, stops[1]]
        self.assertEqual([x['target'] for x in cd.engine_stops(faults, 1)], ['me0', 'me1'])
        self.assertIn('engine_polite_stop', cd.DRILLS['a04-regenesis']['lines'])


class A05LinesTest(unittest.TestCase):
    B = 'b' * 40

    def swaps(self, kind='stop', build=None, ready_after_kill=1.1):
        out = []
        for n, (a, b) in enumerate(((30.0, 31.6), (50.0, 51.5))):
            out.append({'slot': f'fwd{n}', 'kind': kind, 'start_s': a, 'ready_s': b, 'pre_build': None,
                        'replace': {'old': {'sha256': next(iter(core_contracts.HEALTH_BUILD_ABSENT)),
                                            'source_sha': '2be3a1999ca193c0f37db7f6e460edd652c55fa1'},
                                    'new': {'sha256': 'c' * 64, 'source_sha': self.B}, 'build_health': build or self.B,
                                    'f7_rejected': 0, 'ready_after_kill_s': ready_after_kill if kind == 'kill' else None}})
        return out

    def progress(self, stall=None):
        rows, seq = [], 0
        for i in range(0, 400):
            t = 1000.0 + i * 0.25
            if not (stall and stall[0] <= t - 1000.0 < stall[1]):
                seq += 25
            rows.append(S(t, me0=dict(lead('me'), match_engine_next_journal_seq=float(seq),
                                      match_durable_duplicates_suppressed_total=float(seq // 2))))
        return rows

    def w(self, **kw):
        base = {'b_source_sha': self.B, 'swaps': self.swaps(), 't0_ms': 1_000_000, 'samples': self.progress(),
                'settings': dict(cd.SETTINGS), 'tap_dispatch': [], 'n': 2}
        base.update(kw)
        return base

    def test_build_witness_and_a_same_build_swap(self):
        self.assertTrue(cd.line_build_witness(self.w())['holds'])
        self.assertFalse(cd.line_build_witness(self.w(swaps=self.swaps(build='d' * 40)))['holds'])
        pre = self.swaps(); pre[0]['pre_build'] = self.B
        self.assertFalse(cd.line_build_witness(self.w(swaps=pre))['holds'])     # build A must not report build B
        self.assertFalse(cd.line_build_witness(self.w(swaps=self.swaps()[:1]))['holds'])

    def test_build_witness_judges_the_reverse_direction(self):
        """RC2 S17 W6 fix round item 3. RED 5d0339f: entries 22/23 (s17-a05-reverse, cut -> build A) FAIL build_witness 9/9:
        the line wanted 'no build before, build B after', but there the swapped-out cut binary reports its source sha and the
        swapped-in build A (ct 2be3a19) has no /health build field. Each side is judged by what its binary reports."""
        A = '2be3a1999ca193c0f37db7f6e460edd652c55fa1'                       # build A, ct 2be3a19 (S15 bin-s15)
        a_fwd = next(iter(core_contracts.HEALTH_BUILD_ABSENT))
        cut, cut_sha = 'e' * 40, 'f' * 64

        def rev(build=None, pre=cut, new_sha=a_fwd, old_sha=cut_sha, n=2):
            return [{'slot': f'fwd{i}', 'kind': 'stop', 'start_s': 30.0 + 20 * i, 'ready_s': 31.5 + 20 * i, 'pre_build': pre,
                     'replace': {'old': {'artifact': 'forwarder', 'sha256': old_sha, 'source_sha': cut},
                                 'new': {'artifact': 'forwarder_b', 'sha256': new_sha, 'source_sha': A},
                                 'build_health': build, 'f7_rejected': 0}} for i in range(n)]
        line = cd.line_build_witness(self.w(b_source_sha=A, swaps=rev()))
        self.assertTrue(line['holds'], line)
        refused = {'no swap: the cut binary still answers': rev(build=cut),
                   'build A does not report a build': rev(build=A),
                   'the swapped-out cut binary reported none': rev(pre=None),
                   'a swapped-in binary that is not the pinned build A': rev(new_sha='9' * 64),
                   'one swap only': rev(n=1),
                   'same bytes': rev(new_sha=cut_sha)}
        for why, swaps in refused.items():
            with self.subTest(refused=why):
                self.assertFalse(cd.line_build_witness(self.w(b_source_sha=A, swaps=swaps))['holds'])
        # the forward direction keeps its rule: build A before (no build field), build B after
        fwd = rev(build=self.B, pre=None)
        for s in fwd:
            s['replace']['old'], s['replace']['new'] = ({'artifact': 'forwarder', 'sha256': a_fwd, 'source_sha': A},
                                                        {'artifact': 'forwarder_b', 'sha256': cut_sha, 'source_sha': self.B})
        self.assertTrue(cd.line_build_witness(self.w(swaps=fwd))['holds'])
        fwd[0]['pre_build'] = A
        self.assertFalse(cd.line_build_witness(self.w(swaps=fwd))['holds'])

    def test_survivor_delivered_n1_control_and_a_vacuous_window(self):
        self.assertTrue(cd.line_survivor_delivered(self.w())['holds'])
        n1 = cd.line_survivor_delivered(self.w(samples=self.progress(stall=(30.0, 31.6))))
        self.assertFalse(n1['holds'])
        self.assertFalse(n1.get('inconclusive'))
        short = self.swaps(); short[0]['ready_s'] = 30.5
        self.assertTrue(cd.line_survivor_delivered(self.w(swaps=short)).get('inconclusive'))

    def test_dup_outcomes_counts_n_minus_1_per_dispatch_outside_the_windows(self):
        t0 = 1_000_000
        # 25 journal seqs per 0.25 s; duplicates half of them; dispatches: one command per 2 journal seqs => 50/s
        tap = [{'seq': i + 1, 'id_high': i + 1, 'id_low': 0, 'kind': 'CREATE', 'at_ms': t0 + i * 20} for i in range(5000)]
        w = self.w(tap_dispatch=tap)
        line = cd.line_dup_outcomes(w)
        self.assertTrue(line['holds'], line)
        n1 = self.w(tap_dispatch=tap, samples=[dict(s, roles={'me0': dict(s['roles']['me0'],
                    match_durable_duplicates_suppressed_total=min(s['roles']['me0']['match_durable_duplicates_suppressed_total'], 3000.0))})
                    for s in self.progress()])
        self.assertFalse(cd.line_dup_outcomes(n1)['holds'])          # N = 1 after the stop: no duplicates

    def test_dup_outcomes_slack_default_and_an_unsampled_edge(self):
        """13: W5 measured duplicates - dispatches = -1 (2059 vs 2060, 3129 vs 3130); the default slack is 10, a setting.
        V4: a window edge with no sampler row is INCONCLUSIVE, never FAIL."""
        self.assertEqual(cd.SETTINGS['A05_DUP_EDGE_SLACK'], 10)
        t0 = 1_000_000
        tap = [{'seq': i + 1, 'id_high': i + 1, 'id_low': 0, 'kind': 'CREATE', 'at_ms': t0 + i * 20} for i in range(5000)]
        line = cd.line_dup_outcomes(self.w(tap_dispatch=tap, samples=[]))
        self.assertFalse(line['holds']); self.assertTrue(line.get('inconclusive'))
        off = [dict(s, roles={'me0': dict(s['roles']['me0'], match_durable_duplicates_suppressed_total=
                                          s['roles']['me0']['match_durable_duplicates_suppressed_total'] + (15 if s['t0'] >= 1070 else 0))})
               for s in self.progress()]
        self.assertFalse(cd.line_dup_outcomes(self.w(tap_dispatch=tap, samples=off))['holds'])   # 15 off > 10

    def test_n1_hold_makes_the_controls_gap_exceed_the_slack(self):
        """V3 / fix round: W5 n1 windows were 1.08-1.3 s (survivor gap 0.76 s < 1.0 s; settle lag 51 vs 5 + 40). With the
        single slot held A05_N1_HOLD_S the window is >= 5 s: no progress for 5 s FAILs survivor_delivered and the lag of a
        5 s settlement stop FAILs settle_no_gap by far more than the slack."""
        hold = cd.SETTINGS['A05_N1_HOLD_S']
        self.assertGreaterEqual(hold, 3 * cd.SETTINGS['SURVIVOR_MAX_GAP_S'])
        swaps = self.swaps()[:1]; swaps[0]['ready_s'] = 30.0 + hold + 1.1
        line = cd.line_survivor_delivered(self.w(swaps=swaps, samples=self.progress(stall=(30.1, 30.0 + hold + 1.05))))
        self.assertFalse(line['holds']); self.assertFalse(line.get('inconclusive'))
        self.assertGreater(line['detail'][0]['max_gap_s'], 3 * cd.SETTINGS['SURVIVOR_MAX_GAP_S'])

        def lag_rows(lo, hi, rate=40):
            rows = []
            for i in range(400):
                t = 1000.0 + i * 0.25
                lag = 4 if not (lo <= t - 1000.0 < hi) else 4 + int(rate * (t - 1000.0 - lo))
                rows.append(S(t, me0=dict(lead('me'), match_trades_total=float(1000 + i)),
                              ae0=dict(lead('ae'), assets_last_applied_trade_id=float(1000 + i - lag))))
            return rows
        bswaps = [dict(swaps[0], slot='bridge0')]
        line = cd.line_settle_no_gap(self.w(swaps=bswaps, samples=lag_rows(30.0, 30.0 + hold + 1.1)))
        self.assertFalse(line['holds'])
        self.assertGreater(line['detail']['swaps'][0]['max_lag'], 4 * (4 + cd.SETTINGS['A05_SETTLE_LAG_SLACK']))

    def test_ready_after_kill_bound(self):
        self.assertTrue(cd.line_ready_after_kill(self.w(swaps=self.swaps('kill')))['holds'])
        self.assertFalse(cd.line_ready_after_kill(self.w(swaps=self.swaps('kill', ready_after_kill=7.0)))['holds'])
        self.assertFalse(cd.line_ready_after_kill(self.w(swaps=self.swaps('stop')))['holds'])

    def test_settle_no_gap_and_the_bridge_n1_control(self):
        def lag_rows(spike):
            rows = []
            for i in range(400):
                t = 1000.0 + i * 0.25
                lag = 30 if not (30.0 <= t - 1000.0 < 31.6) else spike
                rows.append(S(t, me0=dict(lead('me'), match_trades_total=float(1000 + i)),
                              ae0=dict(lead('ae'), assets_last_applied_trade_id=float(1000 + i - lag))))
            return rows
        swaps = [dict(s, slot=s['slot'].replace('fwd', 'bridge')) for s in self.swaps()]
        self.assertTrue(cd.line_settle_no_gap(self.w(swaps=swaps, samples=lag_rows(40)))['holds'])
        self.assertFalse(cd.line_settle_no_gap(self.w(swaps=swaps, samples=lag_rows(400)))['holds'])


class A06LinesTest(unittest.TestCase):
    def fwd(self, offered, version=3185472, age=0.0, ready=1.0):
        return {'forwarder_tick_offered_total{market="1",edge="trailing"}': float(offered),
                'forwarder_tick_last_offered_version{market="1"}': float(version),
                'forwarder_tick_pending_age_ms{market="1"}': age, 'forwarder_ticks_ready': ready}

    def core(self, applied, stale, version=3185472, leader=True):
        return dict(lead('ae', 2.0 if leader else 1.0), assets_ticks_applied_total=float(applied),
                    assets_ticks_stale_total=float(stale), assets_ticks_invalid_total=0.0, assets_ticks_epoch_drop_total=0.0,
                    assets_ticks_unbound_total=0.0, **{'assets_market_book_version{market="1"}': float(version),
                                                       'assets_market_best_bid{market="1"}': 8057000000.0,
                                                       'assets_market_best_ask{market="1"}': 9787000000.0})

    def w(self, **kw):
        """The DR-A06 counters (a06.log): fwd0 291 at t29, 301 just before the kill, 147 after its restart; fwd1 601."""
        base = {'snaps': {'before': scrape(ae2=self.core(0, 0), fwd0=self.fwd(0), fwd1=self.fwd(0)),
                          't29': scrape(ae2=self.core(321, 273), fwd0=self.fwd(291), fwd1=self.fwd(291)),
                          'prekill': scrape(ae2=self.core(330, 274), fwd0=self.fwd(301), fwd1=self.fwd(300)),
                          'core_prekill': scrape(ae2=self.core(330, 274)), 'core_postkill': scrape(ae2=self.core(340, 276)),
                          'after': scrape(ae2=self.core(770, 279), fwd0=self.fwd(147), fwd1=self.fwd(601))},
                'forwarders': ['fwd0', 'fwd1'], 'ae_leaders': ['ae2', 'ae2', 'ae2'],
                'book': {1: {'version': 3185472, 'bid': 8057000000, 'ask': 9787000000}, 2: None, 3: None, 4: None, 5: None},
                'kill_window': {'kill_s': 30.0, 'restart_begin_s': 45.0, 'restart_s': 46.2}, 'settings': dict(cd.SETTINGS),
                'samples': [S(1000.0 + t, ae2=self.core(330 + 10 * t, 274)) for t in range(25, 50)], 't0_s': 1000.0}
        base.update(kw)
        return base

    def test_tick_conservation_with_the_in_flight_slack(self):
        """offered 301 + 147 + (601 - 0) = 1049, lost slack = 301 - 291 = 10 offers in fwd0's last second; core 770 + 279 =
        1049; the kill gap's core count (340 + 276) - (330 + 274) = 12 bounds fwd0's unscraped last offers."""
        line = cd.line_tick_conservation(self.w())
        self.assertTrue(line['holds'], line)
        self.assertEqual((line['detail']['lost_slack'], line['detail']['kill_gap_core_count']), (10, 12))
        moved = self.w(ae_leaders=['ae2', 'ae1', 'ae1'])
        self.assertFalse(cd.line_tick_conservation(moved)['holds'])      # node-local counters across a leader change
        over = self.w(); over['snaps']['after']['ae2'] = self.core(900, 279)
        self.assertFalse(cd.line_tick_conservation(over)['holds'])
        unscraped = self.w(); del unscraped['snaps']['core_postkill']
        self.assertTrue(cd.line_tick_conservation(unscraped).get('inconclusive'))

    def test_tick_conservation_bounds_offers_made_between_the_last_scrape_and_the_kill(self):
        """Fix round, W5 w5-ctl-a06-n1: fwd0 alone; t29 299, prekill 300, after the restart 147: offered 447; the core
        applied 449 (fwd0 offered 2 more between its pre-kill scrape and the SIGKILL). RED f42a1c6: 449 > 447 + 1 FAIL.
        The AE leader read 300 just before the pre-kill scrape and 302 a settle after the kill: the bound is 2."""
        def fwd(n):
            return {'forwarder_tick_offered_total{market="1",edge="leading"}': 1.0,
                    'forwarder_tick_offered_total{market="1",edge="trailing"}': float(n - 1),
                    'forwarder_tick_pending_age_ms{market="1"}': 0.0, 'forwarder_ticks_ready': 1.0}
        w = self.w(forwarders=['fwd0'])
        w['snaps'] = {'before': scrape(ae2=self.core(0, 0)), 't29': scrape(ae2=self.core(293, 0), fwd0=fwd(299)),
                      'prekill': scrape(fwd0=fwd(300)), 'core_prekill': scrape(ae2=self.core(300, 0)),
                      'core_postkill': scrape(ae2=self.core(302, 0)), 'after': scrape(ae2=self.core(449, 0), fwd0=fwd(147))}
        line = cd.line_tick_conservation(w)
        self.assertTrue(line['holds'], line)
        self.assertEqual((line['detail']['offered'], line['detail']['core'], line['detail']['kill_gap_core_count']), (447.0, 449.0, 2.0))
        w['snaps']['after']['ae2'] = self.core(452, 0)                      # 3 more than any scrape bounds
        self.assertFalse(cd.line_tick_conservation(w)['holds'])

    def test_stale_positive_survivor_end_state_invalid_and_the_n1_control(self):
        w = self.w()
        for name in ('tick_stale_positive', 'tick_survivor', 'tick_end_state', 'tick_invalid_zero'):
            self.assertTrue(cd.LINES[name](w)['holds'], (name, cd.LINES[name](w)))
        n1 = self.w(forwarders=['fwd0'], samples=[S(1000.0 + t, ae2=self.core(330, 274)) for t in range(25, 50)])
        n1['snaps']['after']['ae2'] = self.core(770, 0)
        n1['snaps']['before']['ae2'] = self.core(0, 0)
        self.assertFalse(cd.line_tick_stale_positive(n1)['holds'])
        self.assertFalse(cd.line_tick_survivor(n1)['holds'])
        self.assertFalse(cd.line_tick_survivor(n1).get('inconclusive'))
        wrong = self.w(book={1: {'version': 3185472, 'bid': 8000000000, 'ask': 9787000000}, 2: None, 3: None, 4: None, 5: None})
        self.assertFalse(cd.line_tick_end_state(wrong)['holds'])

    def test_tick_survivor_counts_rises_inside_the_dead_window_only(self):
        """Fix round, W5 w5-ctl-a06-n1 (applied: 296 at 29.6, 302 at 30.6 then flat, 304 at 45.6 as the restarted fwd0
        offered before its /ready returned at 46.158): RED f42a1c6 counted 2 rises in [kill, restart_s] with no survivor.
        The window is [kill + TICK_SETTLE_S, restart issued] and a rise needs two rows inside it."""
        series = [(25.584, 256), (26.584, 266), (27.592, 276), (28.586, 286), (29.592, 296), (30.585, 302)] + \
                 [(31.585 + i, 302) for i in range(14)] + [(45.607, 304), (46.586, 314), (47.585, 324)]
        samples = [S(1000.0 + t, ae2=dict(lead('ae'), assets_ticks_applied_total=float(v))) for t, v in series]
        n1 = self.w(samples=samples, kill_window={'kill_s': 30.298, 'restart_begin_s': 45.01, 'restart_s': 46.158})
        line = cd.line_tick_survivor(n1)
        self.assertFalse(line['holds'], line)
        self.assertEqual(line['detail']['applied_rises_while_fwd0_down'], 0)
        old = cd.progress(cd.series(samples, 'ae', 'assets_ticks_applied_total'), 1030.298, 1046.158)[0]
        self.assertEqual(len(old), 2)                                    # what W5 counted: the pre-kill commit and the restart
        unbracketed = cd.line_tick_survivor(self.w(kill_window={'kill_s': 30.0, 'restart_s': 45.0}))
        self.assertTrue(unbracketed.get('inconclusive'))
        empty = cd.line_tick_survivor(self.w(samples=[]))
        self.assertTrue(empty.get('inconclusive'))                       # V4

    def test_book_lines_parse(self):
        out = 'BOOK market=1 version=3185472 bid=8057000000 ask=9787000000 bids=3 asks=7 blocks=20/20\nBOOK market=2 none\n'
        self.assertEqual(cd.parse_book(out), {1: {'version': 3185472, 'bid': 8057000000, 'ask': 9787000000}, 2: None})


class FwdringLinesTest(unittest.TestCase):
    def ledger(self, branch='none', reconnect=0.0, last_sent_after=5000, pause=True):
        ledger = cd.Ledger()
        for n, (lo, hi) in enumerate(((100, 400), (900, 1300))):
            witness = {'me_seq_pause': lo, 'me_seq_thaw': hi, 'last_sent_before': 1000 * (n + 1), 'thaw_ms': 2000 + n * 10_000}
            if not pause:
                ledger.skip('pause', 'fwd0', 'control fwdring-nopause (8.4)', witness=witness)
                continue
            row = ledger.open('pause', 'fwd0', witness)
            ledger.heal(row, branch, {'reconnect_delta_by_cluster': {'core': reconnect, 'me': reconnect},
                                      'last_sent_after': last_sent_after + n * 10_000})
        return ledger

    def w(self, ledger, released=(3, 4)):
        tap = [{'seq': s, 'at_ms': 1990 + (s % 2) * 10_000, 'kind': 'CREATE'} for s in (900, 4000)]
        return {'ledger': ledger.rows, 'tap_dispatch': tap, 'released_after_thaw': list(released) if released is not None else None}

    def test_ring_outlived_thaw_and_its_controls(self):
        """RED 6380b01: no line_ring_outlived_thaw."""
        self.assertTrue(cd.line_ring_outlived_thaw(self.w(self.ledger()))['holds'])
        self.assertFalse(cd.line_ring_outlived_thaw(self.w(self.ledger(branch='A')))['holds'])          # fwdring-pause15
        self.assertFalse(cd.line_ring_outlived_thaw(self.w(self.ledger(reconnect=1.0, branch='B')))['holds'])
        self.assertFalse(cd.line_ring_outlived_thaw(self.w(self.ledger(pause=False)))['holds'])        # fwdring-nopause
        self.assertFalse(cd.line_ring_outlived_thaw(self.w(self.ledger(last_sent_after=100)))['holds'])

    def test_released_after_thaw_is_a_line_and_none_is_inconclusive(self):
        self.assertTrue(cd.line_released_after_thaw(self.w(self.ledger()))['holds'])
        self.assertFalse(cd.line_released_after_thaw(self.w(self.ledger(), released=(3, 0)))['holds'])
        self.assertTrue(cd.line_released_after_thaw(self.w(self.ledger(), released=None)).get('inconclusive'))

    def test_released_after_thaw_counts_bracketed_skip_rows(self):
        """fwdring-nopause records two bracketed rows without a pause: released_after_thaw reads them (it returns counts,
        never None), so the control FAILs on data rather than on a missing bracket."""
        ledger = self.ledger(pause=False)
        model = types.SimpleNamespace(journal=[], released_repeats=[])
        self.assertEqual(cd.released_after_thaw(model, ledger.rows), [0, 0])


class EngineDriverLinesTest(unittest.TestCase):
    def kills(self, codes=(1, 1, 1), after=(14.2, 13.9, 15.1)):
        rows = []
        for n, (target, code, s) in enumerate(zip(('ae1', 'ae1', 'me0'), codes, after)):
            rows.append({'target': target, 'role': 'me_leader' if target == 'me0' else 'ae_follower', 'kill_s': 15.0 + 25 * n,
                         'exit_code': code, 'exit_after_s': s, 'identity_before': {'cnc_mtime': str(n)},
                         'restart': {'driver': {'old': {'cnc_mtime': str(n)}, 'new': {'cnc_mtime': str(n + 1)}}},
                         'ready_s': 15.0 + 25 * n + s + 13.0, 'ready_during_grace': [200, 503]})
        return rows

    def test_driver_death_loud_and_exit_zero_is_a_fail(self):
        """RED 6380b01: no line_driver_death_loud. 20.1 line 5: W9 makes driver death exit 1; DR-0 saw the AE exit 0."""
        self.assertTrue(cd.line_driver_death_loud({'kills': self.kills()})['holds'])
        zero = cd.line_driver_death_loud({'kills': self.kills(codes=(0, 1, 1))})
        self.assertFalse(zero['holds'])
        self.assertIn('X6', json.dumps(zero['detail']))
        self.assertFalse(cd.line_driver_death_loud({'kills': self.kills(after=(14.2, 19.0, 15.1))})['holds'])
        self.assertFalse(cd.line_driver_death_loud({'kills': self.kills()[:2]})['holds'])            # edk-nokill: fewer kills
        rows = self.kills(); rows[1]['identity_before'] = {'cnc_mtime': 'stale'}
        self.assertFalse(cd.line_driver_death_loud({'kills': rows})['holds'])       # the second kill missed the new driver

    def test_cluster_served(self):
        samples = [S(1000.0 + i * 0.5, me1=dict(lead('me'), match_engine_next_journal_seq=float(i * 10))) for i in range(200)]
        w = {'kills': self.kills(), 'samples': samples, 't0_s': 1000.0,
             'election': {'killed': 'me0', 'new_leader': 'me1'}, 'story_unresolved': 0}
        self.assertTrue(cd.line_cluster_served(w)['holds'], cd.line_cluster_served(w))
        stalled = [S(1000.0 + i * 0.5, me1=dict(lead('me'), match_engine_next_journal_seq=float(min(i, 40) * 10))) for i in range(200)]
        self.assertFalse(cd.line_cluster_served(dict(w, samples=stalled))['holds'])
        self.assertFalse(cd.line_cluster_served(dict(w, kills=[]))['holds'])                        # edk-nokill
        unsampled = cd.line_cluster_served(dict(w, samples=[]))
        self.assertFalse(unsampled['holds']); self.assertTrue(unsampled.get('inconclusive'))          # V4

    def test_cnc_timeout_loud(self):
        good = {'cnc': {m: {'exit_code': 1, 'exit_after_s': 31.0, 'ready_200_seen': False} for m in ('ae0', 'me0')}}
        self.assertTrue(cd.line_cnc_timeout_loud(good)['holds'])
        hang = {'cnc': {m: {'exit_code': None, 'exit_after_s': None, 'ready_200_seen': False} for m in ('ae0', 'me0')}}
        self.assertFalse(cd.line_cnc_timeout_loud(hang)['holds'])                  # 20.1 line 5: a hang before W9
        untimed = {'cnc': {'ae0': {'exit_code': 1, 'exit_after_s': None, 'ready_200_seen': False}}}
        self.assertTrue(cd.line_cnc_timeout_loud(untimed).get('inconclusive'))

    def test_cnc_exit_timing_counts_from_the_engine_driver_wait(self):
        """V10. RED f42a1c6: W5 measured from the harness's spawn loop (35.9 s and 34.8 s against 35): the container
        create, the JVM start and the 0.5 s polling were inside the bound. Now FinishedAt minus the docker timestamp of
        the engine's own 'Driver mode EXTERNAL: connecting' line; the process start if the line is absent."""
        logs = ('2026-11-03T11:00:00.100000000Z starting\n'
                '2026-11-03T11:00:01.900000000Z INFO Driver mode EXTERNAL: connecting to media driver at /dev/shm/aeron-ae0\n')
        f = types.SimpleNamespace(command=lambda argv, check=True: types.SimpleNamespace(stdout=logs, stderr=''))
        state = {'StartedAt': '2026-11-03T11:00:00.000000000Z', 'FinishedAt': '2026-11-03T11:00:32.050000000Z'}
        self.assertEqual(cd.cnc_exit_timing(f, 'c-ae0', state), {'exit_after_s': 30.15, 'measured_from': 'driver_wait_log'})
        bare = types.SimpleNamespace(command=lambda argv, check=True: types.SimpleNamespace(stdout='', stderr='boom\n'))
        self.assertEqual(cd.cnc_exit_timing(bare, 'c-ae0', state), {'exit_after_s': 32.05, 'measured_from': 'process_start'})
        self.assertEqual(cd.SETTINGS['CNC_TIMEOUT_BOUND_S'], 35)


class S16RedVerdictTest(unittest.TestCase):
    def order(self, detail, status='FAIL'):
        return {'status': status, 'rules': {'O12': {'status': status, 'detail': detail}}}

    def test_red_a03_needs_the_three_step_text_and_a_full_ledger(self):
        """RED 6380b01: red_verdict has no red-a03 kind (it falls through to the RED-2 rules)."""
        money = {'status': 'PASS', 'rules': {}}
        text = ("gate transitions [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN'], ['SUSPENDED', 'ME_CAPACITY']] != declared "
                "[['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN'], ['SUSPENDED', 'ME_CAPACITY'], ['OPEN', 'ADMIN']]")
        pre = {'fwd0_running_health_200': True, 'fwd1_running_health_200': True, 'ledger_still_full': True}
        self.assertEqual(cd.red_verdict('red-a03', money, self.order(text), pre)['red'], 'RED')
        self.assertEqual(cd.red_verdict('red-a03', money, self.order(text), dict(pre, ledger_still_full=False))['status'],
                         'INCONCLUSIVE')
        green = cd.red_verdict('red-a03', money, {'status': 'PASS', 'rules': {'O12': {'status': 'PASS'}}}, pre)
        self.assertEqual((green['status'], green['red']), ('FAIL', 'GREEN'))

    def test_red_a04_needs_the_two_step_text_skips_and_no_halt(self):
        money = {'status': 'PASS', 'rules': {}}
        text = ("gate transitions [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']] != declared [['SUSPENDED', 'GENESIS'], "
                "['OPEN', 'ADMIN'], ['SUSPENDED', 'BRIDGE_HALT']]")
        pre = {'bridge0_running_health': True, 'bridge1_running_health': True, 'bridges_not_halted': True,
               'bridge0_skipped': True, 'bridge1_skipped': True, 'settle_rejected_0': True, 'order_fault_0': True,
               'feed_not_halted': True}
        self.assertEqual(cd.red_verdict('red-a04', money, self.order(text), pre)['red'], 'RED')
        crash = cd.red_verdict('red-a04', money, self.order(text), dict(pre, bridge0_skipped=False))
        self.assertEqual(crash['status'], 'INCONCLUSIVE')       # the skip is the mechanism: without it the RED is not shown
        halted = cd.red_verdict('red-a04', money, self.order(text.replace("['OPEN', 'ADMIN']] !=", "['OPEN', 'ADMIN'], "
                                                                          "['SUSPENDED', 'BRIDGE_HALT']] !=")), pre)
        self.assertNotEqual(halted['red'], 'RED')


class ObserveLife1Test(unittest.TestCase):
    """5.4 / R6: life 1's ME evidence comes from the pre-wipe freeze; the fresh ME is never asked."""

    def fixture(self):
        calls = []

        def me(*a, **k):
            raise AssertionError('the ME was queried after the wipe')
        money = {'balances': [], 'holds': [], 'lastAppliedTradeId': 12, 'meEpoch': 15112027, 'lastAppliedJournalSeq': 7505,
                 'feedHalted': True, 'haltReason': 'SOURCE_SCHEMA'}
        replies = {'money-dump': money, 'order-dump': {'orders': []}, 'pending-dump': {'count': 0, 'head': 9, 'entries': []}}
        metrics = {'assets_settle_faults_total': 0.0, 'assets_settle_rejects_total': 0.0, 'assets_cluster_role': 2.0,
                   **{m: 0.0 for m in core_scenarios.COUNTER_METRICS.values()}}
        f = types.SimpleNamespace(m={'ports': {'ae_metrics': 9, 'me_metrics': 8, 'forwarder_http': 7, 'bridge_http': 6},
                                     'me_journal_profile': 'me-journal-4'}, slots={},
                                  core=lambda verb, principal, **kw: ('ANSWERED', replies[verb]),
                                  journal_dump=me, me_open_legs=me,
                                  metrics=lambda role, port: me() if role.startswith('me') else
                                  dict(metrics, assets_cluster_role=2.0 if role == 'ae0' else 1.0))
        f.psql = lambda db, sql: '[]'
        return f, calls

    def test_observe_life1_never_queries_the_me_after_the_wipe(self):
        """RED 6380b01: observe() has no frozen evidence and calls journal_dump / me_open_legs on the fresh ME."""
        f, _ = self.fixture()
        frozen = {'me_journal': [{'type': 'engine_config', 'journal_seq': 1, 'me_epoch': 15112027}], 'me_journal_seq': True,
                  'me_open_legs': [], 'scrape_me': {'me0': {'match_cluster_role': 2.0}}}
        obs = core_scenarios.observe(f, frozen=frozen)
        self.assertEqual(obs['me_journal'], frozen['me_journal'])
        self.assertEqual(obs['scrape']['me0'], {'match_cluster_role': 2.0})

    def test_observe_maps_the_v7_halt_fields(self):
        f, _ = self.fixture()
        obs = core_scenarios.observe(f, frozen={'me_journal': [], 'me_journal_seq': True, 'me_open_legs': [], 'scrape_me': {}})
        core = obs['core']
        self.assertEqual((core['bound_me_epoch'], core['feed_cursor'], core['feed_halted'], core['halt_reason']),
                         (15112027, 7505, True, 'SOURCE_SCHEMA'))


class MemberEpochsTest(unittest.TestCase):
    def test_two_lives_with_overlapping_seqs_stay_apart(self):
        """5.4: the merge keys on (me_epoch, journal_seq). RED 6380b01: Violation "journalSeq 1 differs between two
        recordings" (a life-2 seq 1 merged onto life 1's seq 1)."""
        events = [{'type': 'engine_config', 'journal_seq': 1, 'me_epoch': 11, 'recording': 0},
                  {'type': 'outcome', 'journal_seq': 2, 'me_epoch': 11, 'recording': 0},
                  {'type': 'engine_config', 'journal_seq': 1, 'me_epoch': 13, 'recording': 1, 'ledger_capacity': 9},
                  {'type': 'outcome', 'journal_seq': 2, 'me_epoch': 11, 'recording': 1}]
        merged = core_scenarios.merge_member_lives(events, True)
        self.assertEqual([(e['me_epoch'], e['journal_seq']) for e in merged], [(11, 1), (11, 2), (13, 1)])


class SamplerTest(unittest.TestCase):
    def test_sampler_rows_from_one_probe_exec(self):
        """RED 6380b01: no Sampler. One probe exec per tick reads every target; a target that does not answer is
        'unavailable' in that row, never a crash, and only the wanted names are kept."""
        out = json.dumps({'ae0': {'status': 200, 'body': 'assets_cluster_role 2\nassets_release_backlog 4\nother 1\n'},
                          'me0': {'status': 0, 'error': 'refused'}})
        row = cd.Sampler.parse(out, {'ae0': ('assets_cluster_role', 'assets_release_backlog'), 'me0': ('match_trades_total',)},
                               10.0, 10.2)
        self.assertEqual(row['roles']['ae0'], {'assets_cluster_role': 2.0, 'assets_release_backlog': 4.0})
        self.assertIn('unavailable', row['roles']['me0'])
        self.assertEqual(cd.s_value(row, 'ae', 'assets_release_backlog'), 4.0)       # leader resolution inside one row


class RunA04OrderTest(unittest.TestCase):
    """V1: life 1's evidence is written when life 1 ends (before regenesis('core')), then overwritten by the final verdict.
    RED f42a1c6: the only life-1 write came after life 2 (finish_life(life1) after judge_life(2))."""

    def test_life1_evidence_is_on_disk_before_the_core_is_wiped(self):
        events = []
        g1, g2 = 0x11, 0x13
        faults = []

        def regenesis(plan, scope):
            events.append(('regenesis', scope))
            target = 'me' if scope == 'me' else 'ae'
            faults.extend({'kind': 'stop', 'target': f'{target}{i}', 'exit_code': 143, 'elapsed_s': 0.2} for i in range(3))
            return {'kind': 'regenesis', 'scope': scope}
        fx = types.SimpleNamespace(registry={'faults': faults, 'containers': {}}, start=lambda plan: None,
                                   start_story=lambda args, name=None: {}, regenesis=regenesis,
                                   genesis_id=lambda life: hex(g1 if life == 1 else g2), tap_gate=lambda m: {'state': 'OPEN'},
                                   journal_dump=lambda m: ['{}'])
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.f, run.name, run.spec, run.variant, run.red, run.seed = fx, 'a04-regenesis', cd.DRILLS['a04-regenesis'], {}, None, 1
        run.ledger, run.snaps, run.removed, run.restarted, run.extra = cd.Ledger(), {}, set(), set(), {}
        import tempfile
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        run.out = Path(tmp.name)
        run.snap = lambda label, skip_me=False: run.snaps.setdefault(label, {})
        run.start_sampler = run.stop_sampler = run.post_load = lambda *a: None
        run.story_args = lambda: {}
        run.story_name = 'story'
        run.wait_marker = lambda name, bound: {'at_ns': 0}
        run.wait_story = lambda: {'line': {}, 'summary': {}}
        run.pre_barrier = lambda: {}
        run.freeze_me = lambda: {'scrape_me': {}}
        run.state = lambda role: {'StartedAt': '1970-01-01T00:00:01Z'}
        run.wait_fenced = lambda ns: {}
        run.wait_bridges_halted = lambda: {}
        run.halt_actions = lambda: {'open_gate': {'meaning': 'REFUSED', 'reply': {'replies': [{'result': 'REJECTED'}]}}}
        run.health_of = lambda role: (503, {})
        ok = {'status': 'PASS', 'rules': {}}

        def judge_life(life, story, pre, out):
            events.append(('judge', life))
            journal = [{'type': 'engine_config', 'journal_seq': 1, 'me_epoch': g1 if life == 1 else g2}]
            sample = {'core': {'bound_me_epoch': g2, 'last_applied_trade_id': 0}, 'faults': {'settle_rejected': 0},
                      'me_journal': journal, 'declared': {'epochs': [g2], 'fault_open': False}}
            return {'sample': sample, 'money': ok, 'order': ok, 'w': {}, 'after': {}, 'tap_summary': {}, 'story': story, 'out': out}
        run.judge_life = judge_life
        run.decide = lambda money, order, lines, rows, sample, after: {'status': 'PASS', 'reasons': [], 'oracle_status': {},
                                                                      'lines': {k: v['holds'] for k, v in lines.items()}}
        run.finish_life = lambda life, lines, rows, result: events.append(('write', str(life['out'].name), bool(result.get('provisional')),
                                                                         lines.get('open_refused', {}).get('inconclusive')))
        line = lambda w: cd._line(True, '')
        with mock.patch.dict(cd.LINES, {n: line for n in ('halt_local', 'money_while_halted', 'fenced_forwarders', 'fault_cycles')}), \
                mock.patch.object(cd, 'of_rows', lambda *a, **k: {}), \
                mock.patch.object(cd, 'verdict', lambda *a, **k: {'status': 'PASS', 'reasons': []}):
            result = run.run_a04()
        core = events.index(('regenesis', 'core'))
        first_write = events.index(('write', 'life-1', True, True))       # provisional, open_refused pending life 2
        self.assertLess(first_write, core)
        self.assertGreater(events.index(('write', 'life-1', False, None)), core)    # the final life-1 write
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['lines']['open_refused'])                 # life 2's OPEN observed: no longer pending
        self.assertTrue(result['lines']['engine_polite_stop'])
        self.assertTrue(result['lives']['2']['lines']['engine_polite_stop'])
        self.assertTrue(result['lines']['life2.engine_polite_stop'])       # verdict() returns no 'lines': merged from lines2


class SamplerWatcherTest(unittest.TestCase):
    def test_a_watcher_exception_is_recorded_and_makes_a_pass_inconclusive(self):
        """V13. RED f42a1c6: the GateWatcher's exception went to the sampler's generic errors and the run PASSed."""
        def boom(row):
            raise KeyError('state')
        sampler = cd.Sampler.__new__(cd.Sampler)
        sampler.on_tick, sampler.rows, sampler.errors, sampler.watcher_errors = boom, [], [], []
        sampler.urls, sampler.wanted = {}, {}
        with mock.patch('subprocess.run', lambda *a, **k: types.SimpleNamespace(stdout='{}')):
            row = sampler.tick('c-probe')
        self.assertEqual(sampler.rows, [row])                          # the row is kept
        self.assertEqual(sampler.watcher_errors, ["KeyError('state')"])
        v = cd.with_watcher_errors({'status': 'PASS', 'reasons': []}, sampler.watcher_errors)
        self.assertEqual(v['status'], 'INCONCLUSIVE')
        self.assertIn('sampler watcher raised', v['reasons'][-1])
        self.assertEqual(cd.with_watcher_errors({'status': 'FAIL', 'reasons': ['x']}, ['e'])['status'], 'FAIL')
        self.assertEqual(cd.with_watcher_errors({'status': 'PASS', 'reasons': []}, []), {'status': 'PASS', 'reasons': []})


class S16TableTest(unittest.TestCase):
    S16 = {'a03-lifetime', 'a04-regenesis', 'a04-one-bridge-halt', 'a05-fwd-upgrade', 'a05-fwd-kill', 'a05-bridge-upgrade',
           'a06-two-forwarders-ticks', 'a01-fwdring', 'c13-enginedriverkill'}

    def test_s16_drills_controls_and_reds_are_tabled(self):
        self.assertTrue(self.S16 <= set(cd.DRILLS))
        self.assertEqual({c for c in cd.CONTROLS if cd.CONTROLS[c][0] in self.S16} | {'edk-cnctimeout'},
                         {'a03-cap100k', 'a03-nokill', 'a04-noregen', 'a04-earlyrestart', 'a05-fwd-upgrade-n1',
                          'a05-bridge-upgrade-n1', 'a06-n1', 'fwdring-pause15', 'fwdring-nopause', 'edk-nokill',
                          'edk-cnctimeout'})
        self.assertEqual((cd.REDS['red-a03']['drill'], cd.REDS['red-a04']['drill']), ('a03-lifetime', 'a04-regenesis'))
        for name in self.S16:
            spec = cd.DRILLS[name]
            self.assertTrue(hasattr(cd.DrillRun, 'faults_' + spec['faults']), name)
            for line in spec['lines']:
                self.assertIn(line, cd.LINES, (name, line))

    def test_plans_fit_the_per_user_cap_and_size_the_tap(self):
        for name in self.S16:
            spec = cd.DRILLS[name]
            story = spec['story']
            if story['script'] == 'a01-mix':
                requests = (story['rate'] + story['rate'] // 5) * story['seconds']
                self.assertLessEqual(requests / len(story['users']), 256, name)
            plan = cd.plan_for(spec, 1)
            self.assertGreaterEqual(plan['tap_ms'] / 1000, cd.story_seconds(story) + cd.PRE_BARRIER_S + 60, name)
        self.assertEqual(cd.plan_for(cd.DRILLS['a03-lifetime'], 1)['ledger_capacity'], 2000)
        self.assertEqual(cd.plan_for(cd.DRILLS['a03-lifetime'], 1, variant={'ledger_capacity': 100_000})['ledger_capacity'], 100_000)
        life1 = cd.plan_for(cd.DRILLS['a04-regenesis'], 1)['tap_ms'] / 1000
        self.assertGreaterEqual(life1, 40 + cd.A04_HALT_PHASE_S + cd.PRE_BARRIER_S)     # W1 item 3: life-1 tap ends on its duration
        # V9: the halt phase is a setting, default 60 s (W5: halt ~5 s, funding done ~12 s after the ME restart)
        self.assertEqual(cd.SETTINGS['A04_HALT_PHASE_S'], 60)
        life2 = cd.plan_for(cd.DRILLS['a04-regenesis'], 1, life=2)['tap_ms'] / 1000
        self.assertEqual(life1 - life2, 60)
        with mock.patch.dict(cd.SETTINGS, {'A04_HALT_PHASE_S': 200}):
            self.assertEqual(cd.plan_for(cd.DRILLS['a04-regenesis'], 1)['tap_ms'] / 1000 - life2, 200)

    def test_a03_scenarios_may_stage_the_norelease_build_in_both_slots(self):
        """W1 open item 1. RED 6380b01: 'GREEN drills run the real binaries only' for core-drill-a03-lifetime on s16-a03."""
        a03 = StubFixture(slots={'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b', 'bridge0': 'bridge', 'bridge1': 'bridge'},
                          artifacts={'forwarder_b': {'driver': 'external', 'target': 'ct_forwarder_nc_norelease'},
                                     'forwarder': {'driver': 'external', 'target': 'ct-forwarder'}, 'bridge_b': None})
        a03.m['manifest_kind'] = 's16-a03'
        with mock.patch.object(cd.DrillRun, 'run', lambda self: {'status': 'PASS', 'lines': {}, 'of_rows': {}}):
            self.assertEqual(cd.scenario(a03, 'core-drill-a03-lifetime', '/nonexistent')['status'], 'PASS')
            a03.m['manifest_kind'] = 's16'
            with self.assertRaisesRegex(Inconclusive, 'GREEN drills run the real binaries only'):
                cd.scenario(a03, 'core-drill-a03-lifetime', '/nonexistent')
            a03.m['manifest_kind'] = 's16-a03'
            a03.m['artifacts']['forwarder_b']['target'] = 'ct-forwarder'     # past check_build_b: the slot guard itself
            with self.assertRaisesRegex(Inconclusive, 'GREEN drills run the real binaries only'):
                cd.scenario(a03, 'core-drill-a05-fwd-upgrade', '/nonexistent')

    def test_s17_a03_kinds_run_the_declared_phase_1_exception_and_nothing_else(self):
        """RC2 S17 W6 fix round item 1. RED 5d0339f: entries 09/20 (s17-a03, s17-a03-embedded) refused before running,
        'fwd0 stages forwarder_b: GREEN drills run the real binaries only (8.3)'. S16 20.1 line 2 (PO): A03 phase 1 runs
        ct_forwarder_nc_norelease in both forwarder slots, build A as forwarder for the swap, on an A03 kind only."""
        def a03(kind, target='ct_forwarder_nc_norelease', slots=None, bridge_b=None):
            f = StubFixture(slots=slots or {'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b', 'bridge0': 'bridge', 'bridge1': 'bridge'},
                            artifacts={'forwarder_b': {'driver': 'external', 'target': target},
                                       'forwarder': {'driver': 'external', 'target': 'ct-forwarder'},
                                       'bridge': {'driver': 'external', 'target': 'ct-bridge'}, 'bridge_b': bridge_b})
            f.m['manifest_kind'] = kind
            return f
        with mock.patch.object(cd.DrillRun, 'run', lambda self: {'status': 'PASS', 'lines': {}, 'of_rows': {}}):
            for kind in ('s17-a03', 's17-a03-embedded', 's16-a03', 's16-a03-embedded'):
                with self.subTest(kind=kind):
                    self.assertEqual(cd.scenario(a03(kind), 'core-drill-a03-lifetime', '/nonexistent')['status'], 'PASS')
            refused = {'GREEN kind': (a03('s17'), 'core-drill-a03-lifetime'),
                       'A05 kind': (a03('s17-a05'), 'core-drill-a03-lifetime'),
                       'other drill': (a03('s17-a03'), 'core-drill-lostack'),
                       'other nc target': (a03('s17-a03', target='ct_forwarder_nc_noresync'), 'core-drill-a03-lifetime'),
                       'one slot only': (a03('s17-a03', slots={'fwd0': 'forwarder_b', 'fwd1': 'forwarder', 'bridge0': 'bridge',
                                                               'bridge1': 'bridge'}), 'core-drill-a03-lifetime'),
                       'a bridge_b too': (a03('s17-a03', slots={'fwd0': 'forwarder_b', 'fwd1': 'forwarder_b',
                                                                'bridge0': 'bridge_b', 'bridge1': 'bridge'},
                                              bridge_b={'driver': 'external', 'target': 'ct-bridge'}), 'core-drill-a03-lifetime')}
            for why, (fixture, name) in refused.items():
                with self.subTest(refused=why), self.assertRaisesRegex(Inconclusive, 'GREEN drills run the real binaries only'):
                    cd.scenario(fixture, name, '/nonexistent')

    def test_s16_red_scenarios_need_their_negative_builds(self):
        with self.assertRaisesRegex(Inconclusive, 'needs the negative build bridge_b'):
            cd.scenario(StubFixture(), 'core-red-a04', '/nonexistent')
        with self.assertRaisesRegex(Inconclusive, 'needs the negative build forwarder_b'):
            cd.scenario(StubFixture(), 'core-red-a03', '/nonexistent')

    def test_line_verdict_inconclusive_is_never_pass(self):
        money = order = {'status': 'PASS', 'rules': {}}
        lines = {'x': cd._line(False, 'no witness', inconclusive=True)}
        self.assertEqual(cd.verdict(money, order, lines, {})['status'], 'INCONCLUSIVE')
        self.assertEqual(cd.control_verdict(money, order, lines, ['x'])['status'], 'INCONCLUSIVE')


class S16ScheduleTest(unittest.TestCase):
    """The section 9 schedules on a stub fixture (no docker): the order of acts and what each records."""

    def run_for(self, drill, variant=None, **f):
        calls = []
        fx = types.SimpleNamespace(readiness_override={}, registry={'containers': {}}, slots={}, m={'artifacts': {}},
                                   stop=lambda slot: calls.append(('stop', slot)) or {'kind': 'stop', 'target': slot, 'exit_code': 0},
                                   replace_slot=lambda slot, art, after_kill=False: calls.append(('replace', slot, art, after_kill))
                                   or {'kind': 'replace_slot', 'target': slot, 'old': {'sha256': 'a'}, 'new': {'sha256': 'b'},
                                       'build_health': 'B'},
                                   **f)
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.f, run.name, run.spec, run.variant = fx, drill, cd.DRILLS[drill], dict(variant or {})
        run.ledger, run.removed, run.restarted, run.extra = cd.Ledger(), set(), set(), {}
        run.t0 = time.time_ns() - 100 * 10**9
        run.at = lambda s: calls.append(('at', s))
        run.sleep = lambda s: None
        run.health_of = lambda role: (200, {})
        run.kill = lambda role: calls.append(('kill', role)) or run.ledger.open('kill', role)
        return run, calls

    def test_a05_swaps_slot0_at_30_and_slot1_at_50_and_heals_each(self):
        run, calls = self.run_for('a05-fwd-upgrade')
        run.faults_a05()
        self.assertEqual([c for c in calls if c[0] != 'at'][:4],
                         [('stop', 'fwd0'), ('replace', 'fwd0', 'forwarder_b', False), ('stop', 'fwd1'),
                          ('replace', 'fwd1', 'forwarder_b', False)])
        self.assertEqual([c[1] for c in calls if c[0] == 'at'], [30, 50])
        self.assertFalse(run.ledger.fault_open())
        self.assertEqual([s['slot'] for s in run.swaps], ['fwd0', 'fwd1'])
        self.assertTrue(all(s['ready_s'] >= s['start_s'] for s in run.swaps))

    def test_a05_kill_swap_replaces_after_kill(self):
        run, calls = self.run_for('a05-fwd-kill')
        run.faults_a05()
        self.assertIn(('replace', 'fwd0', 'forwarder_b', True), calls)
        self.assertEqual([r['kind'] for r in run.ledger.faults()], ['kill', 'kill'])

    def test_a05_n1_control_removes_the_survivor_first_and_never_replaces_it(self):
        run, calls = self.run_for('a05-bridge-upgrade', {'n1': True, 'control': 'a05-bridge-upgrade-n1'})
        run.faults_a05()
        self.assertEqual([c for c in calls if c[0] in ('stop', 'replace')],
                         [('stop', 'bridge1'), ('stop', 'bridge0'), ('replace', 'bridge0', 'bridge_b', False)])
        self.assertEqual(run.removed, {'bridge1'})
        skipped = [r for r in run.ledger.rows if 'skipped' in r]
        self.assertEqual((skipped[0]['target'], skipped[0]['witness']['exit_code']), ('bridge1', 0))
        self.assertFalse(run.ledger.fault_open())

    def test_fwdring_nopause_records_bracketed_skip_rows(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'state' / 'probe').mkdir(parents=True)
            run, calls = self.run_for('a01-fwdring', {'pause': False}, root=Path(root), leader=lambda e: 'me0')
            seqs = iter(range(100, 200, 10))
            run.me_seq = lambda me: next(seqs)
            run.wait_marker = lambda name, bound, where=None: calls.append(('marker', name)) or {}
            with mock.patch.object(cd.core_scenarios, 'barrier_scrape', lambda f: {'fwd0': {'forwarder_dispatch_seq{point="last_sent"}': 7.0}}):
                run.faults_fwdring()
            rows = [r for r in run.ledger.rows if r['kind'] == 'pause']
            self.assertEqual(len(rows), 2)
            self.assertTrue(all('skipped' in r and r['witness']['me_seq_thaw'] > r['witness']['me_seq_pause'] for r in rows))
            self.assertEqual([c for c in calls if c[0] == 'marker'], [('marker', 'ioc_burst_started')] * 2)
            self.assertTrue((Path(root) / 'state' / 'probe' / cd.IOC_BURST_FILE).exists())

    def test_gate_watcher_writes_closed_then_open_from_the_tap(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            tap, sig = Path(root) / 'tap.jsonl', Path(root) / 'sig'
            sig.mkdir()
            rows = [('OPEN', 'ADMIN'), ('SUSPENDED', 'ME_CAPACITY')]
            tap.write_text(''.join(json.dumps({'tap': 'admission', 'row': {'market': 0, 'state': s, 'reason': r}}) + '\n'
                                   for s, r in rows) + '{"tap": "admission", "row": {"mar')        # a row still being written
            watch = cd.GateWatcher(tap, sig)
            watch()
            self.assertTrue((sig / 'capacity_closed').exists())
            self.assertFalse((sig / 'capacity_open').exists())
            with tap.open('a') as out:
                out.write('ket": 1, "state": "OPEN", "reason": "ADMIN"}}\n')
                out.write(json.dumps({'tap': 'admission', 'row': {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN'}}) + '\n')
            watch()
            self.assertTrue((sig / 'capacity_open').exists())

    def test_a03_nokill_swaps_before_the_fill_and_injects_nothing(self):
        run, calls = self.run_for('a03-lifetime', {'hold': False}, leader=lambda e: 'me0')
        run.red = None
        run.gate = types.SimpleNamespace(closed_ns=None, opened_ns=None)
        run.sampler = types.SimpleNamespace(latest=lambda: S(1, ae0=dict(lead('ae'), assets_release_backlog=0.0)))
        run.wait_marker = lambda name, bound, where=None: calls.append(('marker', name)) or {}
        run.tap_rows = lambda: {'dispatch': [{'seq': 5}, {'seq': 9}]}
        run.me_seq = lambda me: 777
        run.faults_a03()
        acts = [c for c in calls if c[0] in ('stop', 'replace', 'marker', 'kill')]
        self.assertEqual(acts, [('stop', 'fwd0'), ('replace', 'fwd0', 'forwarder', False), ('stop', 'fwd1'),
                                ('replace', 'fwd1', 'forwarder', False), ('marker', 'fill_ended')])
        self.assertEqual((run.a03_hold['swap_me_seq'], run.a03_hold['swap_dispatch_seq']), (777, 9))
        self.assertEqual([r['kind'] for r in run.ledger.rows if 'skipped' in r], ['pause', 'kill', 'stop'])

    def one_bridge_halt(self, early):
        run, calls = self.run_for('a04-one-bridge-halt', {'early': True} if early else {}, leader=lambda e: 'me0',
                                  unpause=lambda role: calls.append(('unpause', role)))
        seqs = iter([7592, 8700])
        run.me_seq = lambda me: next(seqs)
        health = {'bridge1': {'cursor': 9604}, 'bridge0': {'cursor': 9871, 'expected': 9890, 'last': 9889, 'state': 'STREAMING'}}
        run.health_of = lambda role: calls.append(('health', role)) or (200, health[role])
        run.slot_metrics = lambda role: calls.append(('metrics', role)) or {role: {'bridge_skipped_total{kind="trade"}': 9871.0}}
        run.restart = lambda row: calls.append(('restart', row['target'])) or run.ledger.heal(row, 'restart', {'ready': True})
        run.pause = lambda role, s: calls.append(('pause', role, s)) or run.ledger.open('pause', role)
        run.await_branches = lambda rows, before, thawed: calls.append(('branches', sorted(rows))) or \
            [run.ledger.heal(r, 'none', {}) for r in rows.values()]
        with mock.patch.object(cd.core_scenarios, 'barrier_scrape', lambda f: {}), \
                mock.patch.dict(cd.SETTINGS, {'EARLY_RESTART_AFTER_S': 0.0}):
            run.faults_one_bridge_halt()
        return run, [c for c in calls if c[0] != 'at']

    def test_one_bridge_halt_reads_the_sync_witness_right_after_the_restart(self):
        run, calls = self.one_bridge_halt(early=False)
        self.assertEqual(calls[:5], [('kill', 'bridge0'), ('health', 'bridge1'), ('restart', 'bridge0'), ('health', 'bridge0'),
                                     ('metrics', 'bridge0')])
        self.assertNotIn('pause', [c[0] for c in calls])
        self.assertEqual(run.cold['health_first']['cursor'], 9871)
        self.assertTrue(cd.line_cold_restart_skips({'cold': run.cold})['holds'])
        self.assertFalse(run.ledger.fault_open())

    def test_earlyrestart_control_freezes_the_peer_across_the_restart(self):
        """V2: bridge1 paused before the kill, thawed after bridge0's sync witness, its branch observed."""
        run, calls = self.one_bridge_halt(early=True)
        names = [c[:2] for c in calls]
        self.assertEqual(names[:6], [('pause', 'bridge1'), ('kill', 'bridge0'), ('restart', 'bridge0'), ('health', 'bridge0'),
                                     ('metrics', 'bridge0'), ('unpause', 'bridge1')])
        self.assertEqual(calls[0][2], cd.SETTINGS['EARLY_PEER_PAUSE_BUDGET_S'])
        self.assertIn(('branches', ['bridge1']), calls)
        self.assertNotIn(('health', 'bridge1'), names)                   # a frozen peer is never polled
        self.assertTrue(run.cold['early'])
        self.assertIsNotNone(run.cold['peer_paused_s'])
        self.assertFalse(run.ledger.fault_open())

    def test_a05_n1_control_holds_the_single_slot_down(self):
        """Items 6, 7: the n1 controls hold the swapped slot down A05_N1_HOLD_S before the replacement; GREEN does not."""
        for drill in ('a05-fwd-upgrade', 'a05-bridge-upgrade'):
            run, calls = self.run_for(drill, {'n1': True, 'control': drill + '-n1'})
            slept = []
            run.sleep = slept.append
            run.faults_a05()
            self.assertEqual(slept, [cd.SETTINGS['A05_N1_HOLD_S']], drill)
            self.assertEqual(run.ledger.faults()[0]['witness']['held_s'], cd.SETTINGS['A05_N1_HOLD_S'])
            run, calls = self.run_for(drill)
            slept = []
            run.sleep = slept.append
            run.faults_a05()
            self.assertEqual(slept, [], drill)

    def test_a06_scrapes_the_core_around_the_kill_and_brackets_the_restart(self):
        run, calls = self.run_for('a06-two-forwarders-ticks', ports={'ae_metrics': 9})
        run.f.m['ports'] = {'ae_metrics': 9, 'forwarder_http': 7}
        run.f.metrics = lambda role, port: calls.append(('metrics', role)) or {'assets_ticks_applied_total': 1.0}
        run.snaps = {'before': scrape(ae2=dict(lead('ae')))}
        run.snap = lambda label: run.snaps.__setitem__(label, scrape(ae2=dict(lead('ae')))) or run.snaps[label]
        run.restart = lambda row: calls.append(('restart', row['target'])) or run.ledger.heal(row, 'restart', {'ready': True})
        slept = []
        run.sleep = slept.append
        run.faults_a06()
        acts = [c for c in calls if c[0] in ('metrics', 'kill', 'restart')]
        self.assertEqual(acts, [('metrics', 'ae2'), ('metrics', 'fwd0'), ('kill', 'fwd0'), ('metrics', 'ae2'), ('restart', 'fwd0')])
        self.assertEqual(slept, [cd.SETTINGS['TICK_SETTLE_S']])
        self.assertLessEqual(run.kill_window['restart_begin_s'], run.kill_window['restart_s'])
        self.assertIn('ae2', run.snaps['core_prekill']); self.assertIn('ae2', run.snaps['core_postkill'])

    def test_iso_ns_reads_docker_times(self):
        self.assertEqual(cd._iso_ns('1970-01-01T00:00:01.5Z'), 1_500_000_000)
        self.assertEqual(cd._iso_ns('1970-01-01T00:00:02.123456789Z') - cd._iso_ns('1970-01-01T00:00:02Z'), 123456789)



class A05KeepTest(unittest.TestCase):
    """RC2 S17 W3 (7.1, row 47): A05-keep swaps one forwarder and one bridge with keep_state=True."""

    def test_the_drill_is_declared(self):
        spec = cd.DRILLS['a05-keep']
        self.assertEqual((spec['swap'], spec['how'], spec['keep_state']), ('both', 'stop', True))
        self.assertIn('keep_state', spec['lines'])

    def test_faults_swap_fwd0_then_bridge0_keeping_state(self):
        run = cd.DrillRun.__new__(cd.DrillRun)
        run.spec, run.variant, run.removed = cd.DRILLS['a05-keep'], {}, set()
        calls = []
        run.at = lambda t: calls.append(('at', t))
        run.health_of = lambda slot: (200, {})
        def swap(slot, artifact, how='stop', record=None, hold_s=0.0, keep_state=False):
            calls.append((slot, artifact, keep_state)); record.append({'slot': slot})
        run.swap = swap
        run.f = None
        run.faults_a05()
        self.assertEqual([c for c in calls if c[0] != 'at'], [('fwd0', 'forwarder_b', True), ('bridge0', 'bridge_b', True)])

    def test_keep_state_line(self):
        swaps = [{'slot': 'fwd0', 'replace': {'keep_state': True, 'state_dir': '/x/state/fwd0'}},
                 {'slot': 'bridge0', 'replace': {'keep_state': True, 'state_dir': '/x/state/bridge0'}}]
        self.assertTrue(cd.line_keep_state({'swaps': swaps})['holds'])
        swaps[1]['replace']['keep_state'] = False
        self.assertFalse(cd.line_keep_state({'swaps': swaps})['holds'])
        self.assertFalse(cd.line_keep_state({'swaps': swaps[:1]})['holds'])


if __name__ == '__main__':
    unittest.main()
