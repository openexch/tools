# SPDX-License-Identifier: Apache-2.0
"""Order oracle v2: the clean stream passes, and every rule O1-O12 fails on its crafted bad stream."""
import copy
import unittest

import order_oracle
from oracle_samples import BUYER, SELLER, P, Q, clean_sample, schema4_sample, variant


def outcome_index(sample, order, low):
    return next(i for i, e in enumerate(sample['me_journal'])
                if e['type'] == 'outcome' and e['command_id_high'] == order and e['command_id_low'] == low)


class OrderOracleTest(unittest.TestCase):
    def assertRule(self, sample, rule, status='FAIL'):
        result = order_oracle.judge(sample)
        self.assertEqual(result['rules'].get(rule, {}).get('status'), status, result)
        if status == 'FAIL':
            self.assertEqual(result['status'], 'FAIL')
        return result

    def test_clean_streams_pass(self):
        for sample in (clean_sample(), schema4_sample()):
            result = order_oracle.judge(sample)
            self.assertEqual(result['status'], 'PASS', result)
            self.assertEqual(len(result['rules']), 12)

    def test_o1_replayed_request_mints_a_second_order(self):
        def edit(s):
            s['creates'][-1]['reply'].update(order=1099, duplicate=False)
        self.assertRule(variant(clean_sample(), edit), 'O1')

    def test_o1_unknown_create_outcome_is_inconclusive(self):
        sample = variant(clean_sample(), lambda s: s['creates'].append(dict(s['creates'][0], request=[1, 99], reply={'outcome': 'UNKNOWN'})))
        self.assertRule(sample, 'O1', 'INCONCLUSIVE')

    def test_o2_double_leg_from_a_repeated_command(self):
        # A lost-ack resend applied twice: the repeat carries a NEW position and a NEW leg.
        def edit(s):
            i = outcome_index(s, 1003, 0)
            s['me_journal'].insert(i + 1, dict(s['me_journal'][i], applied_position=99_999, leg=5099))
        self.assertRule(variant(clean_sample(), edit), 'O2')

    def test_o2_faithful_repeat_passes_and_is_counted(self):
        def edit(s):
            i = outcome_index(s, 1003, 0)
            s['me_journal'].insert(i + 1, copy.deepcopy(s['me_journal'][i]))
            s['counters']['redundant_outcomes'] = 1
        result = order_oracle.judge(variant(clean_sample(), edit))
        self.assertEqual(result['rules']['O2']['status'], 'PASS', result)
        self.assertEqual(result['rules']['O11']['status'], 'PASS', result)

    def test_o3_attempt_skipped(self):
        def edit(s):
            row = next(r for r in s['dispatch_tap'] if r['seq'] == 9)
            row['id_low'] = 2 << 2
            s['me_journal'][outcome_index(s, 1005, 1 << 2)]['command_id_low'] = 2 << 2
        self.assertRule(variant(clean_sample(), edit), 'O3')

    def test_o3_outcome_for_undispatched_command(self):
        def edit(s):
            extra = dict(s['me_journal'][outcome_index(s, 1003, 0)], command_id_low=3 << 2, leg=5098, applied_position=1)
            s['me_journal'].append(extra)
        self.assertRule(variant(clean_sample(), edit), 'O3')

    def test_o4_orphan_me_leg(self):
        def edit(s):
            s['me_open_legs'].append({'leg': 5999, 'order': 1004, 'user': SELLER, 'market': 1})
        self.assertRule(variant(clean_sample(), edit), 'O4')

    def test_o4_trade_on_a_leg_outside_the_history(self):
        self.assertRule(variant(clean_sample(), lambda s: s['me_journal'][2].update(maker_leg=5777)), 'O4')

    def test_o5_two_terminals_for_one_order(self):
        def edit(s):
            s['core_events'].append({'seq': 10, 'order': 1002, 'kind': 'CANCELLED', 'status': 'CANCELLED',
                                     'filled': Q, 'quantity': Q})
        self.assertRule(variant(clean_sample(), edit), 'O5')

    def test_o5_cancelled_without_me_evidence(self):
        def edit(s):
            s['me_journal'] = [e for e in s['me_journal'] if not (e['type'] == 'terminal' and e['leg'] == 5005)]
            s['me_journal'][outcome_index(s, 1004, 1 << 2 | 1)]['result'] = 1   # ME refused the cancel
        self.assertRule(variant(clean_sample(), edit), 'O5')

    def test_o6_filled_disagrees_with_me_trades(self):
        def edit(s):
            row = s['core']['live_orders'][1]
            row.update(filled=0, remaining=row['quantity'])
        self.assertRule(variant(clean_sample(), edit), 'O6')

    def test_o7_pending_dispatch_at_barrier(self):
        self.assertRule(variant(clean_sample(), lambda s: s['core']['live_orders'][0].update(status='PENDING_REPLACE')), 'O7')

    def test_o7_pending_without_forwarder_is_inconclusive_not_pass(self):
        def edit(s):
            s['core']['live_orders'][0]['status'] = 'PENDING_NEW'
            s['core']['pending_dispatch']['count'] = 1
            s['declared']['forwarder_absent'] = True
        result = self.assertRule(variant(clean_sample(), edit), 'O7', 'INCONCLUSIVE')
        self.assertNotEqual(result['status'], 'PASS')

    def test_o8_iceberg_refill_does_not_add_up(self):
        self.assertRule(variant(clean_sample(), lambda s: s['core']['live_orders'][1].update(hidden_qty=Q)), 'O8')

    def test_o8_iceberg_refill_before_slice_filled(self):
        # Three slices that add up, but the third was minted while the second was still unfilled.
        def edit(s):
            second = next(r for r in s['dispatch_tap'] if r['seq'] == 9)
            second['quantity'] = Q // 2
            s['dispatch_tap'].append(dict(second, seq=11, id_low=2 << 2))
        result = self.assertRule(variant(clean_sample(), edit), 'O8')
        self.assertIn('refilled before', result['rules']['O8']['detail'])

    def test_o8_child_budget_follows_hold_remaining_at_trigger_not_the_create_hold(self):
        def edit(s):
            next(e for e in s['core_events'] if e['kind'] == 'TRIGGERED')['hold_remaining'] = P(1) - 7
            next(r for r in s['dispatch_tap'] if r['seq'] == 10)['budget'] = P(1) - 7
        self.assertEqual(order_oracle.judge(variant(clean_sample(), edit))['rules']['O8']['status'], 'PASS')
        missing = variant(clean_sample(), lambda s: next(e for e in s['core_events'] if e['kind'] == 'TRIGGERED').pop('hold_remaining'))
        self.assertRule(missing, 'O8', 'INCONCLUSIVE')

    def test_o4_resting_leg_reported_for_another_user(self):
        self.assertRule(variant(clean_sample(), lambda s: s['me_open_legs'][0].update(user=SELLER)), 'O4')

    def test_o4_dispatch_user_differs_from_the_creator(self):
        self.assertRule(variant(clean_sample(), lambda s: s['dispatch_tap'][0].update(user=BUYER)), 'O4')

    def test_o4_live_order_past_pending_without_an_me_leg(self):
        self.assertRule(variant(clean_sample(), lambda s: s['core']['live_orders'][0].update(me_order_id=0)), 'O4')

    def test_o9_has_no_reorder_escape(self):
        def edit(s):
            a, b = outcome_index(s, 1006, 0), outcome_index(s, 1005, 1 << 2)
            s['me_journal'][a], s['me_journal'][b] = s['me_journal'][b], s['me_journal'][a]
            s['declared']['reorder_allowed'] = True
        self.assertRule(variant(clean_sample(), edit), 'O9')

    def test_o8_stop_child_budget_differs_from_hold(self):
        self.assertRule(variant(clean_sample(), lambda s: next(r for r in s['dispatch_tap'] if r['seq'] == 10).update(budget=P(2))), 'O8')

    def test_o9_first_apply_out_of_dispatch_order(self):
        def edit(s):
            a, b = outcome_index(s, 1006, 0), outcome_index(s, 1005, 1 << 2)
            s['me_journal'][a], s['me_journal'][b] = s['me_journal'][b], s['me_journal'][a]
        self.assertRule(variant(clean_sample(), edit), 'O9')

    def test_o10_dispatched_command_never_applied(self):
        def edit(s):
            del s['me_journal'][outcome_index(s, 1003, 0)]
        self.assertRule(variant(clean_sample(), edit), 'O10')

    def test_o11_counters_disagree_with_duplicates(self):
        self.assertRule(variant(clean_sample(), lambda s: s['counters'].update(stale_outcomes=1)), 'O11')

    def test_o11_missing_g6_export_is_inconclusive(self):
        self.assertRule(variant(clean_sample(), lambda s: s.pop('counters')), 'O11', 'INCONCLUSIVE')

    def test_o11_unexpected_quarantine(self):
        self.assertRule(variant(clean_sample(), lambda s: s['faults'].update(quarantined=1)), 'O11')

    def test_o12_gate_never_opened(self):
        self.assertRule(variant(clean_sample(), lambda s: s['admission'].pop()), 'O12')

    def test_every_rule_has_a_negative_control(self):
        names = {name for name in dir(self) if name.startswith('test_o')}
        for rule, _ in order_oracle.RULES:
            self.assertTrue(any(name.startswith('test_' + rule.lower() + '_') for name in names), rule)


if __name__ == '__main__':
    unittest.main()
