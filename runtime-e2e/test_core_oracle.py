# SPDX-License-Identifier: Apache-2.0
"""Money oracle v2: the clean stream passes, and every rule M1-M14 fails on its crafted bad stream."""
import unittest

import core_oracle
from oracle_samples import BUYER, SELLER, P, Q, clean_sample, derive_money, q, schema4_sample, seal, variant


def balance(sample, user, asset):
    return next(row for row in sample['core']['balances'] if row['user'] == user and row['asset'] == asset)


class CoreOracleTest(unittest.TestCase):
    def assertRule(self, sample, rule, status='FAIL'):
        result = core_oracle.judge(sample)
        self.assertEqual(result['rules'].get(rule, {}).get('status'), status, result)
        self.assertEqual(result['status'], 'FAIL' if status == 'FAIL' else result['status'])
        return result

    def test_clean_legacy_and_schema4_streams_pass(self):
        for sample in (clean_sample(), schema4_sample()):
            result = core_oracle.judge(sample)
            self.assertEqual(result['status'], 'PASS', result)
            self.assertEqual(len(result['rules']), 14)

    def test_changing_barrier_is_inconclusive_not_pass(self):
        sample = clean_sample()
        sample['barrier']['samples'][1] = dict(sample['barrier']['samples'][1], core_digest='0')
        self.assertEqual(core_oracle.judge(sample)['status'], 'INCONCLUSIVE')
        sample = clean_sample(); sample['barrier']['input_closed'] = False
        self.assertEqual(core_oracle.judge(sample)['status'], 'INCONCLUSIVE')
        sample = clean_sample(); sample['core']['balances'][0]['available'] += 1   # not re-sealed
        self.assertEqual(core_oracle.judge(sample)['status'], 'INCONCLUSIVE')

    def test_non_empty_genesis_fails(self):
        sample = variant(clean_sample(), lambda s: s['genesis'].update(last_applied_trade_id=3))
        self.assertEqual(core_oracle.judge(sample)['status'], 'FAIL')

    def test_m1_money_created(self):
        self.assertRule(variant(clean_sample(), lambda s: balance(s, BUYER, 0).update(available=balance(s, BUYER, 0)['available'] + 1)), 'M1')

    def test_m2_money_moved_between_users(self):
        def edit(s):
            balance(s, BUYER, 0)['available'] -= 1
            balance(s, SELLER, 0)['available'] += 1
        result = self.assertRule(variant(clean_sample(), edit), 'M2')
        self.assertEqual(result['rules']['M1']['status'], 'PASS')

    def test_m3_locked_not_backed_by_holds(self):
        def edit(s):
            balance(s, BUYER, 0)['available'] -= 7
            balance(s, BUYER, 0)['locked'] += 7
        self.assertRule(variant(clean_sample(), edit), 'M3')

    def test_m4_residual_hold_after_terminal(self):
        # Order 1002 FILLED at 100 under a 101 limit: the 0.01 surplus must be released, not left held.
        def edit(s):
            s['core']['holds'].append({'order': 1002, 'user': BUYER, 'asset': 0, 'remaining': q(P(1), Q)})
            balance(s, BUYER, 0)['available'] -= q(P(1), Q)
            balance(s, BUYER, 0)['locked'] += q(P(1), Q)
        self.assertRule(variant(clean_sample(), edit), 'M4')

    def test_m5_amend_top_up_missing(self):
        # Order 1003 amended 0.02@90 -> 0.03@95: the hold must be topped up by 1.05 (2.85 total).
        def edit(s):
            hold = next(h for h in s['core']['holds'] if h['order'] == 1003)
            short = hold['remaining'] - q(P(90), 2 * Q)
            hold['remaining'] -= short
            balance(s, BUYER, 0)['locked'] -= short
            balance(s, BUYER, 0)['available'] += short
        result = self.assertRule(variant(clean_sample(), edit), 'M5')
        self.assertEqual(result['rules']['M3']['status'], 'PASS')

    def test_m5_sell_hold_differs_from_quantity(self):
        self.assertRule(variant(clean_sample(), lambda s: s['creates'][4]['reply'].update(hold_amount=Q)), 'M5')

    def _budgetless_stop(self, s, hold):
        create = next(c for c in s['creates'] if c['reply']['order'] == 1007)
        create['budget'] = 0
        create['reply']['hold_amount'] = hold
        next(r for r in s['dispatch_tap'] if r['order'] == 1007)['budget'] = hold
        next(e for e in s['core_events'] if e['kind'] == 'TRIGGERED')['hold_remaining'] = hold

    def test_m5_budgetless_stop_buy_estimate_is_recomputed(self):
        estimate = q(q(P(98), P(1) + 500 * 10_000), Q)   # stop x (1 + 5%) x qty, FixedPoint.multiply twice
        self.assertEqual(estimate, 102_900_000)
        ok = core_oracle.judge(variant(clean_sample(), lambda s: self._budgetless_stop(s, estimate)))
        self.assertEqual(ok['status'], 'PASS', ok)
        self.assertRule(variant(clean_sample(), lambda s: self._budgetless_stop(s, estimate + 1)), 'M5')
        no_risk = variant(clean_sample(), lambda s: (self._budgetless_stop(s, estimate), s['risk'].clear()))
        self.assertEqual(core_oracle.judge(no_risk)['rules']['M5']['status'], 'INCONCLUSIVE')

    def test_m5_budgetless_market_buy_is_inconclusive_not_read_back(self):
        def edit(s):
            create = next(c for c in s['creates'] if c['reply']['order'] == 1007)
            create.update(type='MARKET', budget=0)
        self.assertEqual(core_oracle.judge(variant(clean_sample(), edit))['rules']['M5']['status'], 'INCONCLUSIVE')

    def test_m5_stop_limit_buy_hold_is_price_times_quantity(self):
        def edit(s):
            create = next(c for c in s['creates'] if c['reply']['order'] == 1007)
            create.update(type='STOP_LIMIT', price=P(101), budget=0)
        self.assertRule(variant(clean_sample(), edit), 'M5')   # ACK says 1.00, intent says 1.01

    def test_m5_unresolved_amend_is_inconclusive(self):
        sample = variant(clean_sample(), lambda s: s['me_journal'].pop(5))
        self.assertEqual(core_oracle.judge(sample)['rules']['M5']['status'], 'INCONCLUSIVE')

    def test_m6_trade_through_limit_overdraws_the_hold(self):
        def edit(s):
            s['me_journal'][2]['price'] = P(102)   # BUY 1002 limit 101
        self.assertRule(variant(clean_sample(), edit), 'M6')

    def test_m7_settle_price_differs_from_me_trade(self):
        def edit(s):
            next(r for r in s['money_journal'] if r.get('trade') == 2)['price'] = P(98)
        self.assertRule(variant(clean_sample(), edit), 'M7')

    def test_m8_duplicate_settle_from_two_bridges(self):
        def edit(s):
            first = next(r for r in s['money_journal'] if r.get('trade') == 1)
            s['money_journal'].append(dict(first, seq=len(s['money_journal']) + 1))
        self.assertRule(variant(clean_sample(), edit), 'M8')

    def test_m8_lost_settle(self):
        def edit(s):
            s['money_journal'] = [r for r in s['money_journal'] if r.get('trade') != 3]
            for i, r in enumerate(s['money_journal'], 1): r['seq'] = i
        self.assertRule(variant(clean_sample(), edit), 'M8')

    def test_m9_funding_refused_while_gate_closed(self):
        def edit(s):
            s['funding'][0]['outcome'] = 'REJECT'
        self.assertRule(variant(clean_sample(), edit), 'M9')

    def test_m9_unknown_funding_outcome_is_inconclusive(self):
        sample = variant(clean_sample(), lambda s: s['funding'][2].update(outcome='UNKNOWN'))
        self.assertEqual(core_oracle.judge(sample)['rules']['M9']['status'], 'INCONCLUSIVE')
        self.assertEqual(core_oracle.judge(sample)['rules']['M1']['status'], 'INCONCLUSIVE')

    def test_m10_cursor_behind_the_me(self):
        self.assertRule(variant(clean_sample(), lambda s: s['core'].update(last_applied_trade_id=2)), 'M10')

    def test_m11_unexplained_settle_fault(self):
        self.assertRule(variant(clean_sample(), lambda s: s['faults'].update(settle_fault=1)), 'M11')

    def test_m11_declared_fault_passes(self):
        sample = variant(clean_sample(), lambda s: (s['faults'].update(settle_rejected=1), s['declared'].update(settle_rejected=1)))
        self.assertEqual(core_oracle.judge(sample)['rules']['M11']['status'], 'PASS')

    def test_m12_gap_after_regenesis_swallows_a_reused_trade_id(self):
        # Epoch 78 restarts trade ids at 1; the core swallowed it as an old id (no settle in epoch 78).
        def edit(s):
            s['declared']['epochs'] = [77, 78]
            new = dict(next(e for e in s['me_journal'] if e['type'] == 'trade' and e['trade_id'] == 1))
            new.update(me_epoch=78, journal_seq=1)
            s['me_journal'].append(new)
        result = core_oracle.judge(variant(schema4_sample(), edit))
        self.assertEqual(result['rules']['M12']['status'], 'FAIL', result)

    def test_m12_dense_regenesis_passes(self):
        def edit(s):
            s['declared']['epochs'] = [77, 78]
            s['me_journal'].append({'type': 'engine_config', 'journal_seq': 1, 'me_epoch': 78})
        result = core_oracle.judge(variant(schema4_sample(), edit))
        self.assertEqual(result['rules']['M12']['status'], 'PASS', result)

    def test_m12_needs_schema4_for_multi_epoch(self):
        sample = variant(clean_sample(), lambda s: s['declared'].update(epochs=[1, 2]))
        self.assertEqual(core_oracle.judge(sample)['rules']['M12']['status'], 'INCONCLUSIVE')

    def test_m12_journal_seq_gap(self):
        sample = variant(schema4_sample(), lambda s: s['me_journal'][4].update(journal_seq=99))
        self.assertEqual(core_oracle.judge(sample)['rules']['M12']['status'], 'FAIL')

    def test_m13_money_journal_gap(self):
        self.assertRule(variant(clean_sample(), lambda s: s['money_journal'][3].update(seq=9)), 'M13')

    def test_m14_journal_replay_disagrees_with_dump(self):
        def edit(s):
            s['money_journal_legs'][-1]['balance_after'] += 1
        self.assertRule(variant(clean_sample(), edit), 'M14')

    def test_m14_leg_claim_drifts_from_its_own_movements(self):
        # The final balance still matches the core; an intermediate leg's claim does not match the replay.
        self.assertRule(variant(clean_sample(), lambda s: s['money_journal_legs'][0].update(
            balance_after=s['money_journal_legs'][0]['balance_after'] + 1)), 'M14')

    def test_m14_missing_leg(self):
        self.assertRule(variant(clean_sample(), lambda s: s['money_journal_legs'].pop(3)), 'M14')

    def test_every_rule_has_a_negative_control(self):
        names = {name for name in dir(self) if name.startswith('test_m')}
        for rule, _ in core_oracle.RULES:
            self.assertTrue(any(name.startswith('test_' + rule.lower() + '_') for name in names), rule)


if __name__ == '__main__':
    unittest.main()
