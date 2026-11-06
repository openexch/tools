# SPDX-License-Identifier: Apache-2.0
"""Independent verifier cases for the core oracles (RC2 S14 review, 2026-10-26).

Each case is a stream where money or ownership is wrong but every rule the implementer shipped is
self-consistent. A case marked RED fails on the reviewed tree on purpose: it documents a false PASS
the oracle must stop giving (review.md DEFECT-1..3, FIX-1). GREEN cases pin branches the shipped
negative controls did not reach.
"""
import unittest

import core_oracle
import order_oracle
from oracle_samples import BUYER, SELLER, P, Q, clean_sample, derive_money, q, variant


def balance(sample, user, asset):
    return next(r for r in sample['core']['balances'] if r['user'] == user and r['asset'] == asset)


def judged(sample):
    money, order = core_oracle.judge(sample), order_oracle.judge(sample)
    return money, order, {**money['rules'], **order['rules']}


class OracleVerifierTest(unittest.TestCase):

    # DEFECT-1 (RED): a SELL order whose hold sits on the QUOTE asset. ACK says base, the live row,
    # the hold row and the balances all say quote. LifecycleInvariants I4 checks holdAssetId against
    # the side; the Python port only checks the hold row against the live row.
    def test_hold_on_the_wrong_asset_for_the_side_fails(self):
        def edit(s):
            live = next(r for r in s['core']['live_orders'] if r['order'] == 1005)
            hold = next(h for h in s['core']['holds'] if h['order'] == 1005)
            live['hold_asset'] = hold['asset'] = 0
            balance(s, SELLER, 1)['locked'] -= hold['remaining']; balance(s, SELLER, 1)['available'] += hold['remaining']
            balance(s, SELLER, 0)['locked'] += hold['remaining']; balance(s, SELLER, 0)['available'] -= hold['remaining']
        money, _, rules = judged(variant(clean_sample(), edit))
        self.assertEqual(money['status'], 'FAIL', rules)

    # DEFECT-2 (RED): trade 2's maker leg is settled to BUYER although order 1005 belongs to SELLER;
    # the ME trade, the dispatch tap and the money journal all carry the wrong user, so M2/M7/M14
    # agree with each other. No rule anchors trade or dispatch users on the probe's own create log.
    def test_trade_settled_to_a_user_who_does_not_own_the_order_fails(self):
        def edit(s):
            trade = next(e for e in s['me_journal'] if e['type'] == 'trade' and e['trade_id'] == 2)
            trade['maker_user'] = BUYER
            for row in s['dispatch_tap']:
                if row['order'] == 1005:
                    row['user'] = BUYER
            derive_money(s)
        money, order, rules = judged(variant(clean_sample(), edit))
        self.assertIn('FAIL', {money['status'], order['status']}, rules)

    # DEFECT-3 (RED): STOP_LOSS BUY 1007 declares an explicit budget of 1 quote; the core held 2 and
    # the child spent 1. M5 must recompute the create hold for price-less BUY types (harness 2.5 M5:
    # "MARKET BUY budget, stop-buy stop x slippage x qty"), not read it back from the ACK.
    def test_stop_buy_hold_is_recomputed_from_the_intent(self):
        def edit(s):
            create = next(c for c in s['creates'] if c['reply']['order'] == 1007)
            create['budget'] = P(1)
            create['reply']['hold_amount'] = P(2)
            next(r for r in s['dispatch_tap'] if r['order'] == 1007)['budget'] = P(2)
        money, _, rules = judged(variant(clean_sample(), edit))
        self.assertEqual(rules['M5']['status'], 'FAIL', rules)

    # FIX-1 (RED): an open replace window under a declared fault. Contract 3.4 / LifecycleInvariants
    # expectedResidual: holdRemaining shows the top-up while REPLACE_PENDING. The oracle must not call
    # the engine's correct hold a FAIL.
    def test_pending_top_up_in_an_open_replace_window_is_not_a_fail(self):
        def edit(s):
            s['me_journal'] = [e for e in s['me_journal'] if not (e['type'] == 'outcome' and e['command_id_high'] == 1003
                                                                   and e['command_id_low'] == (1 << 2 | 2))]
            s['declared']['fault_open'] = True
            live = next(r for r in s['core']['live_orders'] if r['order'] == 1003)
            live.update(status='PENDING_REPLACE', price=P(90), quantity=2 * Q, remaining=2 * Q)
        money, _, rules = judged(variant(clean_sample(), edit))
        self.assertNotEqual(rules['M5']['status'], 'FAIL', rules)

    # GREEN: the shipped test_m9_funding_refused_while_gate_closed trips on the extra journal row, not
    # on the gate branch. With a journal consistent with the refusal, the gate branch itself fires.
    def test_m9_gate_closed_refusal_is_reported_on_its_own_branch(self):
        def edit(s):
            s['funding'][0]['outcome'] = 'REJECT'
            derive_money(s)
        _, _, rules = judged(variant(clean_sample(), edit))
        self.assertEqual(rules['M9']['status'], 'FAIL')
        self.assertIn('gate was closed', rules['M9']['detail'])

    # GREEN: a deposit the core applied but the money journal never carried.
    def test_m9_lost_funding_row(self):
        def edit(s):
            s['money_journal'] = [r for r in s['money_journal'] if not (r['kind'] == 'deposit' and r['user'] == SELLER)]
            s['money_journal_legs'] = [l for l in s['money_journal_legs'] if l['seq'] != 2]
            for index, row in enumerate(s['money_journal'], 1):
                for leg in s['money_journal_legs']:
                    if leg['seq'] == row['seq']:
                        leg['seq'] = index
                row['seq'] = index
        _, _, rules = judged(variant(clean_sample(), edit))
        self.assertEqual(rules['M9']['status'], 'FAIL', rules)

    # GREEN: a hold inflated on a live order to park a terminal order's unreleased surplus.
    def test_surplus_parked_on_another_live_hold_fails_m5(self):
        def edit(s):
            hold = next(h for h in s['core']['holds'] if h['order'] == 1003)
            hold['remaining'] += q(P(1), Q)
            balance(s, BUYER, 0)['locked'] += q(P(1), Q); balance(s, BUYER, 0)['available'] -= q(P(1), Q)
        _, _, rules = judged(variant(clean_sample(), edit))
        self.assertEqual(rules['M5']['status'], 'FAIL', rules)


if __name__ == '__main__':
    unittest.main()
