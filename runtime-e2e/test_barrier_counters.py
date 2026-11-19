"""The O11 counters come from the AE member with the fullest count, not blindly from the leader (core_scenarios)."""
import unittest

from contracts import Inconclusive
import core_scenarios


def member(role, stale, redundant, terminals, late, leader=False):
    return {'core_cluster_role': 2.0 if leader else 0.0, 'core_order_stale_outcomes_total': float(stale),
            'core_order_redundant_outcomes_total': float(redundant), 'core_order_stale_terminals_total': float(terminals),
            'core_order_conflicts_total': 0.0, 'core_released_late_total': float(late)}


class BarrierCountersTest(unittest.TestCase):
    def test_a_leader_restored_from_a_snapshot_inside_the_run_is_not_the_witness(self):
        # measured: every member restarted (a peer loss on the kit rejoin wait); the leader ae1 restored from its newest
        # snapshot and counts 2828, ae2 replayed the whole run and counts 6460 = 9 duplicates + 6451 preempted
        by_member = {'ae0': member('ae0', 5, 2818, 4973, 5), 'ae1': member('ae1', 5, 2818, 4973, 5, leader=True),
                     'ae2': member('ae2', 17, 6434, 11415, 9)}
        counters, chosen, every = core_scenarios.barrier_counters(by_member)
        self.assertEqual(chosen, 'ae2')
        self.assertEqual(counters['stale_outcomes'] + counters['redundant_outcomes'] + counters['released_late'], 6460)
        self.assertEqual(set(every), {'ae0', 'ae1', 'ae2'})

    def test_equal_counts_keep_one_member_and_a_missing_export_is_inconclusive(self):
        same = member('x', 1, 2, 3, 0)
        counters, chosen, _ = core_scenarios.barrier_counters({'ae0': same, 'ae1': dict(same), 'ae2': {}})
        self.assertEqual((chosen, counters['redundant_outcomes']), ('ae1', 2))
        with self.assertRaises(Inconclusive):
            core_scenarios.barrier_counters({'ae0': {}, 'ae1': {}})


if __name__ == '__main__':
    unittest.main()
