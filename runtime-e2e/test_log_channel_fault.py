# SPDX-License-Identifier: Apache-2.0
import unittest
from contracts import Violation
from log_channel_fault import filter_arguments, qualified_lag_samples


class LogFilterTest(unittest.TestCase):
    def test_fresh_catchup_is_allowed_but_old_unapplied_leader_bound_is_not(self):
        def sample(at, applied, committed, status):
            def counters(role): return {'counters': [{'type': t, 'value': v}
                for t,v in [(201,role),(207,17),(239,7)]]}
            return {'at_ns': at, 'target_commit': applied, 'leader_commit': committed,
                'target': counters(0), 'leader': counters(2), 'ready': {'status': status,
                'body': f'role=FOLLOWER recovery=ready source=1 term=7 elections=1 applied={applied} '
                        f'commit={committed} checkpoint={applied} observationAgeMs=0 consensusAgeMs=0'}}
        stuck = [sample(i * 2_000_000_000, 100, 200 + i, 200) for i in range(5)]
        self.assertEqual(len(qualified_lag_samples(stuck)), 4)
        recovering = [sample(0, 100, 200, 503), sample(2_000_000_000, 100, 300, 503),
                      sample(4_000_000_000, 350, 400, 200), sample(6_000_000_000, 350, 500, 503)]
        qualified = qualified_lag_samples(recovering)
        self.assertEqual([s['ready']['status'] for s in qualified], [503, 503])
        self.assertEqual(len(qualified_lag_samples([sample(0, 100, 65637, 200)])), 1)

    def test_only_replication_port_on_explicit_engine_member_is_filtered(self):
        m = {'ports': {'me_base': 9000, 'ae_base': 19300, 'stride': 100}}
        self.assertEqual(filter_arguments(m, 'me2', 'add')[-3:], ['9204', '-j', 'DROP'])
        self.assertEqual(filter_arguments(m, 'ae1', 'delete')[2], '-D')
        self.assertIn('19404', filter_arguments(m, 'ae1', 'delete'))
        for target in ('oms', 'me3', '', 'host', 'me0;true'):
            with self.assertRaises(Violation): filter_arguments(m, target, 'add')
        with self.assertRaises(Violation): filter_arguments(m, 'me0', 'flush')


if __name__ == '__main__': unittest.main()
