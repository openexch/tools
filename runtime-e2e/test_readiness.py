# SPDX-License-Identifier: Apache-2.0
import unittest
from contracts import Inconclusive
from readiness import authorize_next_restart


def topology():
    return {f'me{i}': {'observed_ns': 100,
        'ready': {'status': 200, 'body': f'role={"LEADER" if i == 0 else "FOLLOWER"} recovery=ready '
            f'source={42+i} term=7 elections=2 applied=100 commit=100 checkpoint=100 observationAgeMs=0'}}
        for i in range(3)}


class RollingRestartTest(unittest.TestCase):
    def test_ready_replica_has_applied_leader_checkpoint(self):
        result = authorize_next_restart('me', 'me2', topology(), 101)
        self.assertEqual(result['checkpoint'], 100)
        self.assertEqual(result['replica_applied'], 100)

    def test_missing_member_never_authorizes_restart(self):
        value = topology(); del value['me1']
        with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_http_ready_is_insufficient_when_replica_is_behind_leader(self):
        value = topology(); value['me2']['ready']['body'] = value['me2']['ready']['body'].replace('applied=100', 'applied=99')
        with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_each_member_must_be_ready_and_fresh(self):
        for i in range(3):
            for mutation in ['status', 'time']:
                value = topology()
                if mutation == 'status': value[f'me{i}']['ready']['status'] = 503
                else: value[f'me{i}']['observed_ns'] = -2_000_000_000
                with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_term_changes_and_ambiguous_leaders_fail_closed(self):
        for old, new in [('term=7', 'term=8'), ('FOLLOWER', 'LEADER')]:
            value = topology(); value['me2']['ready']['body'] = value['me2']['ready']['body'].replace(old, new)
            with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_unknown_source_or_stale_engine_observation_fails_closed(self):
        for old, new in [('source=44', 'source=-1'), ('observationAgeMs=0', 'observationAgeMs=1000')]:
            value = topology(); value['me2']['ready']['body'] = value['me2']['ready']['body'].replace(old, new)
            with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_old_role_only_response_is_not_a_certificate(self):
        value = topology(); value['me2']['ready']['body'] = 'follower, caught up'
        with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', value, 101)

    def test_clock_regression_does_not_refresh_old_evidence(self):
        with self.assertRaises(Inconclusive): authorize_next_restart('me', 'me2', topology(), 99)


if __name__ == '__main__': unittest.main()
