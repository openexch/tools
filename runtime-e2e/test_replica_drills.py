# SPDX-License-Identifier: Apache-2.0
"""The replica drills' pure parts: settings, lines (each can fail, with its text), the control verdict, the lag sampler's
formula and summary, the netfilter rule check, and the drill frame's refusals. No Docker."""
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import core_contracts
import core_drills
import core_oracle
import lag_sampler
import order_oracle
import replica_drills as rd
import test_replica_fixture
from oracle_samples import clean_sample, variant
from test_core_drills import holed, rule

HERE = Path(__file__).resolve().parent
S = rd.settings({})


def w(**more):
    return dict({'settings': dict(S)}, **more)


def holds(line):
    return line['holds']


class SettingsTest(unittest.TestCase):
    def test_every_setting_has_a_default_inside_its_range(self):
        for name, (default, low, high) in rd.SETTINGS_SPEC.items():
            self.assertTrue(low <= default <= high, name)
            self.assertEqual(rd.settings({})[name], default)
            with self.assertRaises(Violation) as caught:
                rd.settings({name: str(high + 1)})
            self.assertIn(name, str(caught.exception))
        with self.assertRaises(Violation):
            rd.settings({'PEERLOSS_PULLS_BEFORE_KILL': 'two'})

    def test_the_story_is_refused_when_the_users_cannot_carry_it(self):
        story = core_drills.DRILLS['supplierloss']['story']
        self.assertEqual(rd.story_for(story, S)['seconds'], 120)
        self.assertEqual(rd.story_for(core_drills.DRILLS['shadow-catalog']['story'], dict(S, STORY_RATE=150))['rate'], 20)
        with self.assertRaises(Violation) as caught:
            rd.story_for(story, dict(S, STORY_RATE=200))
        self.assertIn('users', str(caught.exception))

    def test_the_replica_users_are_their_own_range(self):
        others = set(core_drills.A01_USERS) | set(core_drills.A02_USERS) | set(core_drills.A05_USERS) \
            | set(core_drills.A04_LIFE2_USERS) | set(core_drills.EDK_USERS)
        self.assertFalse(set(core_drills.REPLICA_USERS) & others)
        self.assertGreaterEqual(len(core_drills.REPLICA_USERS) * rd.STORY_CAP, 100 * 1.2 * 120)


class GaugeTest(unittest.TestCase):
    def test_labels_match_with_or_without_quotes(self):
        scrape = {'shadow_write_total{kind=ALIGNED}': 4.0, 'shadow_write_total{kind=STANDBY}': 1.0,
                  'shadow_last_position{kind="ALIGNED"}': 99.0, 'core_restore_path': 2.0,
                  'shadow_floor_witness_missing{kind="R"}': 1.0}
        self.assertEqual(rd.gauge(scrape, 'shadow_write_total', kind='ALIGNED'), 4.0)
        self.assertEqual(rd.gauge(scrape, 'shadow_last_position', kind='ALIGNED'), 99.0)
        self.assertEqual(rd.gauge(scrape, 'shadow_floor_witness_missing', kind='R'), 1.0)
        self.assertEqual(rd.gauge(scrape, 'shadow_write_total'), 5.0)
        self.assertIsNone(rd.gauge(scrape, 'shadow_write_total', kind='CADENCE'))
        self.assertIsNone(rd.gauge({}, 'core_restore_path'))


class MemberKillLineTest(unittest.TestCase):
    def rows(self, paths, ready=(4.0, 5.0, 6.0)):
        return [{'member': f'ae{i}', 'restore_path': p, 'ready_after_start_s': r, 'waited_after_kill_s': 12.5}
                for i, (p, r) in enumerate(zip(paths, ready))]

    def test_shadow_paths_hold_and_full_fails_with_its_text(self):
        self.assertTrue(holds(rd.line_restore_path_shadow(w(member_restarts=self.rows([2, 3, 4])))))
        full = rd.line_restore_path_shadow(w(member_restarts=self.rows([1, 1, 2])))
        self.assertFalse(holds(full))
        self.assertIn('restore path FULL on ae0', full['detail'])
        genesis = rd.line_restore_path_shadow(w(member_restarts=self.rows([5, 2, 2])))
        self.assertIn('restore path VIRTUAL_GENESIS on ae0', genesis['detail'])
        missing = rd.line_restore_path_shadow(w(member_restarts=self.rows([2, 2])))
        self.assertTrue(missing.get('inconclusive'))

    def test_ready_is_measured_from_docker_start_against_the_bound(self):
        self.assertTrue(holds(rd.line_ready_after_start(w(member_restarts=self.rows([2, 2, 2])))))
        self.assertFalse(holds(rd.line_ready_after_start(w(member_restarts=self.rows([2, 2, 2], (4.0, 31.0, 5.0))))))


class SupplierLossLineTest(unittest.TestCase):
    def x(self, **more):
        # measured on Aeron 1.53.1: a supplier stop moves neither counter (recorded, not required)
        base = {'killed': 'ae1', 'supplier_before': 'ae1', 'supplier_after': 'ae2', 'resets_delta': 0, 'reattach_delta': 0,
                'states_seen': [0, 5, 6], 'commit_at_kill': 1000, 'applied_after': 1200,
                'recovery_s': 16.2, 'bound_s': 30, 'observed_s': 16.2}
        return w(supplier_loss=dict(base, **more))

    def test_recovery_inside_the_bound_holds(self):
        self.assertTrue(holds(rd.line_supplier_loss_recovery(self.x())))

    def test_the_cooldown_control_fails_with_its_text(self):
        line = rd.line_supplier_loss_recovery(self.x(recovery_s=33.4))
        self.assertFalse(holds(line))
        self.assertIn('supplier loss recovery 33.4 s above 30 s', line['detail'])
        never = rd.line_supplier_loss_recovery(self.x(recovery_s=None, observed_s=60))
        self.assertIn('supplier loss recovery not observed', never['detail'])

    def test_vacuity_the_killed_member_was_not_the_supplier(self):
        line = rd.line_supplier_loss_recovery(self.x(killed='ae0'))
        self.assertTrue(line.get('inconclusive'))
        self.assertIn('killed member was not the supplier', line['detail'])

    def test_no_new_supplier_no_backup_reset_state_or_no_catch_up_fails(self):
        self.assertFalse(holds(rd.line_supplier_loss_recovery(self.x(supplier_after='ae1'))))
        self.assertFalse(holds(rd.line_supplier_loss_recovery(self.x(states_seen=[5]))))
        self.assertTrue(holds(rd.line_supplier_loss_recovery(self.x(states_seen=[5, 0]))))
        self.assertFalse(holds(rd.line_supplier_loss_recovery(self.x(applied_after=1000))))
        self.assertFalse(holds(rd.line_supplier_loss_recovery(self.x(commit_at_kill=None))))

    def test_the_counters_are_recorded_not_required(self):
        line = rd.line_supplier_loss_recovery(self.x())
        self.assertIn('recorded: resets +0, reattach +0', line['detail'])
        self.assertIn("backup states ['BACKUP_QUERY', 'BACKING_UP', 'RESET_BACKUP']", line['detail'])


class UntappableWindowTest(unittest.TestCase):
    TRANSITIONS = [{'event': 'registered', 'at_ms': 1000, 'last_dispatch_seq': 0, 'last_event_seq': 0},
                   {'event': 'session_closed', 'at_ms': 5000, 'last_dispatch_seq': 388, 'last_event_seq': 491},
                   {'event': 'reconnect_failed', 'at_ms': 6000, 'last_dispatch_seq': 388, 'last_event_seq': 491},
                   {'event': 'reconnected', 'at_ms': 9000, 'last_dispatch_seq': 388, 'last_event_seq': 491}]
    SUMMARY = {'dispatch': {'gaps': [[389, 499], [900, 901]]}, 'events': {'gaps': [[492, 606]]}}
    QUORUM = {'from_ms': 4000, 'to_ms': 8500, 'killed': ['shadow0', 'ae0', 'ae1'], 'survivor': 'ae2'}

    def test_the_gaps_that_start_at_a_session_closed_inside_the_quorum_loss(self):
        out = rd.untappable_windows(self.TRANSITIONS, self.SUMMARY, self.QUORUM)
        self.assertEqual((out['dispatch'], out['events']), ([[389, 499]], [[492, 606]]))   # [900, 901] is not declared
        self.assertEqual(out['sessions'], [{'closed_ms': 5000, 'reconnected_ms': 9000,
                                            'cause': 'quorum loss: shadow0, ae0, ae1 killed, ae2 alone'}])
        self.assertIn('quorum loss: shadow0, ae0, ae1 killed, ae2 alone', out['reason'])

    def test_nothing_is_declared_outside_the_interval_or_without_a_reconnect(self):
        self.assertIsNone(rd.untappable_windows(self.TRANSITIONS, self.SUMMARY, dict(self.QUORUM, from_ms=5001)))
        self.assertIsNone(rd.untappable_windows(self.TRANSITIONS[:3], self.SUMMARY, self.QUORUM))
        self.assertIsNone(rd.untappable_windows(self.TRANSITIONS, {'dispatch': {'gaps': []}, 'events': {'gaps': []}},
                                                self.QUORUM))


class ElectionWindowTest(unittest.TestCase):
    """A recorded leader election declares the same untappable windows as a quorum loss: a gap that starts at a session
    close inside the election (the leader kill to the new leader serving) and ends at the reconnect."""
    ELECTION = {'from_ms': 4000, 'to_ms': 8500, 'killed': 'ae2', 'new_leader': 'ae0'}
    T = UntappableWindowTest.TRANSITIONS
    SUMMARY = UntappableWindowTest.SUMMARY

    def test_the_gaps_that_start_at_a_session_closed_inside_an_election(self):
        out = rd.untappable_windows(self.T, self.SUMMARY, None, [self.ELECTION])
        self.assertEqual((out['dispatch'], out['events']), ([[389, 499]], [[492, 606]]))
        self.assertEqual(out['sessions'], [{'closed_ms': 5000, 'reconnected_ms': 9000,
                                            'cause': 'leader election: ae2 killed, ae0 elected'}])
        self.assertIn('leader election: ae2 killed, ae0 elected', out['reason'])
        self.assertNotIn('quorum loss', out['reason'])

    def test_nothing_is_declared_outside_the_election_without_a_reconnect_or_for_a_surviving_session(self):
        self.assertIsNone(rd.untappable_windows(self.T, self.SUMMARY, None, [dict(self.ELECTION, to_ms=4999)]))
        self.assertIsNone(rd.untappable_windows(self.T[:3], self.SUMMARY, None, [self.ELECTION]))
        survived = [self.T[0], {'event': 'new_leader', 'at_ms': 5000, 'last_dispatch_seq': 388, 'last_event_seq': 491}]
        self.assertIsNone(rd.untappable_windows(survived, self.SUMMARY, None, [self.ELECTION]))
        self.assertIsNone(rd.untappable_windows(self.T, self.SUMMARY, None, []))

    @staticmethod
    def declared(sample, last_dispatch, dispatch_gap, last_event, event_gap):
        transitions = [{'event': 'session_closed', 'at_ms': 5000, 'last_dispatch_seq': last_dispatch,
                        'last_event_seq': last_event},
                       {'event': 'reconnected', 'at_ms': 9000, 'last_dispatch_seq': last_dispatch,
                        'last_event_seq': last_event}]
        summary = {'dispatch': {'gaps': [dispatch_gap] if dispatch_gap else []},
                   'events': {'gaps': [event_gap] if event_gap else []}}
        windows = rd.untappable_windows(transitions, summary, None, [ElectionWindowTest.ELECTION])
        return variant(sample, lambda s: s.__setitem__('declared', dict(s['declared'], untappable=windows)))

    def test_an_order_whose_terminal_fell_inside_is_recorded_unjudged_and_counted(self):
        lost = variant(clean_sample(), lambda s: s.__setitem__('core_events',
                                                                [e for e in s['core_events'] if e['seq'] != 4]))
        order = order_oracle.judge(self.declared(lost, 0, None, 3, [4, 4]))
        self.assertEqual(rule(order, 'O5')['status'], 'PASS', order)
        self.assertEqual(order['untappable']['orders_unjudged'], [1004])
        self.assertEqual(order['untappable']['orders_unjudged_count'], 1)
        recorded = rd.untapped_record(order)
        self.assertEqual((recorded['orders_unjudged_count'], recorded['orders_unjudged']), (1, [1004]))
        self.assertIn('leader election: ae2 killed, ae0 elected', recorded['reason'])
        self.assertIsNone(rd.untapped_record(order_oracle.judge(clean_sample())))

    def test_an_me_outcome_without_a_dispatch_is_still_a_fail(self):
        """The election declaration closes the dispatch gap; the ME outcome for the lost dispatch is then judged."""
        hidden = order_oracle.judge(self.declared(holed(6), 5, [6, 6], 0, None))
        self.assertEqual(rule(hidden, 'O3')['status'], 'FAIL', hidden)
        self.assertEqual(hidden['status'], 'FAIL')
        self.assertEqual(rule(order_oracle.judge(holed(6)), 'O3')['status'], 'INCONCLUSIVE')

    def test_the_money_oracle_is_unchanged_by_an_election_declaration(self):
        sample = self.declared(holed(6), 5, [6, 6], 0, None)
        self.assertEqual(core_oracle.judge(sample)['status'], core_oracle.judge(holed(6))['status'])


class PromotionLineTest(unittest.TestCase):
    def test_two_named_states_and_the_promotion_half(self):
        attempts = [{'attempt': 1, 'state': 'ii', 'detail': 'other won'}, {'attempt': 2, 'state': 'i', 'detail': 'promoted'}]
        self.assertTrue(holds(rd.line_promotion_states(w(promotion=attempts))))
        self.assertTrue(holds(rd.line_promotion_observed(w(promotion=attempts))))
        unnamed = rd.line_promotion_states(w(promotion=[{'attempt': 1, 'state': None, 'detail': 'outside'}]))
        self.assertFalse(holds(unnamed))
        only_ii = rd.line_promotion_observed(w(promotion=[dict(attempts[0], attempt=n) for n in (1, 2, 3)]))
        self.assertTrue(only_ii.get('inconclusive'))
        self.assertIn('promotion not observed in 3 attempts', only_ii['detail'])

    def test_attempt_lag_is_held_to_the_term_unless_the_backup_reset(self):
        lag = {'samples_with_lag': 600, 'max_lag_bytes': 2_500_000.0, 'term_bytes': 1048576}
        reset = {'attempt': 1, 'state': 'i', 'states_seen': [0, 5, 6], 'max_lag_bytes': 2_500_000}
        calm = {'attempt': 2, 'state': 'ii', 'states_seen': [5], 'max_lag_bytes': 90_000}
        line = rd.line_attempt_lag_within_term(w(lag=lag, promotion=[reset, calm]))
        self.assertTrue(holds(line))
        self.assertIn('attempt 1 max 2500000 B through a backup reset', line['detail'])
        over = rd.line_attempt_lag_within_term(w(lag=lag, promotion=[dict(calm, max_lag_bytes=2_000_000)]))
        self.assertFalse(holds(over))
        self.assertIn('above it without a reset in attempts [2]', over['detail'])
        self.assertTrue(rd.line_attempt_lag_within_term(w(lag=lag, promotion=[]))['inconclusive'])
        self.assertTrue(rd.line_attempt_lag_within_term(w(lag={}, promotion=[calm]))['inconclusive'])

    def test_aligned_per_snapshot(self):
        self.assertTrue(holds(rd.line_aligned_per_snapshot(w(snapshots={'positions': [10, 20, 30], 'aligned_delta': 2}))))
        self.assertFalse(holds(rd.line_aligned_per_snapshot(w(snapshots={'positions': [10, 20, 30], 'aligned_delta': 1}))))
        self.assertTrue(rd.line_aligned_per_snapshot(w(snapshots={'positions': []}))['inconclusive'])

    def test_no_snapshot_yet_is_not_a_snapshot_position(self):
        # the gauge reads -1 before the first snapshot, an unreadable leader gives None; neither counts as a P_cm
        self.assertEqual(rd.snapshot_positions({-1, None, 0, 4096, 8192.0}), [4096, 8192])
        self.assertEqual(rd.snapshot_positions({-1, None}), [])
        self.assertTrue(rd.line_aligned_per_snapshot(w(snapshots={'positions': rd.snapshot_positions({-1})}))['inconclusive'])
        # one real position and the -1 of an attempt before it: one snapshot, so ALIGNED +0 holds (the last may be in flight)
        self.assertTrue(holds(rd.line_aligned_per_snapshot(
            w(snapshots={'positions': rd.snapshot_positions({-1, 4096}), 'aligned_delta': 0}))))


class LagAndCatalogLineTest(unittest.TestCase):
    def test_lag_inside_the_term_and_its_vacuity(self):
        lag = {'samples_with_lag': 600, 'max_lag_bytes': 180000.0, 'term_bytes': 1048576, 'achieved_hz': 9.8,
               'position': lag_sampler.POSITION_NOTE}
        self.assertTrue(holds(rd.line_lag_within_term(w(lag=lag))))
        self.assertFalse(holds(rd.line_lag_within_term(w(lag=dict(lag, max_lag_bytes=2e6)))))
        idle = rd.line_lag_within_term(w(lag=dict(lag, max_lag_bytes=0.0)))
        self.assertIn('no lag observed: the load did not reach the replica', idle['detail'])
        self.assertTrue(idle['inconclusive'])

    def test_the_sampler_control(self):
        rows = [{'t_ns': t * 100_000_000, 'lag_bytes': v} for t, v in
                enumerate([1000] * 50 + [60000, 120000, 180000] * 10 + [2000] * 50)]
        x = rd.pause_analysis(rows, 0, 50 * 100_000_000, 80 * 100_000_000, 10, 1048576)
        self.assertTrue(holds(rd.line_sampler_saw_pause(w(sampler_pause=x))))
        flat = [{'t_ns': t * 100_000_000, 'lag_bytes': 1000} for t in range(130)]
        y = rd.pause_analysis(flat, 0, 50 * 100_000_000, 80 * 100_000_000, 10, 1048576)
        line = rd.line_sampler_saw_pause(w(sampler_pause=y))
        self.assertFalse(holds(line))
        self.assertIn('sampler saw no lag during a 3.0 s pause', line['detail'])

    def test_catalog_bound_and_snapshot_not_triggered(self):
        # the bound is CATALOG_ALIGNED_BOUND_S plus the kind's backup query interval (13 s on the query kinds)
        q = {'catalog_bound_s': 18.0, 'query_interval_s': 13.0}
        ok = rd.line_catalog_bound(w(catalog=[{'position': 10, 'catalog_s': 1.2}, {'position': 20, 'catalog_s': 12.0}], **q))
        self.assertTrue(holds(ok))
        self.assertIn('bound 18.0 s = CATALOG_ALIGNED_BOUND_S 5 s + backup query interval 13.0 s', ok['detail'])
        self.assertFalse(holds(rd.line_catalog_bound(w(catalog=[{'position': 10, 'catalog_s': 18.1}], **q))))
        self.assertFalse(holds(rd.line_catalog_bound(w(catalog=[{'position': 10, 'catalog_s': None}], **q))))
        self.assertTrue(rd.line_catalog_bound(w(catalog=[{'position': 10, 'catalog_s': 1.0}]))['inconclusive'])
        none = rd.line_catalog_bound(w(catalog=[], **q))
        self.assertEqual((none['detail'], none['inconclusive']), ('snapshot not triggered', True))


class ReplicaLineTest(unittest.TestCase):
    def test_restart_wipe_and_second_life_restore_paths(self):
        ok = {'restore_path': 1, 'ready_after_start_s': 40.0, 'verified': 1.0}
        self.assertTrue(holds(rd.line_replica_restart_local(w(replica_restart=ok))))
        line = rd.line_replica_restart_local(w(replica_restart=dict(ok, restore_path=2)))
        self.assertIn('restarted replica did not restore from its local shadow', line['detail'])
        self.assertFalse(holds(rd.line_replica_restart_local(w(replica_restart=dict(ok, ready_after_start_s=61.0)))))
        self.assertTrue(holds(rd.line_replica_pulled(w(replica_wipe={'restore_path': 3, 'ready': True}))))
        self.assertIn('GENESIS', rd.line_replica_pulled(w(replica_wipe={'restore_path': 2, 'ready': True}))['detail'])
        self.assertTrue(holds(rd.line_second_life_local(w(second_life={'restore_path': 1, 'ready': True}))))
        self.assertFalse(holds(rd.line_second_life_local(w(second_life={'restore_path': 3, 'ready': True}))))

    def test_rebootstrap_exit_and_not_taken(self):
        x = {'exit_code': 3, 'replay_below_start_max': 3, 'rebootstrap_total_max': 0, 'replay_failures_setting': 3,
             'restart_line': 'ERROR CRITICAL replica restart (exit 3): members pruned past the local log'}
        self.assertTrue(holds(rd.line_rebootstrap_exit3(w(rebootstrap=x))))     # the counter is recorded, not required
        self.assertFalse(holds(rd.line_rebootstrap_exit3(w(rebootstrap=dict(x, replay_below_start_max=2)))))
        self.assertFalse(holds(rd.line_rebootstrap_exit3(w(rebootstrap=dict(x, restart_line=None)))))
        # detector only (SHADOW_REBOOTSTRAP_REPLAY_FAILURES 0): counts and never acts, and the kit never says not taken
        detector = {'exit_code': None, 'detector_only': True, 'replay_below_start_max': 4, 'refusals_needed': 3,
                    'missed_observed_s': 30.2, 'not_taken_max': 0,
                    'ready_status': 503, 'ready_body': 'unverified continuation'}
        line = rd.line_rebootstrap_exit3(w(rebootstrap=detector))
        self.assertFalse(holds(line))
        self.assertIn('re-bootstrap missed after 4 counted replay-below-start refusals', line['detail'])
        self.assertTrue(holds(rd.line_rebootstrap_refusals_counted(w(rebootstrap=detector))))
        self.assertFalse(holds(rd.line_rebootstrap_refusals_counted(w(rebootstrap=dict(detector, exit_code=3)))))
        self.assertFalse(holds(rd.line_rebootstrap_refusals_counted(w(rebootstrap=dict(detector, replay_below_start_max=2)))))

    def test_purge_witness_disk_and_fence(self):
        purged = {'replica_stop_position': 5_000_000, 'log_starts': {'ae0': 6291456, 'ae1': 6291456, 'ae2': 7340032}}
        self.assertTrue(holds(rd.line_members_purged(w(purge=purged))))
        line = rd.line_members_purged(w(purge=dict(purged, log_starts={'ae0': 1048576, 'ae1': 0, 'ae2': 1048576})))
        self.assertIn('no purge below the stopped replica', line['detail'])
        self.assertTrue(holds(rd.line_witness_missing_replica(w(witness_missing={'ae1': 1.0, 'ae2': 1.0}))))
        self.assertFalse(holds(rd.line_witness_missing_replica(w(witness_missing={'ae1': 1.0, 'ae2': 0.0}))))
        self.assertTrue(holds(rd.line_disk_grew(w(disk={'before': {'ae0': 1, 'ae1': 2}, 'after': {'ae0': 5, 'ae1': 9}}))))
        self.assertFalse(holds(rd.line_disk_grew(w(disk={'before': {'ae0': 1, 'ae1': 2}, 'after': {'ae0': 5, 'ae1': 2}}))))
        self.assertTrue(holds(rd.line_not_fenced(w(replica_fenced=0.0))))
        self.assertFalse(holds(rd.line_not_fenced(w(replica_fenced=1.0))))
        self.assertTrue(holds(rd.line_anchor_rule_any_verified(w(anchor_rule={'ae0': 0.0, 'ae1': 0.0, 'ae2': 0.0}))))
        self.assertFalse(holds(rd.line_anchor_rule_any_verified(w(anchor_rule={'ae0': 1.0, 'ae1': 0.0, 'ae2': 0.0}))))

    def test_peer_loss_lines(self):
        x = {'target': 'ae2', 'restore_path': 3, 'ready': True,
             'listing': {'contiguous': True, 'log_start_segment': 3145728}}
        self.assertTrue(holds(rd.line_peerloss_restore(w(peerloss=x))))
        self.assertFalse(holds(rd.line_peerloss_restore(w(peerloss=dict(x, restore_path=1)))))
        self.assertFalse(holds(rd.line_peerloss_restore(w(peerloss=dict(x, listing={'contiguous': False})))))
        loud = {'target': 'ae2', 'log_start_segment': 3145728, 'exit_code': 1, 'ready_200_seen': False,
                'restore_paths_seen': [0],
                'halt_line': 'FATAL shadow restore: stub at P_cm=9 and no restore path: ... (3) pull: tried 3 sources, 0 '
                             'candidates, refused 0, last: unreachable'}
        self.assertTrue(holds(rd.line_peerloss_loud_halt(w(peerloss=loud))))
        self.assertFalse(holds(rd.line_peerloss_loud_halt(w(peerloss=dict(loud, restore_paths_seen=[5])))))
        self.assertFalse(holds(rd.line_peerloss_loud_halt(w(peerloss=dict(loud, ready_200_seen=True)))))
        self.assertFalse(holds(rd.line_peerloss_loud_halt(w(peerloss=dict(loud, exit_code=0)))))
        at_zero = rd.line_peerloss_loud_halt(w(peerloss=dict(loud, log_start_segment=0)))
        self.assertTrue(at_zero['inconclusive'])
        self.assertTrue(holds(rd.line_pull_skip_unchanged(w(peerloss=dict(x, skipped_leader=0.0)))))
        self.assertFalse(holds(rd.line_pull_skip_unchanged(w(peerloss=dict(x, skipped_leader=1.0)))))

    def test_aligned_after_the_fault(self):
        ok = {'written': True, 'match_delta': 1, 'mismatch_delta': 0, 'waited_s': 40}
        self.assertTrue(holds(rd.line_aligned_after_fault(w(aligned_after=ok))))
        self.assertFalse(holds(rd.line_aligned_after_fault(w(aligned_after=dict(ok, mismatch_delta=1)))))
        self.assertFalse(holds(rd.line_aligned_after_fault(w(aligned_after=dict(ok, written=False)))))
        self.assertTrue(rd.line_aligned_after_fault(w())['inconclusive'])

    def test_the_filter_deletion_is_read_from_the_chain(self):
        listed = ('Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source'
                  '               destination\n      12      480 DROP       17   --  !lo    *       0.0.0.0/0            '
                  '0.0.0.0/0            udp dpt:19301\n')
        self.assertFalse(rd.rule_removed(listed, '172.30.1.13:19301'))
        self.assertTrue(rd.rule_removed(listed.replace('dpt:19301', 'dpt:19401'), '172.30.1.13:19301'))
        self.assertTrue(rd.rule_removed('Chain INPUT (policy ACCEPT)\n', '172.30.1.13:19301'))
        self.assertTrue(holds(rd.line_filters_removed(w(filters=[{'removed': True}]))))
        self.assertFalse(holds(rd.line_filters_removed(w(filters=[{'removed': True}, {'removed': False}]))))


class ControlVerdictTest(unittest.TestCase):
    PASS = {'status': 'PASS', 'rules': {}}

    def lines(self, **over):
        base = {name: {'holds': True, 'detail': 'ok'} for name in rd.LINES}
        base['fault_cycles'] = {'holds': True, 'detail': '3 rows'}
        base.update(over)
        return base

    def test_the_named_line_fails_with_its_text_and_the_kept_lines_hold(self):
        lines = self.lines(restore_path_shadow={'holds': False, 'detail': 'restore path FULL on ae0; restore path FULL on ae1'})
        self.assertEqual(rd.replica_control_verdict(self.PASS, self.PASS, lines, 'kill9-fullmode')['status'], 'PASS')

    def test_a_named_line_failing_for_another_reason_is_not_the_control(self):
        lines = self.lines(restore_path_shadow={'holds': False, 'detail': 'restore path NONE on ae0'})
        verdict = rd.replica_control_verdict(self.PASS, self.PASS, lines, 'kill9-fullmode')
        self.assertEqual(verdict['status'], 'FAIL')
        self.assertIn('without its text', verdict['reasons'][0])

    def test_a_vacuous_control_and_a_kept_line_that_fails(self):
        self.assertEqual(rd.replica_control_verdict(self.PASS, self.PASS, self.lines(), 'kill9-fullmode')['status'], 'FAIL')
        lines = self.lines(members_purged={'holds': False, 'detail': 'no purge below the stopped replica: ...'},
                           disk_grew={'holds': False, 'detail': 'flat'})
        verdict = rd.replica_control_verdict(self.PASS, self.PASS, lines, 'rebootstrap-nowitness')
        self.assertEqual(verdict['status'], 'FAIL')
        self.assertIn('disk_grew', verdict['reasons'][0])

    def test_the_companion_has_no_failing_line_and_keeps_its_skip_assertion(self):
        self.assertEqual(rd.replica_control_verdict(self.PASS, self.PASS, self.lines(), 'peerloss-loud-unblocked')['status'],
                         'PASS')
        lines = self.lines(pull_skip_unchanged={'holds': False, 'detail': 'skipped 1'})
        self.assertEqual(rd.replica_control_verdict(self.PASS, self.PASS, lines, 'peerloss-loud-unblocked')['status'], 'FAIL')

    def test_every_control_names_a_known_line_and_its_own_kind(self):
        for control, (drill, variant, named) in core_drills.CONTROLS.items():
            if control not in core_drills.REPLICA_CONTROL_EXPECT:
                continue
            expect = core_drills.REPLICA_CONTROL_EXPECT[control]
            self.assertEqual(sorted(named), sorted(expect['fail']), control)
            self.assertIn(variant['kind'], core_contracts.CUT_KINDS, control)
            for name in list(expect['fail']) + expect['hold']:
                self.assertIn(name, rd.LINES, (control, name))


class LagSamplerTest(unittest.TestCase):
    def test_parse_and_one_formula(self):
        text = ('# HELP x\ncore_log_position 5000\ncore_cluster_role 2\nshadow_replica_applied_position 4200\n'
                'shadow_replica_recorded_position 4800\nshadow_replica_internal_lag_bytes 600\n'
                'shadow_replica_time_lag_ms 12\nshadow_write_total{kind="ALIGNED"} 3\n')
        m = lag_sampler.parse(text)
        self.assertEqual(m['shadow_write_total{kind="ALIGNED"}'], 3.0)
        r = lag_sampler.row(7, 1, m, m)
        self.assertEqual((r['lag_bytes'], r['internal_lag'], r['recorded']), (800.0, 600.0, 4800.0))
        self.assertIsNone(lag_sampler.row(7, None, {}, m)['lag_bytes'])

    def test_the_sampler_follows_the_leader_and_counts_errors(self):
        role = {'m0': 2.0, 'm1': 0.0, 'm2': 0.0}
        positions = {'m0': 100.0, 'm1': 90.0, 'm2': 95.0}

        def fetch(url):
            if url == 'rep':
                return {'shadow_replica_applied_position': 80.0}
            if url == 'm2' and role[url] is None:
                raise OSError('down')
            return {'core_cluster_role': role[url], 'core_log_position': positions[url]}
        s = lag_sampler.Sampler(['m0', 'm1', 'm2'], 'rep', fetch, clock=lambda: 1)
        self.assertEqual((s.tick()['leader'], s.tick()['lag_bytes']), (0, 20.0))
        role.update(m0=0.0, m1=2.0)
        r = s.tick()
        self.assertEqual((r['leader'], r['lag_bytes']), (1, 10.0))
        role.update(m1=0.0, m2=None)
        self.assertIsNone(s.tick()['leader'])
        self.assertGreaterEqual(s.errors, 1)

    def test_summary_and_the_tsv_round_trip(self):
        rows = [lag_sampler.row(1_000_000_000 + i * 100_000_000, 0, {'core_log_position': 1000.0 + 170 * i},
                                {'shadow_replica_applied_position': 900.0 + 170 * i}) for i in range(11)]
        summary = lag_sampler.summarize(rows, 1_000_000_000, 2_100_000_000, 10, term_bytes=1048576)
        self.assertEqual((summary['samples'], summary['max_lag_bytes'], summary['within_term']), (11, 100.0, True))
        self.assertEqual(summary['achieved_hz'], 10.0)
        self.assertEqual(summary['log_bytes_per_s'], 1700.0)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'lag.tsv'
            path.write_text('\t'.join(lag_sampler.COLUMNS) + '\n' + ''.join(
                '\t'.join('' if r[c] is None else str(r[c]) for c in lag_sampler.COLUMNS) + '\n' for r in rows))
            back = lag_sampler.read_tsv(path)
            self.assertEqual([r['lag_bytes'] for r in back], [100.0] * 11)

    def test_the_command_line_ends_on_its_stop_file(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'lag'
            stop = Path(temp) / 'stop'; stop.write_text('stop\n')
            code = lag_sampler.main(['--members', 'http://127.0.0.1:9/metrics', '--replica', 'http://127.0.0.1:9/metrics',
                                     '--out', str(out), '--stop-file', str(stop), '--hz', '10', '--term-bytes', '1048576'])
            self.assertEqual(code, 0)
            summary = json.loads((out / 'summary.json').read_text())
            self.assertEqual((summary['samples'], summary['term_bytes']), (0, 1048576))
        with self.assertRaises(SystemExit):
            lag_sampler.main(['--members', 'a', '--replica', 'b', '--out', '/nonexistent/x', '--hz', '0', '--duration-s', '1'])


def catalog_descriptor(rid, stream, segment=1048576, state=1):
    """One archive.catalog entry in the layout core_fixture.catalog_descriptors reads (aligned to the header's 64)."""
    body = struct.pack('<qqqqqqqiiiiii', 0, 0, rid, 0, 0, 0, -1, 0, segment, 1048576, 8192, 5, stream) + b'\0' * 8
    return (struct.pack('<iiq', len(body), state, 0).ljust(32, b'\0') + body).ljust(128, b'\0')


def write_catalog(archive, streams):
    header = struct.pack('<iiqi', 196864, 32, max(streams) + 1, 64).ljust(32, b'\0')
    (archive / 'archive.catalog').write_bytes(
        header + b''.join(catalog_descriptor(rid, stream) for rid, stream in sorted(streams.items())) + b'\0' * 256)


class WipeShadowsTest(unittest.TestCase):
    def member(self, temp):
        f = test_replica_fixture.bare_fixture(test_replica_fixture.replica_manifest(temp))
        f.root = Path(temp) / 'root'
        base = f.root / 'state' / 'ae2' / 'state'
        (base / 'cluster').mkdir(parents=True); (base / 'archive').mkdir()
        entries = struct.pack('<qqqqqii', 4, 0, 0, 0, 0, -1, 0).ljust(64, b'\0') \
            + struct.pack('<qqqqqii', 6, 0, 0, 900, 0, 0, 1).ljust(64, b'\0')       # TERM 4, SNAPSHOT 6
        (base / 'cluster' / 'recording.log').write_bytes(entries)
        f.registry['containers']['ae2'] = 'cid'
        f.inspect = lambda kind, cid: {'State': {'Running': False}}
        f.save = lambda: None
        return f, base / 'archive'

    def test_only_shadow_stream_recordings_are_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            f, archive = self.member(temp)
            # log 4 (stream 100), snapshot 6 (107), shadows 9 and 11 (4301), the money journal 12 (4101)
            write_catalog(archive, {4: 100, 6: 107, 9: 4301, 11: 4301, 12: 4101})
            for name in ('4-0.rec', '4-1048576.rec', '6-0.rec', '9-0.rec', '11-0.rec', '12-0.rec', '12-1048576.rec'):
                (archive / name).write_bytes(b'abcd')
            witness = f.wipe_shadows('ae2')
            self.assertEqual(sorted(witness['files_removed']), ['11-0.rec', '9-0.rec'])
            self.assertEqual(witness['bytes_removed'], 8)
            self.assertEqual(sorted(p.name for p in archive.glob('*.rec')),
                             ['12-0.rec', '12-1048576.rec', '4-0.rec', '4-1048576.rec', '6-0.rec'])
            with self.assertRaises(Violation):
                f.wipe_shadows('me0')
            f.inspect = lambda kind, cid: {'State': {'Running': True}}
            with self.assertRaises(Violation):
                f.wipe_shadows('ae2')

    def test_a_non_shadow_recording_the_recording_log_does_not_name_survives(self):
        # the defect: every recording recording.log did not name was deleted, the money journal among them
        with tempfile.TemporaryDirectory() as temp:
            f, archive = self.member(temp)
            write_catalog(archive, {4: 100, 6: 107, 12: 4101, 13: 1001})
            for name in ('4-0.rec', '6-0.rec', '12-0.rec', '13-0.rec'):
                (archive / name).write_bytes(b'abcd')
            witness = f.wipe_shadows('ae2')
            self.assertEqual(witness['files_removed'], {})
            self.assertEqual(sorted(p.name for p in archive.glob('*.rec')), ['12-0.rec', '13-0.rec', '4-0.rec', '6-0.rec'])

    def test_a_segment_the_catalog_does_not_describe_stops_the_wipe(self):
        with tempfile.TemporaryDirectory() as temp:
            f, archive = self.member(temp)
            write_catalog(archive, {4: 100, 9: 4301})
            for name in ('4-0.rec', '9-0.rec', '12-0.rec'):
                (archive / name).write_bytes(b'abcd')
            with self.assertRaises(Inconclusive) as caught:
                f.wipe_shadows('ae2')
            self.assertIn('[12]', str(caught.exception))
            self.assertEqual(sorted(p.name for p in archive.glob('*.rec')), ['12-0.rec', '4-0.rec', '9-0.rec'])
            (archive / 'archive.catalog').unlink()                      # no catalog at all: nothing is removed either
            with self.assertRaises(Inconclusive):
                f.wipe_shadows('ae2')
            self.assertEqual(len(list(archive.glob('*.rec'))), 3)

    def test_the_delete_guard_refuses_any_non_shadow_descriptor(self):
        import core_fixture
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / '12-0.rec'
            path.write_bytes(b'money')
            for descriptor, keep in (({'stream': 4101}, ()), ({'stream': 100}, ()), (None, ()), ({}, ()),
                                     ({'stream': 4301}, {12})):
                with self.assertRaises(Violation):
                    core_fixture.delete_shadow_segment(path, descriptor, keep)
                self.assertTrue(path.is_file())
            self.assertEqual(core_fixture.delete_shadow_segment(path, {'stream': 4301}), 5)
            self.assertFalse(path.exists())


class DrillFrameTest(unittest.TestCase):
    def fixture(self, temp, kind):
        m = test_replica_fixture.replica_manifest(temp, kind) if kind in core_contracts.REPLICA_KINDS else \
            dict(test_core_fixture_manifest(temp), manifest_kind=kind)
        f = test_replica_fixture.bare_fixture(m)
        f.clock, f.sleep = (lambda: 0.0), (lambda s: None)
        return f

    def test_a_drill_refuses_a_kind_it_does_not_run_on(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(Inconclusive) as caught:
                rd.ReplicaDrillRun(self.fixture(temp, 'shadow-cooldown30'), 'supplierloss', Path(temp) / 'out')
            self.assertIn('runs on kinds', str(caught.exception))
            with self.assertRaises(Inconclusive) as caught:
                rd.ReplicaDrillRun(self.fixture(temp, 'shadow'), 'supplierloss', Path(temp) / 'out',
                                   variant={'kind': 'shadow-cooldown30', 'control': 'supplierloss-cooldown30'})
            self.assertIn('runs on kind shadow-cooldown30', str(caught.exception))
            run = rd.ReplicaDrillRun(self.fixture(temp, 'shadow-cooldown30'), 'supplierloss', Path(temp) / 'out',
                                     variant={'kind': 'shadow-cooldown30', 'control': 'supplierloss-cooldown30'})
            self.assertEqual(run.spec['lines'], ['supplier_loss_recovery'])
            self.assertGreater(run.spec['tap_extra_s'], 0)

    def test_every_drill_has_its_step_and_a_tap_long_enough(self):
        with tempfile.TemporaryDirectory() as temp:
            for name, spec in core_drills.DRILLS.items():
                if not spec.get('replica'):
                    continue
                kind = spec['kinds'][0]
                run = rd.ReplicaDrillRun(self.fixture(temp, kind), name, Path(temp) / name)
                self.assertTrue(hasattr(run, 'replica_' + spec['replica']), name)
                self.assertEqual(run.spec['story']['users'], core_drills.REPLICA_USERS)
                self.assertGreater(run.spec['tap_extra_s'], 0, name)
                plan = core_drills.plan_for(run.spec, 1)
                self.assertGreater(plan['tap_ms'], (120 + run.spec['tap_extra_s']) * 1000, name)


class EarlyTapEndTest(unittest.TestCase):
    """The tap ends at the drill's last step plus TAP_SETTLE_S, not at its summed worst-case window (on a virtual clock)."""

    def run_drill(self, temp, fault_s, honours_stop=True):
        f = DrillFrameTest.fixture(None, temp, 'shadow')
        clock = {'ns': 1_000 * 10**9}
        calls = {'stop': [], 'faults': 0}

        def sleep(seconds):
            clock['ns'] += int(seconds * 1e9)
        f.sleep = sleep
        run = rd.ReplicaDrillRun(f, 'replica-restart', Path(temp) / 'out')
        run.wall_ns = lambda: clock['ns']
        tap_ms = core_drills.plan_for(run.spec, 1)['tap_ms']

        def start(plan):
            f.registry['tap'] = {'started_ns': clock['ns'], 'duration_ms': plan['tap_ms'], 'life': 1}

        def stop_tap(life=None):
            calls['stop'].append(clock['ns'])
            return clock['ns']

        def read_tap_summary(life=None):
            worst = f.registry['tap']['started_ns'] + tap_ms * 1_000_000
            if (honours_stop and calls['stop']) or clock['ns'] >= worst:
                return {'line': 'TAP', 'summary': {'ended': 'stop' if calls['stop'] and honours_stop else 'duration'},
                        'transitions': []}
            raise Inconclusive('the tap printed no TAP density line: it is still running or died')

        def faults():
            calls['faults'] += 1
            sleep(fault_s)                 # the drill's own steps: each returns as soon as its condition holds
        f.start, f.stop_tap, f.read_tap_summary, f.start_story = start, stop_tap, read_tap_summary, (lambda kv: {})
        run.snap = lambda label: {}
        run.wait_marker = lambda name, bound: {'at_ns': clock['ns']}
        run.faults_replica = faults
        run.post_load = lambda: None
        run.wait_story = lambda: sleep(5) or {'line': 'STORY', 'summary': {}, 'lists': {}}
        run.pre_barrier = lambda: {'status': 'settled'}
        run.tap_rows = lambda: {}
        run.barrier = lambda story, tap, summary: ({}, {})
        run.build_sample = lambda *a: {}
        run.seal = lambda sample, first, second: sample
        run.witness = lambda sample, after: {}
        run.write_evidence = lambda *a: None
        run.decide = lambda money, order, lines, rows, sample, after: {
            'status': 'PASS' if all(v['holds'] for v in lines.values()) else 'FAIL'}
        held = {name: (lambda w: {'holds': True, 'detail': 'held'}) for name in run.spec['lines'] + ['fault_cycles']}
        passed = {'status': 'PASS'}
        with mock.patch.dict(core_drills.LINES, held), mock.patch.object(core_drills, 'of_rows', lambda *a: {}), \
                mock.patch.object(core_drills.core_oracle, 'judge', lambda sample: passed), \
                mock.patch.object(core_drills.order_oracle, 'judge', lambda sample: passed):
            started = clock['ns']
            result = run.run()
        self.assertEqual(result['status'], 'PASS')
        return run, (clock['ns'] - started) / 1e9, tap_ms / 1000, calls

    def test_a_drill_whose_lines_all_hold_returns_before_its_worst_case_window(self):
        with tempfile.TemporaryDirectory() as temp:
            run, wall, window, calls = self.run_drill(temp, fault_s=40)
            self.assertEqual(calls['faults'], 1)
            self.assertEqual(len(calls['stop']), 1)
            self.assertLess(wall, window / 2)
            self.assertAlmostEqual(wall, 40 + 5 + S['TAP_SETTLE_S'], delta=1)
            self.assertEqual(run.rw['tap_end']['ended'], 'stop')
            self.assertGreater(run.rw['tap_end']['saved_s'], 0)

    def test_a_step_that_waits_to_its_bound_keeps_the_worst_case_window(self):
        with tempfile.TemporaryDirectory() as temp:
            run, wall, window, calls = self.run_drill(temp, fault_s=10**4)
            self.assertEqual(calls['stop'], [])
            self.assertEqual(run.rw['tap_end']['ended'], 'duration')

    def test_a_tap_that_ignores_the_stop_file_ends_at_its_window_not_later(self):
        with tempfile.TemporaryDirectory() as temp:
            run, wall, window, calls = self.run_drill(temp, fault_s=40, honours_stop=False)
            self.assertEqual(len(calls['stop']), 1)
            self.assertEqual(run.rw['tap_end']['ended'], 'duration')
            self.assertLessEqual(wall, window + 1)


def test_core_fixture_manifest(temp):
    import test_core_fixture
    return test_core_fixture.manifest(temp)


class NamingTest(unittest.TestCase):
    """No plan ids and no em-dash in the files and names this change adds (naming by content)."""
    FILES = ['replica_drills.py', 'lag_sampler.py', 'test_replica_drills.py', 'test_replica_fixture.py',
             'nightly-cut-embedded.json', 'nightly-cut-external.json']
    PLAN_ID = re.compile(r'\b(RCS?\d*|S9|S-A0\d|D-S9[-\w]*|T-PL\d|PL[1-5]|FIX-\d+|BLOCKER-\d|NOTE-\d+|W[0-6]|Q-R\d*)\b'
                         r'|\b(PL\d*|S_A0\d|A0\d)_[A-Z]')
    # a setting name carries no plan-id segment (A05_..., S_A02_..., PL2_...)
    SETTING_ID = re.compile(r'(^|_)(RCS?\d*|S9|PL\d*|A0\d|QR\d*)(_|$)|(^|_)S_A0\d')

    def test_the_added_files_carry_no_plan_id_and_no_em_dash(self):
        for name in self.FILES:
            text = (HERE / name).read_text()
            self.assertNotIn(chr(0x2014), text, name)
            if name not in ('test_replica_drills.py',):              # this file names the pattern it refuses
                self.assertIsNone(self.PLAN_ID.search(text), (name, self.PLAN_ID.search(text)))

    def test_the_settings_are_named_by_content(self):
        for name in rd.SETTINGS_SPEC:
            self.assertIsNone(self.SETTING_ID.search(name), name)
        for shaped in ('A09_SAMPLE_S', 'S_A09_SAMPLE_S', 'PL9_SAMPLE', 'PL_SAMPLE'):     # the shapes it refuses
            self.assertIsNotNone(self.SETTING_ID.search(shaped), shaped)

    def test_kinds_drills_and_controls_are_named_by_content(self):
        names = list(core_contracts.REPLICA_KINDS) + sorted(core_contracts.FULL_KINDS) \
            + [n for n, s in core_drills.DRILLS.items() if s.get('replica')] + list(core_drills.REPLICA_CONTROL_EXPECT)
        for name in names:
            self.assertIsNone(self.PLAN_ID.search(name.upper()), name)


if __name__ == '__main__':
    unittest.main()
