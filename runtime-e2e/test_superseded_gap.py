# SPDX-License-Identifier: Apache-2.0
"""A dispatch gap after a ``new_leader`` note closes exactly when every missed seq is either traced (backfilled) or
accounted for by the core's superseded release mints:

    superseded = minted_up_to + minted_order - (tapped releases + ME-traced untapped releases)

read from ``core_release_superseded_total`` when the core exports it. Without the metric (an older cut) the gap stays
open as before. The fixture numbers are those of a recorded leader-loss run: gap [13575, 13577] after the third
new_leader (last_dispatch_seq 13574), the ME release record at 13575 holds (4909, 3) and (4950, 3), the core minted
8470 + 11945 = 20415 releases and the tap saw 20412."""
import unittest

import core_drills
import order_oracle
import replica_drills as rd
from oracle_model import superseded_account
from oracle_samples import clean_sample, variant


def rule(result, name):
    return result['rules'].get(name, {})


def counters(up_to, order, superseded, roles=('ae0', 'ae1', 'ae2'), abandoned=None):
    return {role: {'minted_up_to': up_to, 'minted_order': order, 'superseded': superseded, 'abandoned': abandoned}
            for role in roles}


NEW_LEADER = [{'event': 'registered', 'at_ms': 1, 'last_dispatch_seq': 0, 'last_event_seq': 0, 'session': 3, 'leader': 0},
              {'event': 'new_leader', 'at_ms': 2, 'last_dispatch_seq': 10, 'last_event_seq': 9, 'session': 3,
               'term': 1, 'leader': 1},
              {'event': 'reregistered', 'at_ms': 3, 'last_dispatch_seq': 10, 'last_event_seq': 9, 'session': 3,
               'leader': 1}]


def holed_after_new_leader(release_counters, transitions=NEW_LEADER, head=12):
    """The clean sample whose core minted two more dispatches (11, 12) after the tap's last row, across a new_leader:
    both were release mints superseded before any forwarder offered them."""
    def edit(s):
        s['core']['pending_dispatch']['head'] = head
        s['tap_continuity'] = {'transitions': transitions, 'release_counters': release_counters,
                               'summary': {'dispatch': {'gaps': [[11, head]]}, 'events': {'gaps': []}}}
    return variant(clean_sample(), edit)


class OracleTest(unittest.TestCase):
    def test_the_superseded_count_closes_a_gap_after_a_new_leader(self):
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, 2)))
        for name in ('O3', 'O10'):
            self.assertEqual(rule(order, name)['status'], 'PASS', order)
        account = order['tap_superseded']
        self.assertTrue(account['closes'], account)
        self.assertEqual((account['untraced'], account['superseded_derived'], account['superseded_metric']), (2, 2, 2))
        self.assertIn('superseded = minted_up_to 2 + minted_order 0 - (tapped 0 + ME-traced untapped 0) = 2',
                      account['arithmetic'])

    def test_an_older_cut_without_the_metric_keeps_todays_open_gap(self):
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, None)))
        self.assertEqual(rule(order, 'O3')['status'], 'INCONCLUSIVE')
        self.assertIn('tap gap [11, 12] not closed', rule(order, 'O3')['detail'])
        self.assertFalse(order['tap_superseded']['closes'])
        self.assertIn('core_release_superseded_total', order['tap_superseded']['why'])
        # no counters at all (a sample from before this rule): the same open gap, nothing recorded
        order = order_oracle.judge(holed_after_new_leader(None))
        self.assertIn('tap gap [11, 12] not closed', rule(order, 'O3')['detail'])

    def test_a_count_that_does_not_account_for_every_missed_seq_keeps_it_open(self):
        for c, why in ((counters(1, 0, 5), 'derived 1 != 2'), (counters(3, 0, 5), 'derived 3 != 2'),
                       (counters(2, 0, 1), 'above the core\'s superseded and abandoned count 1')):
            order = order_oracle.judge(holed_after_new_leader(c))
            self.assertIn('tap gap [11, 12] not closed', rule(order, 'O3')['detail'], c)
            self.assertIn(why, order['tap_superseded']['why'])

    def test_a_gap_not_after_a_new_leader_note_keeps_it_open(self):
        moved = [dict(n, last_dispatch_seq=9) if n['event'] != 'registered' else n for n in NEW_LEADER]
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, 2), transitions=moved))
        self.assertIn('tap gap [11, 12] not closed', rule(order, 'O3')['detail'])
        self.assertIn('does not start right after a new_leader note', order['tap_superseded']['why'])

    def test_the_member_with_the_fullest_count_is_read(self):
        # ae0 restored from a snapshot inside the run and counts only the log after it; ae2 replayed the whole run
        c = dict(counters(2, 0, 2, roles=('ae1', 'ae2')), ae0={'minted_up_to': 1, 'minted_order': 0, 'superseded': 1})
        order = order_oracle.judge(holed_after_new_leader(c))
        self.assertEqual(rule(order, 'O3')['status'], 'PASS', order)
        self.assertIn(order['tap_superseded']['member'], ('ae1', 'ae2'))

    def test_abandoned_release_entries_are_recorded_and_bound_the_unseen_seqs_with_the_supersedes(self):
        # an abandoned entry (RELEASED 7) also takes a pending release seq out of the index unseen: superseded 1 and
        # abandoned 1 together bound the 2 unseen seqs; the record names both and never claims which seqs they were
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, 1, abandoned=1)))
        self.assertEqual(rule(order, 'O3')['status'], 'PASS', order)
        account = order['tap_superseded']
        self.assertEqual((account['superseded_metric'], account['abandoned_metric']), (1, 1))
        self.assertIn('core_release_abandoned_total 1', account['arithmetic'])
        self.assertIn('not which seqs', account['why'])
        # without abandoned entries the supersedes alone bound them, as before
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, 1, abandoned=0)))
        self.assertIn('above the core\'s superseded and abandoned count 1', order['tap_superseded']['why'])
        record = rd.superseded_record(order_oracle.judge(holed_after_new_leader(counters(2, 0, 2, abandoned=0))))
        self.assertEqual(record['abandoned_metric'], 0)


class RecordedRunFixtureTest(unittest.TestCase):
    """The recorded run's numbers on rows shaped like its tap (the arithmetic, not the 58 MB sample)."""
    TRANSITIONS = [
        {'event': 'registered', 'at_ms': 1795058725614, 'last_dispatch_seq': 0, 'last_event_seq': 0, 'session': 3, 'leader': 0},
        {'event': 'new_leader', 'at_ms': 1795058839590, 'last_dispatch_seq': 373, 'last_event_seq': 473, 'session': 3,
         'term': 1, 'leader': 1},
        {'event': 'reregistered', 'at_ms': 1795058839647, 'last_dispatch_seq': 373, 'last_event_seq': 473, 'session': 3,
         'leader': 1},
        {'event': 'new_leader', 'at_ms': 1795058863842, 'last_dispatch_seq': 6303, 'last_event_seq': 8023, 'session': 3,
         'term': 2, 'leader': 0},
        {'event': 'reregistered', 'at_ms': 1795058863897, 'last_dispatch_seq': 6303, 'last_event_seq': 8023, 'session': 3,
         'leader': 0},
        {'event': 'new_leader', 'at_ms': 1795058892505, 'last_dispatch_seq': 13574, 'last_event_seq': 17279, 'session': 3,
         'term': 3, 'leader': 2},
        {'event': 'reregistered', 'at_ms': 1795058892560, 'last_dispatch_seq': 13574, 'last_event_seq': 17279, 'session': 3,
         'leader': 2}]
    SUMMARY = {'dispatch': {'first': 1, 'last': 32882, 'rows': 32879, 'duplicates': 0, 'gaps': [[13575, 13577]]},
               'events': {'first': 1, 'last': 41744, 'rows': 41739, 'duplicates': 0, 'gaps': [[17280, 17284]]}}
    REPLAY = {'span': {'from': 17279, 'until': 17284, 'gaps': [[17280, 17284]], 'tail': False}, 'requests': 1, 'added': 5,
              'lost': [], 'remaining_gaps': [], 'head': None, 'complete': True}

    @staticmethod
    def rows():
        """32879 tapped rows over [1, 32882] without 13575..13577, 20412 of them releases, and the two releases of the
        ME record at release_seq 13575 rebuilt by the backfill (seq null)."""
        out = []
        for seq in range(1, 32883):
            if 13575 <= seq <= 13577:
                continue
            kind = 'RELEASE_ID' if len(out) < 20412 else 'CREATE'
            out.append({'seq': seq, 'id_high': seq, 'id_low': 3 if kind == 'RELEASE_ID' else 0, 'kind': kind})
        for high in (4909, 4950):
            out.append({'seq': None, 'id_high': high, 'id_low': 3, 'kind': 'RELEASE_ID', 'source': 'backfill',
                        'origin': 'me_release'})
        return out

    def test_the_recorded_gap_is_one_superseded_release(self):
        rows = self.rows()
        self.assertEqual(sum(1 for r in rows if r['kind'] == 'RELEASE_ID' and r.get('source') != 'backfill'), 20412)
        account = superseded_account(rows, self.TRANSITIONS, counters(8470, 11945, 6000), 32882,
                                     summary=self.SUMMARY, event_replay=self.REPLAY)
        self.assertTrue(account['closes'], account)
        self.assertEqual(account['gaps'], [[13575, 13577]])
        self.assertEqual(account['after_new_leader'], [13575])
        self.assertEqual((account['missed'], account['backfilled'], account['untraced']), (3, 2, 1))
        self.assertEqual((account['minted_up_to'], account['minted_order'], account['tapped_releases'],
                          account['traced_untapped_releases'], account['superseded_derived']), (8470, 11945, 20412, 2, 1))
        self.assertIn('= 1', account['arithmetic'])
        # the order-event gap at the same new_leader: the ring replay closed it
        self.assertEqual(account['events'], {'gaps': [[17280, 17284]], 'replayed': True, 'remaining': []})

    def test_the_recorded_run_on_its_own_cut_keeps_the_gap_open(self):
        account = superseded_account(self.rows(), self.TRANSITIONS, counters(8470, 11945, None), 32882,
                                     summary=self.SUMMARY, event_replay=self.REPLAY)
        self.assertFalse(account['closes'])
        self.assertEqual(account['metric'], 'absent')


class DrillRecordTest(unittest.TestCase):
    def test_the_counters_come_from_the_barrier_scrape(self):
        scrape = {'ae0': {'core_release_minted_up_to_total': 8470.0, 'core_release_minted_order_total': 11945.0,
                          'core_release_superseded_total': 9.0, 'core_release_abandoned_total': 0.0},
                  'ae1': {'core_release_minted_up_to_total': 8470.0, 'core_release_minted_order_total': 11945.0},
                  'ae2': {'unavailable': 'refused'}, 'me0': {'match_trades_total': 1.0}}
        self.assertEqual(core_drills.release_counters(scrape), {
            'ae0': {'minted_up_to': 8470, 'minted_order': 11945, 'superseded': 9, 'abandoned': 0},
            'ae1': {'minted_up_to': 8470, 'minted_order': 11945, 'superseded': None, 'abandoned': None}})
        self.assertEqual(core_drills.release_counters({}), {})

    def test_the_drill_verdict_records_the_arithmetic(self):
        order = order_oracle.judge(holed_after_new_leader(counters(2, 0, 2)))
        record = rd.superseded_record(order)
        self.assertTrue(record['closes'])
        self.assertIn('superseded = minted_up_to 2', record['arithmetic'])
        self.assertIsNone(rd.superseded_record({'status': 'PASS', 'rules': {}}))


if __name__ == '__main__':
    unittest.main()
