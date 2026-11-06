# SPDX-License-Identifier: Apache-2.0
"""RC2 S15 W2: CoreProbe story and tap against a reply stub (contract 5.7, 6, 6.1). No cluster.

The cases live in java/CoreProbeTest.java (they drive the story and the egress listener in the probe's own
JVM, on the AE jar it runs with). This module compiles CoreProbe.java with them, runs them, and then reads the
request logs they wrote through the real oracle model, so the story's rows are checked against the reader
that judges them. Needs a JDK 21 (javac, java) and the S13 AE jar named by CORE_PROBE_AE_JAR; without them the
whole class is SKIPPED with that reason (never a silent pass).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import oracle_model
import order_oracle

HERE = Path(__file__).resolve().parent
AE_JAR = os.environ.get('CORE_PROBE_AE_JAR')
JAVA_FLAGS = ['--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED', '--add-opens', 'java.base/sun.nio.ch=ALL-UNNAMED',
              '--add-opens', 'java.base/java.nio=ALL-UNNAMED']
CASES = ['a01_request_log_is_a_function_of_the_seed', 'a02_request_log_is_a_function_of_the_seed',
         'a01_open_loop_never_waits_for_a_reply', 'a01_cancels_target_live_own_orders',
         'markers_are_written_once_per_moment', 'without_iceberg_removes_the_moment',
         'unknown_replies_are_resolved_by_resend_with_the_same_request_id', 'unanswered_resend_leaves_the_row_unresolved',
         'unoffered_rows_are_unsent_not_unknown', 'hold_waits_for_the_gate_file', 'hold_without_gate_file_expires_loudly',
         'story_refuses_ambiguous_arguments', 'funding_plan_covers_every_user_and_asset',
         'a03_fill_runs_the_three_phases_with_markers', 'a03_open_timeout_starts_phase_three_with_opened_false',
         'a03_summary_counts_gate_rejects_and_reopen_acks', 'a03_request_log_is_a_function_of_the_seed',
         'a03_refuses_ambiguous_arguments', 'a01_ioc_burst_follows_the_marker_for_two_seconds',
         'a01_takes_120_users_and_funding_covers_them', 'money_dump_exports_the_v7_halt_fields',
         'listener_routes_story_replies_by_correlation', 'tap_reports_dispatch_gaps_and_new_leader',
         'tap_dense_run_reports_no_gap', 'order_dump_keeps_every_page']
# the sample's request rows (oracle_model docstring; core_scenarios._create writes the same create keys)
CREATE_KEYS = {'request', 'user', 'market', 'side', 'type', 'tif', 'price', 'quantity', 'budget', 'stop_price', 'display_qty',
               'reply'}
STORY_KEYS = {'id', 'expires', 'moment', 'scheduled_ns', 'sent_ns', 'reply_ns'}
AMEND_KEYS = {'request', 'user', 'order', 'new_price', 'new_quantity', 'reply'}
CANCEL_KEYS = {'request', 'user', 'order', 'reply'}
FUNDING_KEYS = {'request', 'kind', 'user', 'asset', 'amount'}
ACK_KEYS = {'outcome', 'order', 'duplicate', 'hold_asset', 'hold_amount', 'status'}


def load(path):
    lists = {'creates': [], 'amends': [], 'cancels': [], 'unsent': [], 'funding': []}
    for line in path.read_text().splitlines():
        entry = json.loads(line)
        lists[entry['story']].append(entry['row'])
    return lists


def model_sample(lists):
    """The smallest sample oracle_model.Model reads the request rows from (markets 1..5 of Market.ALL)."""
    return {'markets': {str(m): {'base': m, 'quote': 0} for m in range(1, 6)}, 'declared': {}, 'me_journal': [],
            'core': {'live_orders': []}, 'creates': lists['creates'], 'amends': lists['amends'],
            'cancels': lists['cancels'], 'dispatch_tap': [], 'core_events': []}   # core_events: the W3 Model reads tap continuity


@unittest.skipUnless(AE_JAR and Path(AE_JAR).is_file() and shutil.which('javac') and shutil.which('java'),
                     'set CORE_PROBE_AE_JAR to the S13 assets-cluster.jar (and put a JDK 21 on PATH) to run the W2 cases')
class StoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='core-probe-test-')
        root = Path(cls.tmp.name)
        classes = root / 'classes'; classes.mkdir()
        cls.out = root / 'out'
        subprocess.run(['javac', '-proc:none', '--release', '21', '-cp', AE_JAR, '-d', str(classes),
                        str(HERE / 'java' / 'CoreProbe.java'), str(HERE / 'java' / 'CoreProbeTest.java')],
                       check=True, capture_output=True, text=True)
        cls.java_run = subprocess.run(['java', *JAVA_FLAGS, '-cp', f'{classes}:{AE_JAR}', 'CoreProbeTest', str(cls.out)],
                                 capture_output=True, text=True, timeout=600)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_java_case_passes(self):
        lines = self.java_run.stdout.splitlines()
        for case in CASES:
            with self.subTest(case=case):
                self.assertIn('PASS ' + case, lines, self.java_run.stdout + self.java_run.stderr)
        self.assertEqual(self.java_run.returncode, 0, self.java_run.stdout + self.java_run.stderr)

    def test_rows_carry_the_sample_key_set(self):
        for name in ['a01-mix.jsonl', 'a02-lifecycle.jsonl', 'a01-resolved.jsonl', 'a03-fill.jsonl']:
            lists = load(self.out / name)
            self.assertTrue(lists['creates'], name)
            for row in lists['creates']:
                self.assertLessEqual(CREATE_KEYS | STORY_KEYS, set(row), (name, row))
                oracle_model.request_key(row['request'])
                self.assertIn(row['reply']['outcome'], {'ACK', 'REJECT', 'UNKNOWN'}, row)
                if row['reply']['outcome'] == 'ACK':
                    self.assertLessEqual(ACK_KEYS, set(row['reply']), row)
            for row in lists['amends']:
                self.assertLessEqual(AMEND_KEYS, set(row), (name, row))
            for row in lists['cancels']:
                self.assertLessEqual(CANCEL_KEYS, set(row), (name, row))
            self.assertEqual(lists['unsent'], [], name)
        funding = load(self.out / 'funding.jsonl')['funding']
        self.assertEqual(len(funding), 12)
        for row in funding:
            self.assertLessEqual(FUNDING_KEYS, set(row), row)
            oracle_model.request_key(row['request'])

    def test_model_reads_the_story_rows(self):
        lists = load(self.out / 'a01-mix.jsonl')
        model = oracle_model.Model(model_sample(lists))
        acked = [r for r in lists['creates'] if r['reply']['outcome'] == 'ACK']
        self.assertEqual(len(model.orders), len(acked))
        order_oracle.o1(model)   # every requestId minted one order, no replay

    def test_model_reads_the_a03_rows(self):
        lists = load(self.out / 'a03-fill.jsonl')
        self.assertEqual(lists['cancels'], [])
        self.assertEqual({r['moment'] for r in lists['creates']}, {'fill', 'reopen'})
        model = oracle_model.Model(model_sample(lists))
        order_oracle.o1(model)

    def test_resolved_log_is_judged_after_w3(self):
        """6.1 rule 2 (W3): the story's resolved UNKNOWN originals are judged as their re-send's verdict. W2 pinned the
        c781b4c reading here (O1 INCONCLUSIVE "create outcome unknown"); W3 turns it."""
        lists = load(self.out / 'a01-resolved.jsonl')
        unknown = [r for r in lists['creates'] if r['reply']['outcome'] == 'UNKNOWN']
        self.assertEqual(len(unknown), 3)
        self.assertTrue(all('resolved_by' in r for r in unknown), unknown)
        resolving = {r['resolves']: r for r in lists['creates'] if 'resolves' in r}
        for r in unknown:
            self.assertEqual(resolving[r['id']]['request'], r['request'])
        model = oracle_model.Model(model_sample(lists))
        self.assertEqual(model.unresolved, [])
        order_oracle.o1(model)


if __name__ == '__main__':
    unittest.main()
