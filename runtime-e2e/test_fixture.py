# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import sys
import tempfile
import unittest

from contracts import Inconclusive
from fixture import Fixture
from scenarios import order_id


class FixtureContractTest(unittest.TestCase):
    def test_int64_json_identity_never_rounds(self):
        self.assertEqual(order_id('362704708969721856'), 362704708969721856)
        for bad in [True, 362704708969721856.0, '1e18', '0', '-1', '9223372036854775808', None]:
            with self.subTest(bad=bad), self.assertRaises(Inconclusive): order_id(bad)

    def test_real_failed_child_cannot_pass_and_retains_output(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture.__new__(Fixture)
            fixture.root = Path(temp); (fixture.root / 'logs').mkdir()
            fixture.registry = {'command_seq': 0}
            with self.assertRaises(Inconclusive):
                fixture.command([sys.executable, '-c', 'print("negative-control-reached"); raise SystemExit(17)'])
            row = json.loads((fixture.root / 'commands.jsonl').read_text())
            self.assertEqual(row['exit_code'], 17)
            self.assertIn('negative-control-reached', Path(row['output']).read_text())

    def test_real_timeout_cannot_pass_and_retains_output(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Fixture.__new__(Fixture)
            fixture.root = Path(temp); (fixture.root / 'logs').mkdir()
            fixture.registry = {'command_seq': 0}
            with self.assertRaises(Inconclusive):
                fixture.command([sys.executable, '-u', '-c', 'import time; print("started"); time.sleep(3)'], timeout=.1)
            row = json.loads((fixture.root / 'commands.jsonl').read_text())
            self.assertEqual(row['exit_code'], 124)
            self.assertIn('started', Path(row['output']).read_text())
