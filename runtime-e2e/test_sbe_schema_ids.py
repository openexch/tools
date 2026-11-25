# SPDX-License-Identifier: Apache-2.0
"""One SBE schema id names one wire schema: sbe-schema-ids.txt (repo root, the same file in every repo) against the
schema copies under runtime-e2e/schemas, and the checker's negative controls."""
import io
import contextlib
from pathlib import Path
import unittest

import check_sbe_schema_ids as ids

ROOT = Path(__file__).resolve().parent.parent


class SbeSchemaIdsTest(unittest.TestCase):
    def test_registry_and_schema_copies_agree(self):
        problems = ids.check(str(ROOT), 'tools', copies_under=['runtime-e2e/schemas'])
        self.assertEqual(problems, [])

    def test_every_rule_fails_on_a_broken_input(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ids.self_test()
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn('0 failed', out.getvalue())


if __name__ == '__main__':
    unittest.main()
