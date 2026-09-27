# SPDX-License-Identifier: Apache-2.0
import unittest
from contracts import Violation
from log_channel_fault import filter_arguments


class LogFilterTest(unittest.TestCase):
    def test_only_replication_port_on_explicit_engine_member_is_filtered(self):
        m = {'ports': {'me_base': 9000, 'ae_base': 19300, 'stride': 100}}
        self.assertEqual(filter_arguments(m, 'me2', 'add')[-3:], ['9204', '-j', 'DROP'])
        self.assertEqual(filter_arguments(m, 'ae1', 'delete')[2], '-D')
        self.assertIn('19404', filter_arguments(m, 'ae1', 'delete'))
        for target in ('oms', 'me3', '', 'host', 'me0;true'):
            with self.assertRaises(Violation): filter_arguments(m, target, 'add')
        with self.assertRaises(Violation): filter_arguments(m, 'me0', 'flush')


if __name__ == '__main__': unittest.main()
