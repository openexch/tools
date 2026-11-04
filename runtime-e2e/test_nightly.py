# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W2/W4 (contract 5.4, 20.1 line 20): child manifests are written under the names mk_manifests.py produces,
``<kind>--<tag>.json``, so the S16 kind rule (``validate_build_b``) accepts a child of a kinded manifest. No Docker."""
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import core_contracts
import core_scenarios
import nightly


class ChildManifestNameTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = Path(self.temp.name)
        self.path = self.dir / 's16-ext--night.json'

    def tearDown(self):
        self.temp.cleanup()

    def template(self, kind='s16-ext'):
        m = {'run_id': 'rc2-0123456789ab', 'state_root': str(self.dir / 'fixtures' / 'rc2-0123456789ab'), 'artifacts': {}}
        if kind:
            m['manifest_kind'] = kind
        return m

    def accepted(self, path):
        child = json.loads(Path(path).read_text())
        core_contracts.validate_build_b(child, path)          # the kind rule: raises on <run_id>-manifest.json (W0)
        self.assertEqual(Path(child['state_root']), Path(path).parent / 'fixtures' / child['run_id'])
        return child

    def test_nightly_derive_keeps_the_kind_in_the_file_name(self):
        path = nightly.derive(self.template(), self.path, 'core-drill-a04-regenesis')
        self.assertTrue(path.name.startswith('s16-ext--'), path.name)
        child = self.accepted(path)
        self.assertNotEqual(child['run_id'], 'rc2-0123456789ab')
        second = nightly.derive(self.template(), self.path, 'core-drill-a04-regenesis')
        self.assertNotEqual(path, second)

    def test_unkinded_template_keeps_the_old_name(self):
        path = nightly.derive(self.template(None), self.dir / 'template.json', 'core-smoke')
        self.assertTrue(path.name.endswith('-manifest.json'), path.name)
        self.accepted(path)

    def test_consecutive_boots_children_keep_the_kind(self):
        seen = []

        def popen(argv, **kw):
            manifest = Path(argv[argv.index('--manifest') + 1]); output = Path(argv[argv.index('--output') + 1])
            seen.append(manifest); output.mkdir(parents=True)
            (output / 'result.json').write_text(json.dumps({'status': 'PASS', 'teardown': 'COMPLETE_OWNED_RESOURCES_ONLY'}))
            return types.SimpleNamespace(wait=lambda timeout=None: 0)
        m = dict(self.template('s16'), timeouts='production', limits={'cpu_set_by_role': {}})
        out = self.dir / 'out'; out.mkdir()
        with mock.patch.object(core_scenarios.subprocess, 'Popen', popen):
            result = core_scenarios.consecutive_boots(m, self.dir / 's16--boots.json', out, 2)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(len(seen), 2)
        for path in seen:
            self.assertTrue(path.name.startswith('s16--'), path.name)
            self.accepted(path)


if __name__ == '__main__':
    unittest.main()
