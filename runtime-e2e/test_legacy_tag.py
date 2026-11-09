# SPDX-License-Identifier: Apache-2.0
"""The legacy tag profile carries the two adaptations a dry run of the old tag needed
into the harness, plus the tag-engine settings. No Docker."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import legacy_tag

SRC = {'match': 'a89335d15165ae8ddf603e0409dca0d81bdcb09a', 'assets': '374b62f584c3506658c6361b8556fe5d20f69be3',
       'oms': '25f30bdbcf53f8a5c83e4f516daee20a3a4b396f'}


def bare(cls=None):
    f = (cls or legacy_tag.LegacyTagFixture).__new__(cls or legacy_tag.LegacyTagFixture)
    f.registry = {'containers': {'me0': 'c-me0', 'ae1': 'c-ae1', 'oms': 'c-oms'}}
    return f


class PsqlPinTest(unittest.TestCase):
    def test_timescaledb_extension_is_pinned_to_the_host_package(self):
        seen = []
        with mock.patch.object(legacy_tag.fixture.Fixture, 'psql', lambda self, db, sql: seen.append((db, sql)) or ''):
            f = bare()
            f.psql('r01_market', 'CREATE EXTENSION timescaledb')
            f.psql('r01_oms', 'SELECT 1')
        self.assertEqual(seen, [('r01_market', "CREATE EXTENSION timescaledb VERSION '2.28.2'"), ('r01_oms', 'SELECT 1')])
        self.assertEqual(legacy_tag.TIMESCALEDB_VERSION, '2.28.2')     # a setting (the host's version may drift)


class MarkerReadinessTest(unittest.TestCase):
    def logs(self, text):
        return lambda argv, **kw: types.SimpleNamespace(stdout=text, stderr='', returncode=0)

    def test_tag_engines_are_ready_on_their_log_marker(self):
        f = bare(); f.sleep = lambda s: None
        with mock.patch.object(legacy_tag.subprocess, 'run', self.logs('... SERVICE onStart complete ...')):
            r = f.wait_http('me0', 19500, '/ready', timeout=5)
        self.assertEqual(r['status'], 200); self.assertIn('log marker', r['body'])
        with mock.patch.object(legacy_tag.subprocess, 'run', self.logs('Money journal writer started')):
            self.assertEqual(f.wait_http('ae1', 19700, '/ready', timeout=5)['status'], 200)

    def test_a_missing_marker_is_inconclusive(self):
        f = bare(); f.sleep = lambda s: None
        clock = iter(range(0, 1000, 10))
        with mock.patch.object(legacy_tag.subprocess, 'run', self.logs('starting')), \
                mock.patch.object(legacy_tag.time, 'monotonic', lambda: next(clock)):
            with self.assertRaisesRegex(Inconclusive, 'tag engine log marker missing: me0'):
                f.wait_http('me0', 19500, '/ready', timeout=30)

    def test_other_waits_are_the_fixture_s(self):
        f = bare()
        with mock.patch.object(legacy_tag.fixture.Fixture, 'wait_http', lambda self, *a, **k: 'base'):
            self.assertEqual(f.wait_http('oms', 18080, '/api/v1/health'), 'base')


class StopAndToolTest(unittest.TestCase):
    def test_tag_engines_stop_by_sigkill(self):
        f = bare(); calls = []
        f.command = lambda argv, **kw: calls.append([str(a) for a in argv]) or types.SimpleNamespace(stdout='', returncode=0)
        f.stop_engines(['me0', 'ae1'])
        self.assertEqual(calls, [['docker', 'kill', '--signal', 'KILL', 'c-me0'], ['docker', 'kill', '--signal', 'KILL', 'c-ae1']])
        with self.assertRaises(Violation):
            f.stop_engines(['oms'])

    def test_snapshot_trigger_is_cluster_tool_on_the_leader(self):
        f = bare(); runs = []
        logs = {'n': 0}

        def execute(name, argv, **kw):
            runs.append((name, argv[-1]))
            if argv[-1] == 'list-members':
                return types.SimpleNamespace(stdout='currentTimeNs=1, leaderMemberId=1, memberId=0', stderr='', returncode=0)
            if argv[-1] == 'recording-log':
                logs['n'] += 1
                return types.SimpleNamespace(stdout='SNAPSHOT entry' * (logs['n'] > 2), stderr='', returncode=0)
            return types.SimpleNamespace(stdout='SNAPSHOT applied successfully', stderr='', returncode=0)
        f.execute = execute; f.sleep = lambda s: None
        f.registry['containers'].update(me1='c-me1', me2='c-me2')
        lead, witness = f.snapshot('me', bound_s=30)
        self.assertEqual(lead, 1)
        self.assertIn(('me1', 'snapshot'), runs)
        self.assertIn('SNAPSHOT', witness)
        self.assertEqual(legacy_tag.CLUSTER_TOOL[:3], ['java', '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED'])


class LegacyManifestTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); root = self.root = Path(self.temp.name)
        self.jars = root / 'jars'; self.jars.mkdir()
        lines = []
        for name, repo in legacy_tag.TAG_JARS.values():
            data = b'tag ' + name.encode(); (self.jars / name).write_bytes(data)
            lines.append(f'{hashlib.sha256(data).hexdigest()}  v0.5.0-beta/{name}  source_sha={SRC[repo]}  recipe=r  recipe_sha256={"0" * 64}')
        self.pins = root / 'old-artifacts.sha256'; self.pins.write_text('\n'.join(lines) + '\n')
        nodes = {r: f'172.30.9.{10 + i}' for i, r in enumerate(['ae0', 'ae1', 'ae2', 'me0', 'me1', 'me2', 'oms', 'market', 'bridge',
                                                               'projector', 'probe', 'xprojector'])}
        self.template = root / 'template.json'
        self.template.write_text(json.dumps({'run_id': 'r01-000000000000', 'state_root': '/x', 'nodes': nodes,
                                             'network': {'subnet': '172.30.9.0/24', 'internal': True}, 'journal_cutover': {},
                                             'artifacts': {}, 'limits': {'shm_mb': 1024, 'memory_mb': 2048}, 'cpu_set': [0],
                                             'postgres_port': 1, 'test_helper': {}, 'benchmark_helper': {}}))

    def tearDown(self):
        self.temp.cleanup()

    def test_manifest_takes_only_pinned_tag_jars(self):
        path, m = legacy_tag.legacy_manifest('seed-a', 140, self.root / 'runs', jars=self.jars, pins=self.pins,
                                             template=self.template)
        self.assertEqual(set(m['artifacts']), set(legacy_tag.TAG_JARS))
        self.assertEqual(m['artifacts']['oms']['source_sha'], SRC['oms'])
        self.assertEqual((m['limits']['shm_mb'], m['limits']['memory_mb']), (4096, 4096))       # settings
        self.assertNotIn('xprojector', m['nodes']); self.assertNotIn('journal_cutover', m)
        self.assertEqual(m['nodes']['me0'], '172.30.140.13')
        self.assertEqual(m['legacy_tag_profile']['timescaledb_version'], '2.28.2')
        (self.jars / 'oms-app.jar').write_bytes(b'not the pinned build')
        with self.assertRaisesRegex(Violation, 'oms-app.jar is not pinned in'):
            legacy_tag.legacy_manifest('seed-b', 141, self.root / 'runs', jars=self.jars, pins=self.pins, template=self.template)


class TreeHashTest(unittest.TestCase):
    def test_tree_hash_is_over_sorted_relative_paths_and_file_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'a').mkdir(); (root / 'a/x').write_bytes(b'1'); (root / 'b').write_bytes(b'2')
            first = legacy_tag.tree_hash(root)
            (root / 'b').write_bytes(b'3')
            self.assertNotEqual(first['sha256'], legacy_tag.tree_hash(root)['sha256'])
            self.assertEqual(first['files'], 2)


if __name__ == '__main__':
    unittest.main()
