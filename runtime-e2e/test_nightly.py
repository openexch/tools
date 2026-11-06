# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W2/W4 (contract 5.4, 20.1 line 20): child manifests are written under the names mk_manifests.py produces,
``<kind>--<tag>.json``, so the S16 kind rule (``validate_build_b``) accepts a child of a kinded manifest. No Docker."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import core_contracts
import core_scenarios
from contracts import Violation
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


# ------------------------------------------------------------------ RC2 S17 W4 (contract 5.4, 8.3): the plan nightly

class FakeHost(nightly.Host):
    """No docker, no runner, no clock: records what the night would have done."""
    def __init__(self, containers=(), fixture=(), load=0.5, results=None, durations=None):
        self.containers, self.fixture, self.load, self.removed, self.started = list(containers), list(fixture), load, [], []
        self.results, self.durations, self.clock = results or {}, durations or {}, 0.0

    def fixture_containers(self): return list(self.fixture)
    def running_containers(self): return list(self.containers)
    def remove_container(self, cid): self.removed.append(cid); self.fixture = [c for c in self.fixture if c != cid]
    def load5(self): return self.load
    def monotonic(self): return self.clock
    def make_manifest(self, entry, index, work, settings):
        path = work / f'{entry["kind"]}--night-{index}.json'; work.mkdir(parents=True, exist_ok=True); path.write_text('{}\n')
        return path

    def run_entry(self, entry, manifest, output, log, timeout):
        key = entry['scenario']; self.started.append(key)
        duration = self.durations.get(key, 10.0)
        if timeout is not None and duration > timeout:
            self.clock += timeout
            return 'TIMEOUT', None
        self.clock += duration
        output.mkdir(parents=True)
        status = self.results.get(key, 'PASS')
        (output / 'result.json').write_text(json.dumps({'status': status, 'error': None if status == 'PASS' else 'x'}))
        log.write('ran ' + key + '\n')
        return 'DONE', 0 if status == 'PASS' else 1


def plan2():
    return [{'kind': 's17', 'scenario': 'core-boots-1'}, {'kind': 's17-ext', 'scenario': 'core-drill-a04-regenesis'}]


class PlanTest(unittest.TestCase):
    def test_plan_refuses_unknown_kind_and_scenario(self):
        with self.assertRaisesRegex(Violation, 'unknown kind'):
            nightly.parse_plan([{'kind': 's99', 'scenario': 'core-smoke'}])
        with self.assertRaisesRegex(Violation, 'unknown scenario'):
            nightly.parse_plan([{'kind': 's17', 'scenario': 'core-drill-nonesuch'}])
        with self.assertRaisesRegex(Violation, 'unknown scenario'):
            nightly.parse_plan([{'kind': 's17', 'scenario': 'core-boots-0'}])
        with self.assertRaisesRegex(Violation, 'entry'):
            nightly.parse_plan([{'kind': 's17'}])
        with self.assertRaisesRegex(Violation, 'entry'):
            nightly.parse_plan([{'kind': 's17', 'scenario': 'core-smoke', 'extra': 1}])
        with self.assertRaisesRegex(Violation, 'empty'):
            nightly.parse_plan([])

    def test_plan_accepts_the_known_names(self):
        plan = nightly.parse_plan({'entries': plan2() + [{'kind': 's17-red-a04', 'scenario': 'core-red-a04'},
                                                         {'kind': 's17', 'scenario': 'core-control-a06-n1'}]})
        self.assertEqual(len(plan), 4)

    def test_default_plan_is_valid_and_ends_with_boots(self):
        plan = nightly.parse_plan(json.loads((Path(__file__).with_name('nightly-cut.json')).read_text()))
        self.assertEqual(plan[-1], {'kind': 's17', 'scenario': 'core-boots-10'})
        self.assertGreaterEqual(len(plan), 18 + 4)           # contract 7.1: 18 drills and the embedded repeats at least
        self.assertEqual(len({(e['kind'], e['scenario']) for e in plan}), len(plan))


class NightBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = Path(self.temp.name)
        self.ev = self.dir / 'evidence'; self.ev.mkdir(); self.work = self.dir / 'work'
        self.lock = self.dir / 'heavy.lock'

    def tearDown(self):
        self.temp.cleanup()

    def settings(self, **kw):
        base = dict(lock=str(self.lock), bound_s=18000.0, after_interrupt='run', load_max=6.0, harness_commit='a' * 40)
        base.update(kw)
        return nightly.Settings(**base)

    def night(self, host, plan=None, **kw):
        host.clock_start = host.monotonic()
        return nightly.run_night(plan or nightly.parse_plan(plan2()), self.ev, self.work, self.settings(**kw), host)

    def summary(self, night):
        return json.loads((self.ev / night / 'summary.json').read_text())


class LockTest(NightBase):
    def test_held_lock_is_skipped_busy_and_runs_nothing(self):          # nightly-busy
        host = FakeHost()
        holder = open(self.lock, 'a'); fcntl.flock(holder, fcntl.LOCK_EX)
        code, summary = self.night(host)
        self.assertEqual((code, summary['status']), (75, 'SKIPPED_BUSY'))
        self.assertEqual(host.started, []); self.assertEqual(host.removed, [])
        self.assertEqual(summary['lock'], str(self.lock))
        self.assertEqual(summary['entries'], [])
        # the lock is per night and released on exit: the same test then runs a normal night (C4)
        fcntl.flock(holder, fcntl.LOCK_UN); holder.close()
        code, summary = self.night(host)
        self.assertEqual((code, summary['status']), (0, 'PASS'))
        self.assertEqual(host.started, ['core-boots-1', 'core-drill-a04-regenesis'])
        code, summary = self.night(host)            # released again by the night just finished
        self.assertEqual(code, 0)

    def test_busy_night_is_sealed(self):
        holder = open(self.lock, 'a'); fcntl.flock(holder, fcntl.LOCK_EX)
        _, summary = self.night(FakeHost())
        self.assertTrue(nightly.verify_seal(self.ev / summary['night']))
        holder.close()


class PreflightTest(NightBase):
    def test_unfinished_night_dir_is_interrupted_then_runs(self):       # nightly-stale (dir half)
        (self.ev / '20200101T000000Z').mkdir(); (self.ev / '20200102T000000Z').mkdir()
        (self.ev / '20200102T000000Z' / 'half.log').write_text('x')
        host = FakeHost()
        code, summary = self.night(host)
        self.assertEqual(summary['status'], 'PASS')
        self.assertEqual(sorted(summary['interrupted']['unfinished_night_dirs']), ['20200101T000000Z', '20200102T000000Z'])
        for name in ('20200101T000000Z', '20200102T000000Z'):
            old = self.summary(name)
            self.assertEqual(old['status'], 'INTERRUPTED')
        code, second = self.night(host)                  # recorded once: the second night finds nothing unfinished (C4)
        self.assertNotIn('interrupted', second)

    def test_stale_fixture_container_is_removed_and_after_interrupt_skip(self):   # nightly-stale (container half)
        host = FakeHost(containers=['c1'], fixture=['c1'])
        code, summary = self.night(host, after_interrupt='skip')
        self.assertEqual((code, summary['status']), (0, 'INTERRUPTED'))
        self.assertEqual(host.removed, ['c1']); self.assertEqual(host.started, [])
        self.assertEqual(summary['interrupted']['stale_fixture_containers'], ['c1'])

    def test_stale_container_removed_then_night_runs_by_default(self):
        host = FakeHost(containers=['c1'], fixture=['c1'])
        code, summary = self.night(host)
        self.assertEqual(host.removed, ['c1'])
        self.assertEqual(summary['status'], 'PASS'); self.assertEqual(summary['previous_night'], 'INTERRUPTED')
        self.assertEqual(len(host.started), 2)

    def test_foreign_container_is_skipped_busy(self):                   # nightly-foreign-load
        host = FakeHost(containers=['f1', 'c1'], fixture=['c1'])
        code, summary = self.night(host)
        self.assertEqual((code, summary['status']), (75, 'SKIPPED_BUSY'))
        self.assertEqual(summary['preflight']['foreign_running'], ['f1'])
        self.assertEqual(host.started, [])

    def test_load_average_is_skipped_busy(self):
        code, summary = self.night(FakeHost(load=7.5))
        self.assertEqual((code, summary['status']), (75, 'SKIPPED_BUSY'))
        self.assertEqual(summary['preflight']['load5'], 7.5)
        code, summary = self.night(FakeHost(load=7.5), load_max=8.0)
        self.assertEqual(code, 0)


class BoundTest(NightBase):
    def test_bound_marks_the_remaining_entries_inconclusive(self):
        plan = nightly.parse_plan(plan2() + [{'kind': 's17', 'scenario': 'core-smoke'}])
        host = FakeHost(durations={'core-boots-1': 600.0, 'core-drill-a04-regenesis': 600.0})
        code, summary = self.night(host, plan, bound_s=900.0)
        by = {e['scenario']: e['status'] for e in summary['entries']}
        self.assertEqual(by, {'core-boots-1': 'PASS', 'core-drill-a04-regenesis': 'INCONCLUSIVE', 'core-smoke': 'INCONCLUSIVE'})
        self.assertEqual(summary['status'], 'INCONCLUSIVE'); self.assertEqual(code, 2)
        self.assertIn('night bound', summary['entries'][2]['error'])
        self.assertEqual(host.started, ['core-boots-1', 'core-drill-a04-regenesis'])

    def test_bound_already_spent_starts_nothing(self):
        host = FakeHost()
        code, summary = self.night(host, bound_s=0.0)
        self.assertEqual(host.started, []); self.assertEqual(summary['status'], 'INCONCLUSIVE')

    def test_fail_outranks_inconclusive(self):
        host = FakeHost(results={'core-boots-1': 'FAIL'}, durations={'core-boots-1': 400.0, 'core-drill-a04-regenesis': 1000.0})
        code, summary = self.night(host, bound_s=500.0)
        self.assertEqual((code, summary['status']), (1, 'FAIL'))

    def test_bound_default_is_five_hours_and_a_setting(self):
        self.assertEqual(nightly.settings_from_env({}).bound_s, 18000.0)
        self.assertEqual(nightly.settings_from_env({'NIGHTLY_BOUND_S': '900'}).bound_s, 900.0)
        with self.assertRaises(Violation): nightly.settings_from_env({'NIGHTLY_BOUND_S': 'soon'})
        with self.assertRaises(Violation): nightly.settings_from_env({'NIGHTLY_AFTER_INTERRUPT': 'maybe'})
        s = nightly.settings_from_env({})
        self.assertEqual((s.after_interrupt, s.load_max), ('run', 6.0))
        self.assertTrue(s.lock.endswith('/scratchpad/heavy.lock'))


class SealTest(NightBase):
    def test_night_is_sealed_over_every_file(self):
        code, summary = self.night(FakeHost())
        night = self.ev / summary['night']
        files = sorted(str(p.relative_to(night)) for p in night.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
        lines = (night / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual([l.split('  ', 1)[1] for l in lines], files)
        self.assertIn('summary.json', files); self.assertTrue(any(f.endswith('.log') for f in files))
        log = next(night / f for f in files if f.endswith('-core-boots-1.log'))
        for line in lines:
            digest, name = line.split('  ', 1)
            self.assertEqual(digest, hashlib.sha256((night / name).read_bytes()).hexdigest())
        self.assertTrue(nightly.verify_seal(night))
        original = log.read_text(); log.write_text('edited')
        self.assertFalse(nightly.verify_seal(night))
        log.write_text(original)
        (night / 'late.txt').write_text('x')
        self.assertFalse(nightly.verify_seal(night))        # a file the seal does not list


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = Path(self.temp.name)
        self.repo = self.dir / 'repo'; (self.repo / 'runtime-e2e').mkdir(parents=True)
        (self.repo / 'runtime-e2e' / 'a.py').write_text('print(1)\n'); (self.repo / 'runtime-e2e' / 'b.txt').write_text('b\n')
        self.git('init', '-q'); self.git('add', '-A'); self.git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'one')
        self.sha = self.git('rev-parse', 'HEAD').strip(); self.root = self.dir / 'nightly'

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo)] + list(args), capture_output=True, text=True, check=True).stdout

    def test_harness_is_the_archive_of_the_commit_not_the_working_tree(self):
        (self.repo / 'runtime-e2e' / 'a.py').write_text('print(2)\n')          # a dirty checkout
        (self.repo / 'runtime-e2e' / 'new.py').write_text('x\n')
        harness = nightly.prepare_harness(self.repo, self.sha, self.root)
        self.assertEqual(harness, self.root / ('harness-' + self.sha))
        self.assertEqual((harness / 'runtime-e2e' / 'a.py').read_text(), 'print(1)\n')
        self.assertFalse((harness / 'runtime-e2e' / 'new.py').exists())
        again = nightly.prepare_harness(self.repo, self.sha, self.root)          # unpacked once
        self.assertEqual(again, harness)

    def test_dirty_harness_is_refused(self):                                  # nightly-dirty
        harness = nightly.prepare_harness(self.repo, self.sha, self.root)
        (harness / 'runtime-e2e' / 'b.txt').write_text('edited\n')
        with self.assertRaisesRegex(Violation, 'dirty.*b.txt'):
            nightly.prepare_harness(self.repo, self.sha, self.root)
        (harness / 'runtime-e2e' / 'b.txt').write_text('b\n'); (harness / 'runtime-e2e' / 'extra.py').write_text('x')
        with self.assertRaisesRegex(Violation, 'dirty.*extra.py'):
            nightly.prepare_harness(self.repo, self.sha, self.root)
        (harness / 'runtime-e2e' / 'extra.py').unlink(); (harness / 'runtime-e2e' / 'a.py').unlink()
        with self.assertRaisesRegex(Violation, 'dirty.*a.py'):
            nightly.prepare_harness(self.repo, self.sha, self.root)

    def test_unknown_commit_and_short_sha_are_refused(self):
        with self.assertRaisesRegex(Violation, '40-hex'):
            nightly.prepare_harness(self.repo, self.sha[:7], self.root)
        with self.assertRaisesRegex(Violation, 'not in'):
            nightly.prepare_harness(self.repo, '0' * 40, self.root)

    def test_dirty_harness_runs_nothing(self):
        harness = nightly.prepare_harness(self.repo, self.sha, self.root)
        (harness / 'runtime-e2e' / 'b.txt').write_text('edited\n')
        host = FakeHost()
        with tempfile.TemporaryDirectory() as ev:
            with self.assertRaises(Violation):
                nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', ev, '--tools-repo', str(self.repo),
                                   '--harness-commit', self.sha, '--harness-root', str(self.root)], host=host)
        self.assertEqual(host.started, [])


class UnitFilesTest(unittest.TestCase):
    D = Path(__file__).with_name('systemd')

    def test_service_reads_the_bound_from_environment_and_keeps_its_shape(self):
        text = (self.D / 'runtime-e2e-nightly.service').read_text()
        self.assertRegex(text, r'(?m)^Environment=NIGHTLY_BOUND_S=18000$')
        self.assertRegex(text, r'(?m)^Nice=5$'); self.assertRegex(text, r'(?m)^After=docker.service$')
        self.assertIn('--plan', text); self.assertIn('--harness-commit', text)
        self.assertNotRegex(text, r'(?m)^TimeoutStartSec=.*\$')       # systemd does not expand Environment= there

    def test_outer_guard_is_in_the_drop_in_and_larger_than_the_bound(self):
        text = (self.D / 'runtime-e2e-nightly.service.d' / 'timeout.conf').read_text()
        guard = int(re.search(r'(?m)^TimeoutStartSec=(\d+)$', text).group(1))
        self.assertEqual(guard, 21600)
        self.assertGreater(guard, nightly.settings_from_env({}).bound_s)
        self.assertNotRegex((self.D / 'runtime-e2e-nightly.service').read_text(), r'(?m)^TimeoutStartSec=')

    def test_timer_keeps_its_calendar_and_persistence(self):
        text = (self.D / 'runtime-e2e-nightly.timer').read_text()
        self.assertIn('OnCalendar=*-*-* 03:17:00', text); self.assertIn('Persistent=true', text)



class S17ScenarioTableTest(unittest.TestCase):
    """RC2 S17 W3 (coordinator): the xver/activation/rollback names and A05-keep are known; the default plan carries RED-1,
    RED-2 and A05-keep on their cut kinds."""

    def test_every_w3_scenario_is_known(self):
        import xver
        for name in xver.SCENARIO_NAMES + ['core-drill-a05-keep']:
            self.assertTrue(nightly.scenario_known(name), name)
        self.assertFalse(nightly.scenario_known('core-xver-me-old-on-new'))

    def test_default_plan_carries_red1_red2_and_a05_keep(self):
        plan = nightly.parse_plan(json.loads((Path(__file__).with_name('nightly-cut.json')).read_text()))
        pairs = {(e['kind'], e['scenario']) for e in plan}
        self.assertTrue({('s17-red1', 'core-red-1'), ('s17-red2', 'core-red-2'), ('s17-a05-keep', 'core-drill-a05-keep')} <= pairs)


class EntryEnvironmentTest(unittest.TestCase):
    """RC2 S17 W6 fix round item 2. RED 5d0339f: entry 26 (s17-ctl-edk-cnctimeout) ran without ENGINE_DRIVER_SKIP=1 and was
    INCONCLUSIVE 3/3 ('edk-cnctimeout needs ENGINE_DRIVER_SKIP=1 on its own manifest (5.2)'). S16 set it in its driver script
    for that kind only (S16/evidence/w6/run1.sh:6); the night sets it for that kind and scenario only, and strips it elsewhere."""

    def env_of(self, entry, outer):
        seen = {}

        def popen(argv, **kw):
            seen.update(kw['env']); return types.SimpleNamespace(wait=lambda timeout=None: 0)
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, outer, clear=False), \
                mock.patch.object(nightly.subprocess, 'Popen', popen), open(Path(d) / 'log', 'w') as log:
            nightly.Host().run_entry(entry, Path(d) / 'm.json', Path(d) / 'out', log, 10)
        return seen

    def test_the_cnc_timeout_control_alone_runs_with_engine_driver_skip(self):
        env = self.env_of({'kind': 's17-ctl-edk-cnctimeout', 'scenario': 'core-control-edk-cnctimeout'}, {})
        self.assertEqual(env.get('ENGINE_DRIVER_SKIP'), '1')
        for entry in ({'kind': 's17-ext', 'scenario': 'core-drill-c13-enginedriverkill'},
                      {'kind': 's17-ctl-edk-cnctimeout', 'scenario': 'core-drill-c13-enginedriverkill'},
                      {'kind': 's17-ext', 'scenario': 'core-control-edk-cnctimeout'}):
            with self.subTest(entry=entry):
                self.assertNotIn('ENGINE_DRIVER_SKIP', self.env_of(entry, {'ENGINE_DRIVER_SKIP': '1'}))
        self.assertEqual(nightly.entry_env({'kind': 's17-ctl-edk-cnctimeout', 'scenario': 'core-control-edk-cnctimeout'}, {}),
                         {'ENGINE_DRIVER_SKIP': '1'})

    def test_the_derived_cnc_manifest_accepts_the_setting_and_others_refuse_it(self):
        with tempfile.TemporaryDirectory() as d:
            m = {'manifest_kind': 's17-ctl-edk-cnctimeout', 'engine_driver': 'external'}
            path = Path(d) / 's17-ctl-edk-cnctimeout--night-26.json'
            self.assertEqual(core_contracts.check_engine_driver_skip(m, path, '1'), ('ae0', 'me0'))
            with self.assertRaisesRegex(Violation, 'ENGINE_DRIVER_SKIP is refused outside'):
                core_contracts.check_engine_driver_skip(dict(m, manifest_kind='s17-ext'), Path(d) / 's17-ext--night-17.json', '1')


class RepoPathsTest(unittest.TestCase):
    """RC2 S17 W6 fix round item 5. RED 5d0339f: a night from the pinned archive read r10_cut.REPO_PATHS['tools'] as the
    unpacked harness-<sha>/ (not a git repo), so the cut checker could not read the probe sources at harness_commit (W6
    aborted-env/, every entry INCONCLUSIVE in 8 s); W6 needed R10_TOOLS_REPO / R10_CT_REPO by hand. The night passes both."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = Path(self.temp.name)
        self.tools, self.ct = self.dir / 'tools', self.dir / 'ct'
        for repo in (self.tools, self.ct):
            repo.mkdir(); subprocess.run(['git', '-C', str(repo), 'init', '-q'], check=True)

    def tearDown(self):
        self.temp.cleanup()

    def launch(self, *extra, env=None):
        execs = []
        harness = self.dir / 'h' / 'runtime-e2e'; harness.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(nightly, 'prepare_harness', lambda repo, commit, root: harness.parent), \
                mock.patch.object(nightly.os, 'execv', lambda exe, argv: execs.append((argv, dict(os.environ)))), \
                mock.patch.dict(os.environ, env or {}, clear=False), \
                mock.patch.dict(nightly.r10_cut.REPO_PATHS, {}, clear=False):
            try:
                nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', str(self.dir / 'e'),
                                   '--harness-commit', 'a' * 40, '--tools-repo', str(self.tools), *extra])
            except (Violation, OSError, ValueError):
                pass
            paths = dict(nightly.r10_cut.REPO_PATHS)
        return execs, paths

    def test_the_launcher_passes_both_repos_to_the_archived_night(self):
        execs, _ = self.launch('--ct-repo', str(self.ct), env={'R10_TOOLS_REPO': '/nowhere', 'R10_CT_REPO': '/nowhere'})
        self.assertTrue(execs)
        argv, env = execs[0]
        self.assertEqual(argv[argv.index('--ct-repo') + 1], str(self.ct.resolve()))
        self.assertEqual(env['R10_TOOLS_REPO'], str(self.tools.resolve()))
        self.assertEqual(env['R10_CT_REPO'], str(self.ct.resolve()))

    def test_the_ct_repo_default_is_a_setting_and_a_non_git_dir_is_refused(self):
        execs, _ = self.launch(env={'NIGHTLY_CT_REPO': str(self.ct)})
        self.assertEqual(execs[0][1]['R10_CT_REPO'], str(self.ct.resolve()))
        plain = self.dir / 'plain'; plain.mkdir()
        with mock.patch.object(nightly, 'prepare_harness', lambda repo, commit, root: self.dir), \
                mock.patch.object(nightly.os, 'execv', lambda exe, argv: self.fail('a non-git ct repo must not launch')):
            with self.assertRaisesRegex(Violation, 'not a git repository'):
                nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', str(self.dir / 'e'),
                                   '--harness-commit', 'a' * 40, '--tools-repo', str(self.tools), '--ct-repo', str(plain)])

    def test_the_night_itself_reads_the_repos_it_was_given(self):
        harness = self.dir / 'h'
        with mock.patch.object(nightly, 'prepare_harness', lambda repo, commit, root: harness), \
                mock.patch.object(nightly, '__file__', str(harness / 'runtime-e2e' / 'nightly.py')), \
                mock.patch.object(nightly, 'pinned_plan', lambda plan, h: (_ for _ in ()).throw(Violation('stop here'))), \
                mock.patch.dict(nightly.r10_cut.REPO_PATHS, {}, clear=False), mock.patch.dict(os.environ, {}, clear=False):
            (harness / 'runtime-e2e').mkdir(parents=True)
            with self.assertRaisesRegex(Violation, 'stop here'):
                nightly.main_with(['--plan', str(self.dir / 'p.json'), '--evidence-root', str(self.dir / 'e'),
                                   '--harness-commit', 'a' * 40, '--tools-repo', str(self.tools), '--ct-repo', str(self.ct)])
            self.assertEqual(nightly.r10_cut.REPO_PATHS['tools'], self.tools.resolve())
            self.assertEqual(nightly.r10_cut.REPO_PATHS['cluster-tools'], self.ct.resolve())
            self.assertEqual(os.environ['R10_TOOLS_REPO'], str(self.tools.resolve()))

    def test_the_unit_template_names_both_repos(self):
        text = (Path(__file__).with_name('systemd') / 'runtime-e2e-nightly.service').read_text()
        self.assertRegex(text, r'(?m)^Environment=NIGHTLY_CT_REPO=\S+$')
        self.assertIn('--tools-repo ${RUNTIME_E2E_REPO}', text)
        self.assertIn('--ct-repo ${NIGHTLY_CT_REPO}', text)


if __name__ == '__main__':
    unittest.main()
