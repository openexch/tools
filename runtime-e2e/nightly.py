# SPDX-License-Identifier: Apache-2.0
"""T2 nightly on the dev box (critic D20; RC2 S17 carry X5, contract 5.4): a local systemd timer runs this, never a GitHub runner.

usage: nightly.py --plan nightly-cut.json --evidence-root DIR [--harness-commit SHA] [--tools-repo DIR] [settings]
       nightly.py --template core-template.json --evidence-root DIR [--scenario S ...]    the pre-S17 path (core-smoke)

A plan lists entries ``{kind, scenario}``; every entry derives its OWN manifest from the cut (``mk_manifests.build_from_cut``, so one
night runs A04 on ``s17-ext`` and A05 on ``s17-a05``) and runs ``runner.py`` on it. Behaviour (each is a nightly control of 8.3):
  * pinned harness: this file re-executes itself from ``git archive <harness_commit>`` unpacked once into ``<root>/harness-<sha>/``
    and checked blob by blob against the commit; a modified or extra file refuses the night before any run (``nightly-dirty``);
  * one heavy-job lock, taken without waiting: a held lock ends the night ``SKIPPED_BUSY`` (exit 75), nothing starts
    (``nightly-busy``); the path used is recorded in ``summary.json``;
  * preflight: a stale labelled fixture container or an unfinished earlier night is recorded ``INTERRUPTED`` (the earlier night gets
    its own ``summary.json``), the containers are removed, and the night runs or stops per ``NIGHTLY_AFTER_INTERRUPT``
    (``nightly-stale``); a running container without the fixture label, or a 5-minute load above ``NIGHTLY_LOAD_MAX``, ends the night
    ``SKIPPED_BUSY`` (``nightly-foreign-load``);
  * the night bound ``NIGHTLY_BOUND_S`` (default 5 h) is enforced here, not by systemd: an entry running at the bound is stopped
    and it and every later entry are recorded ``INCONCLUSIVE``;
  * the night directory ends with ``SHA256SUMS`` over every file in it (written last, SHA-256 only).
Settings come from the environment (``NIGHTLY_*``), a command-line flag wins. Nothing is pushed or published.
"""
import argparse
from dataclasses import dataclass
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

from contracts import Violation
import core_contracts
from core_contracts import child_manifest, validate_core_manifest
import r10_cut

DEFAULT_SCENARIOS = ['core-boots-10', 'core-smoke']
FIXTURE_LABEL = 'org.openexchange.runtime-fixture'
NIGHT_NAME = re.compile(r'\d{8}T\d{6}Z')
EXIT = {'PASS': 0, 'FAIL': 1, 'INCONCLUSIVE': 2, 'SKIPPED_BUSY': 75, 'INTERRUPTED': 0}
DEFAULT_BOUND_S = 5 * 3600.0
DEFAULT_CUT = (Path('/home/emre/Apps/openexchange/.runtime-handoff/20260927-r00/workspace/notebook/reports/'
                    'runtime-handoff-execution/R10/rc2-cut-manifest.json'))


class NightTerminated(BaseException):
    """SIGTERM or SIGINT reached the night (systemd stop, ctrl-c): the entries not finished are recorded INCONCLUSIVE."""


# ------------------------------------------------------------------ settings

@dataclass
class Settings:
    lock: str = r10_cut.HEAVY_LOCK
    bound_s: float = DEFAULT_BOUND_S
    after_interrupt: str = 'run'
    load_max: float = 6.0
    harness_commit: str = None
    cut: str = str(DEFAULT_CUT)
    template: str = None              # the pre-S17 path: derive every entry from this one template manifest
    keep_state: bool = False          # keep the state root of a PASSing entry (a failing entry's is always kept)
    stop_grace_s: float = 180         # RC2 S17 review V17: the runner's SIGTERM-to-SIGKILL grace, a setting
    cut_sha256: str = None            # review V13 (c): the cut the night derives from, by sha256 and id
    cut_id: str = None

    def record(self):
        return {'lock': self.lock, 'bound_s': self.bound_s, 'after_interrupt': self.after_interrupt, 'load_max': self.load_max,
                'cut': self.cut, 'cut_sha256': self.cut_sha256, 'cut_id': self.cut_id, 'template': self.template,
                'keep_state': self.keep_state, 'stop_grace_s': self.stop_grace_s}


def _number(env, key, default):
    try:
        value = float(env.get(key, default))
    except ValueError:
        raise Violation(f'{key} must be a number, got {env.get(key)!r}')
    if value < 0:
        raise Violation(f'{key} must not be negative')
    return value


def settings_from_env(env=None):
    env = os.environ if env is None else env
    after = env.get('NIGHTLY_AFTER_INTERRUPT', 'run')
    if after not in ('run', 'skip'):
        raise Violation(f'NIGHTLY_AFTER_INTERRUPT is run or skip, got {after!r}')
    return Settings(lock=env.get('NIGHTLY_LOCK', r10_cut.HEAVY_LOCK), bound_s=_number(env, 'NIGHTLY_BOUND_S', DEFAULT_BOUND_S),
                    after_interrupt=after, load_max=_number(env, 'NIGHTLY_LOAD_MAX', 6.0),
                    harness_commit=env.get('NIGHTLY_HARNESS_COMMIT') or None, cut=env.get('NIGHTLY_CUT', str(DEFAULT_CUT)),
                    keep_state=env.get('NIGHTLY_KEEP_STATE', '') in ('1', 'true', 'yes'),
                    stop_grace_s=_number(env, 'NIGHTLY_STOP_GRACE_S', 180))


# ------------------------------------------------------------------ plan

def known_kinds():
    import mk_manifests
    return set(mk_manifests.KINDS17)


def scenario_known(scenario):
    import core_drills
    if scenario in ('core-boot', 'core-smoke'):
        return True
    m = re.fullmatch(r'core-boots-(\d+)', scenario)
    if m:
        return 1 <= int(m.group(1)) <= 20           # runner.py's bound
    if scenario == 'core-control-edk-cnctimeout':        # run_cnc_timeout, outside the CONTROLS table
        return True
    if scenario.startswith(('core-xver-', 'core-act-', 'core-rollback-')):    # RC2 S17 W3: xver.scenario
        import xver
        return scenario in xver.SCENARIO_NAMES
    if scenario.startswith('core-red-'):                  # core_drills.scenario: S15 red1/red2(-negctl), S16 red-a03/red-a04
        suffix = scenario[len('core-red-'):]
        return 'red' + suffix in core_drills.REDS or 'red-' + suffix in core_drills.REDS
    for prefix, table in (('core-drill-', core_drills.DRILLS), ('core-control-', core_drills.CONTROLS)):
        if scenario.startswith(prefix):
            return scenario[len(prefix):] in table
    return False


def parse_plan(obj, kinds=None):
    """The entries of a plan (a list, or ``{"entries": [...]}``); refuses an unknown kind or scenario, an entry with other keys, an empty plan."""
    entries = obj.get('entries') if isinstance(obj, dict) else obj
    if not isinstance(entries, list) or not entries:
        raise Violation('the plan is empty: a list of {kind, scenario} entries is required')
    kinds = known_kinds() if kinds is None else kinds
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {'kind', 'scenario'}:
            raise Violation(f'plan entry {index} must be exactly {{kind, scenario}}: {entry!r}')
        if entry['kind'] not in kinds:
            raise Violation(f'plan entry {index}: unknown kind {entry["kind"]!r}; kinds: ' + ', '.join(sorted(kinds)))
        if not isinstance(entry['scenario'], str) or not scenario_known(entry['scenario']):
            raise Violation(f'plan entry {index}: unknown scenario {entry["scenario"]!r}')
    return [dict(e) for e in entries]


def derive(template, template_path, scenario):
    """A fresh run identity from the template; the child file keeps the template's kind in its name (20.1 line 20)."""
    path, _ = child_manifest(template, Path(template_path).absolute().parent, scenario)
    return path


# ------------------------------------------------------------------ pinned harness

def _git(repo, *args, check=True):
    return subprocess.run(['git', '-C', str(repo)] + list(args), capture_output=True, check=check)


def _blob_sha1(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def _tree(repo, commit):
    listing = _git(repo, 'ls-tree', '-r', '-z', commit, '--', 'runtime-e2e').stdout.split(b'\0')
    tree = {}
    for record in listing:
        if record:
            meta, path = record.split(b'\t', 1)
            mode, kind, blob = meta.decode().split()
            tree[path.decode()] = (mode, blob)
    return tree


def _dirt(target, tree):
    """What differs between an unpacked harness and the commit's tree: [] for a clean one."""
    found = []
    for path, (mode, blob) in sorted(tree.items()):
        file = target / path
        if mode == '120000':
            same = file.is_symlink() and _blob_sha1(os.readlink(file).encode()) == blob
        else:
            same = file.is_file() and not file.is_symlink() and _blob_sha1(file.read_bytes()) == blob
        if not same:
            found.append(path + (' (missing)' if not file.exists() and not file.is_symlink() else ' (modified)'))
    for file in sorted((target / 'runtime-e2e').rglob('*')):
        rel = str(file.relative_to(target))
        if '__pycache__' in file.parts or file.is_dir() and not file.is_symlink():
            continue
        if rel not in tree:
            found.append(rel + ' (extra)')
    return found


def prepare_harness(repo, commit, root):
    """``<root>/harness-<commit>/runtime-e2e`` from ``git archive <commit>``, unpacked once; verified blob by blob on every call."""
    if not re.fullmatch(r'[0-9a-f]{40}', commit or ''):
        raise Violation(f'the harness commit must be a 40-hex sha, got {commit!r}')
    if _git(repo, 'cat-file', '-e', commit + '^{commit}', check=False).returncode:
        raise Violation(f'harness commit {commit} is not in {repo}')
    tree = _tree(repo, commit)
    if not tree:
        raise Violation(f'harness commit {commit} has no runtime-e2e tree')
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    target = root / ('harness-' + commit)
    if not target.exists():
        staging = Path(tempfile.mkdtemp(prefix='.unpack-', dir=root))
        try:
            archive = subprocess.Popen(['git', '-C', str(repo), 'archive', '--format=tar', commit, 'runtime-e2e'], stdout=subprocess.PIPE)
            subprocess.run(['tar', '-x', '-C', str(staging)], stdin=archive.stdout, check=True)
            archive.stdout.close()
            if archive.wait():
                raise Violation(f'git archive {commit} failed')
            staging.rename(target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    dirt = _dirt(target, tree)
    if dirt:
        raise Violation(f'harness {target} is dirty, refusing the night: ' + ', '.join(dirt[:8]) + (' ...' if len(dirt) > 8 else ''))
    return target


# ------------------------------------------------------------------ seal

def _night_files(night):
    return sorted(p for p in Path(night).rglob('*') if (p.is_file() or p.is_symlink()) and p.name != 'SHA256SUMS')


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def seal(night):
    """``SHA256SUMS`` over every file of the night directory, written last (sorted, ``sha256sum -c`` format)."""
    night = Path(night)
    lines = [f'{_sha256(p)}  {p.relative_to(night)}' for p in _night_files(night)]
    (night / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')


def verify_seal(night):
    """True when the seal lists exactly the files of the night with their hashes."""
    night = Path(night)
    try:
        listed = [line.split('  ', 1) for line in (night / 'SHA256SUMS').read_text().splitlines()]
    except OSError:
        return False
    actual = {str(p.relative_to(night)) for p in _night_files(night)}
    if {name for _, name in listed} != actual or len(listed) != len(actual):
        return False
    return all((night / name).is_file() and _sha256(night / name) == digest for digest, name in listed)


# ------------------------------------------------------------------ the host (docker, runner, clock; replaced in unit tests)

class Host:
    def _docker(self, *args):
        done = subprocess.run(['docker'] + list(args), capture_output=True, text=True)
        if done.returncode:
            raise Violation('docker ' + ' '.join(args) + ' failed: ' + done.stderr.strip()[-200:])
        return done.stdout.split()

    def fixture_containers(self):           # running or stopped, with the fixture label
        return self._docker('ps', '-aq', '--filter', 'label=' + FIXTURE_LABEL)

    def running_containers(self):
        return self._docker('ps', '-q')

    def remove_container(self, cid):
        subprocess.run(['docker', 'rm', '-f', cid], capture_output=True)

    def load5(self):
        return os.getloadavg()[1]

    def monotonic(self):
        import time
        return time.monotonic()

    def make_manifest(self, entry, index, work, settings):
        if settings.template:
            template_path = Path(settings.template)
            return derive(json.loads(template_path.read_text()), template_path, entry['scenario'])
        import mk_manifests
        cfg = mk_manifests.Config(runs=work, harness_commit=settings.harness_commit, harness_dirty=False)
        path, _ = mk_manifests.build_from_cut(entry['kind'], f'night-{index:02d}', settings.cut, cfg)
        return path

    def run_entry(self, entry, manifest, output, log, timeout):
        """Runs runner.py from this harness; returns ('DONE', exit code) or ('TIMEOUT', code) after stopping it at ``timeout``."""
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.Popen([sys.executable, '-s', str(Path(__file__).with_name('runner.py')), '--manifest', str(manifest),
                                    '--scenario', entry['scenario'], '--output', str(output)],
                                   stdout=log, stderr=subprocess.STDOUT, env=env)
        try:
            return 'DONE', process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._stop(process)
            return 'TIMEOUT', process.returncode
        except BaseException:
            self._stop(process)
            raise

    stop_grace_s = 180

    def _stop(self, process):
        process.terminate()                  # the runner turns SIGTERM into INCONCLUSIVE and tears its fixture down
        try:
            process.wait(timeout=self.stop_grace_s)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()

    def cleanup_entry(self, manifest, status, settings):
        if status != 'PASS' or settings.keep_state:
            return
        try:
            root = Path(json.loads(Path(manifest).read_text()).get('state_root') or '')
        except (OSError, ValueError):
            return
        if root.name and root.is_dir() and root.parent.name == 'fixtures':
            shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------------------------ the night

def _write_summary(night, summary):
    (night / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')


def _interrupt_old(old, by):
    """An unfinished earlier night gets its own record, so the next night does not find it again."""
    files = sorted(str(p.relative_to(old)) for p in old.rglob('*') if p.is_file())
    _write_summary(old, {'night': old.name, 'status': 'INTERRUPTED', 'recorded_by': by, 'files_found': files})
    seal(old)


def _overall(entries):
    states = {e['status'] for e in entries}
    if 'FAIL' in states:
        return 'FAIL'
    return 'PASS' if states == {'PASS'} else 'INCONCLUSIVE'


def run_night(plan, evidence_root, work_root, settings, host):
    """One night: lock, preflight, entries under the bound, summary, seal. Returns (exit code, summary)."""
    evidence_root = Path(evidence_root); evidence_root.mkdir(parents=True, exist_ok=True)
    moment = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    while (evidence_root / moment.strftime('%Y%m%dT%H%M%SZ')).exists() or (evidence_root / moment.strftime('.skip-%Y%m%dT%H%M%SZ')).exists():
        moment += datetime.timedelta(seconds=1)              # two nights in one second (only a test does that)
    stamp = moment.strftime('%Y%m%dT%H%M%SZ')
    summary = {'night': stamp, 'status': None, 'lock': settings.lock, 'settings': settings.record(),
               'harness': {'commit': settings.harness_commit, 'dirty': False}, 'plan': plan, 'entries': [], 'preflight': {}}
    started = host.monotonic()
    Path(settings.lock).parent.mkdir(parents=True, exist_ok=True)
    lock = open(settings.lock, 'a')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # the record is written under a hidden name and renamed: a running night, which owns the lock, never sees a half dir
            summary['preflight']['lock'] = 'held by another heavy job'
            staging = evidence_root / ('.skip-' + stamp); staging.mkdir(exist_ok=False)
            return _finish(staging, summary, 'SKIPPED_BUSY', started, host, rename=evidence_root / stamp)
        night = evidence_root / stamp
        unfinished = [p for p in sorted(evidence_root.iterdir()) if p.is_dir() and NIGHT_NAME.fullmatch(p.name)
                      and not (p / 'summary.json').exists()]
        night.mkdir(exist_ok=False)
        return _run_locked(plan, night, unfinished, work_root, settings, host, summary, started)
    finally:
        lock.close()                        # releases the flock: per night, never held past the exit


def _run_locked(plan, night, unfinished, work_root, settings, host, summary, started):
    try:
        stale = host.fixture_containers()
        if stale or unfinished:
            summary['interrupted'] = {'stale_fixture_containers': list(stale), 'unfinished_night_dirs': [p.name for p in unfinished]}
            for cid in stale:
                host.remove_container(cid)
            summary['interrupted']['containers_removed'] = list(stale)
            for old in unfinished:
                _interrupt_old(old, night.name)
            if settings.after_interrupt == 'skip':
                return _finish(night, summary, 'INTERRUPTED', started, host)
            summary['previous_night'] = 'INTERRUPTED'
        foreign = sorted(set(host.running_containers()) - set(stale))
        load5 = host.load5()
    except Violation as error:
        summary['preflight']['error'] = str(error)
        return _finish(night, summary, 'INCONCLUSIVE', started, host)
    summary['preflight'].update(foreign_running=foreign, load5=round(load5, 2), load_max=settings.load_max)
    if foreign or load5 > settings.load_max:
        return _finish(night, summary, 'SKIPPED_BUSY', started, host)
    work = Path(work_root) / night.name
    pending = list(enumerate(plan))
    try:
        while pending:
            index, entry = pending[0]
            remaining = settings.bound_s - (host.monotonic() - started)
            record = {'index': index, 'kind': entry['kind'], 'scenario': entry['scenario']}
            if remaining <= 0:
                break
            summary['entries'].append(record); pending.pop(0)
            tag = f'{index:02d}-{entry["kind"]}-{entry["scenario"]}'
            begun = host.monotonic()
            try:
                manifest = host.make_manifest(entry, index, work, settings)
            except Exception as error:               # a manifest the cut checker refuses is a result, not a crash
                record.update(status='INCONCLUSIVE', error=f'manifest not derived: {error}')
                continue
            record['manifest'] = Path(manifest).name
            output = night / tag
            with (night / f'{index:02d}-{entry["scenario"]}.log').open('x') as log:
                state, code = host.run_entry(entry, manifest, output, log, remaining)
            result = {}
            if (output / 'result.json').exists():
                try:
                    result = json.loads((output / 'result.json').read_text())
                except ValueError:
                    result = {}
            status = result.get('status', 'NOT_RUN')
            error = result.get('error')
            if state == 'TIMEOUT':
                status, error = 'INCONCLUSIVE', f'night bound {settings.bound_s:g} s reached while this entry ran'
            elif status not in ('PASS', 'FAIL', 'INCONCLUSIVE'):
                status = 'INCONCLUSIVE'
            record.update(status=status, exit_code=code, wall_s=round(host.monotonic() - begun, 1), error=error, evidence=tag)
            host.cleanup_entry(manifest, status, settings)
    except NightTerminated:
        if summary['entries'] and 'status' not in summary['entries'][-1]:
            summary['entries'][-1].update(status='INCONCLUSIVE', error='night terminated by a signal')
        for index, entry in pending:
            summary['entries'].append({'index': index, **entry, 'status': 'INCONCLUSIVE', 'error': 'night terminated by a signal'})
        return _finish(night, summary, _records(night, summary, _overall(summary['entries'])), started, host)
    for index, entry in pending:
        summary['entries'].append({'index': index, **entry, 'status': 'INCONCLUSIVE',
                                   'error': f'not started: night bound {settings.bound_s:g} s reached'})
    return _finish(night, summary, _records(night, summary, _overall(summary['entries'])), started, host)


def _records(night, summary, status):
    """RC2 step 7 (review V10): the night's activation records, checked as a set (no repeated genesisId, equal invariants,
    each OK); a refused set makes the night FAIL."""
    paths = sorted(night.rglob('rc2-activation-record.json'))
    records = []
    for p in paths:
        try:
            records.append(json.loads(p.read_text()))
        except ValueError:
            records.append({'status': 'UNREADABLE'})
    refusals = r10_cut.check_record_set(records) + [f'{p.relative_to(night)}: status {r.get("status")}'
                                                    for p, r in zip(paths, records) if r.get('status') != 'OK']
    summary['activation_records'] = {'files': [str(p.relative_to(night)) for p in paths], 'refusals': refusals}
    return 'FAIL' if refusals and status == 'PASS' else status


def cut_identity(cut, commit):
    """Review V2/V13 (c): the cut by sha256 and cut_id; its harness_commit must be the night's pinned commit."""
    data = Path(cut).read_bytes()
    m = json.loads(data)
    if m.get('harness_commit') != commit:
        raise Violation(f'the cut names harness_commit {m.get("harness_commit")}, the night is pinned at {commit}: a night runs the '
                        'harness its cut was made with')
    return {'cut_id': m.get('cut_id'), 'sha256': hashlib.sha256(data).hexdigest(), 'harness_commit': m.get('harness_commit')}


def pinned_plan(plan, harness_dir):
    """Review V13 (b): the plan the night runs is the one at the pinned commit (``<harness>/runtime-e2e/<name>``), byte-equal."""
    plan, pinned = Path(plan), Path(harness_dir) / Path(plan).name
    if not pinned.is_file() or pinned.read_bytes() != plan.read_bytes():
        raise Violation(f'{plan} is not the plan at the pinned commit ({pinned}): edit the plan by commit, not in the working tree')
    return pinned


def _finish(night, summary, status, started, host, rename=None):
    summary['status'] = status
    summary['wall_s'] = round(host.monotonic() - started, 1)
    _write_summary(night, summary)
    seal(night)
    if rename is not None:
        night.rename(rename)
    return EXIT[status], summary


# ------------------------------------------------------------------ command line

def _terminate(number, frame):
    raise NightTerminated(number)


def main_with(argv, host=None):
    env = settings_from_env()
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan', type=Path)
    group.add_argument('--template', type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--scenario', action='append', help='with --template: the scenarios (default core-boots-10, core-smoke)')
    parser.add_argument('--tools-repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--harness-commit', default=env.harness_commit)
    parser.add_argument('--harness-root', type=Path, help='where harness-<sha>/ is unpacked (default: next to the evidence root)')
    parser.add_argument('--work-root', type=Path, help='manifests and fixture state of the night (default: next to the evidence root)')
    parser.add_argument('--cut', default=env.cut)
    parser.add_argument('--lock', default=env.lock)
    parser.add_argument('--bound-s', type=float, default=env.bound_s)
    parser.add_argument('--load-max', type=float, default=env.load_max)
    parser.add_argument('--after-interrupt', choices=('run', 'skip'), default=env.after_interrupt)
    parser.add_argument('--keep-state', action='store_true', default=env.keep_state)
    args = parser.parse_args(argv)
    if args.plan is not None and not args.harness_commit:
        # review V13 (a): an unset NIGHTLY_HARNESS_COMMIT expands to "" in ExecStart; a night never falls back to HEAD
        raise Violation('an empty harness commit: --plan nights run only on a pinned NIGHTLY_HARNESS_COMMIT')
    commit = args.harness_commit or _git(args.tools_repo, 'rev-parse', 'HEAD').stdout.decode().strip()
    harness_root = args.harness_root or args.evidence_root.resolve().parent / 'harness'
    harness = prepare_harness(args.tools_repo, commit, harness_root)        # refuses a dirty harness before anything else
    if host is None and Path(__file__).resolve().parent != (harness / 'runtime-e2e').resolve():
        # a launcher: the night itself runs from the archive of the pinned commit, never from this checkout
        flags = [a for a in argv]
        if '--harness-commit' not in flags:
            flags += ['--harness-commit', commit]
        if '--tools-repo' in flags:                 # review V13 (d): always the real repo, absolute, never harness-<sha>
            flags[flags.index('--tools-repo') + 1] = str(args.tools_repo.resolve())
        else:
            flags += ['--tools-repo', str(args.tools_repo.resolve())]
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        os.execv(sys.executable, [sys.executable, '-s', str(harness / 'runtime-e2e' / 'nightly.py')] + flags)
    settings = Settings(lock=args.lock, bound_s=args.bound_s, after_interrupt=args.after_interrupt, load_max=args.load_max,
                        harness_commit=commit, cut=args.cut, keep_state=args.keep_state,
                        template=str(args.template.absolute()) if args.template else None)
    if args.template:
        template = json.loads(args.template.read_text())
        validate_core_manifest(template, args.template)
        plan = [{'kind': template.get('manifest_kind') or 'template', 'scenario': s} for s in args.scenario or DEFAULT_SCENARIOS]
        for entry in plan:
            if not scenario_known(entry['scenario']):
                raise Violation(f'unknown scenario {entry["scenario"]!r}')
    else:
        plan_path = pinned_plan(args.plan, harness / 'runtime-e2e')
        plan = parse_plan(json.loads(plan_path.read_text()))
        ident = cut_identity(args.cut, commit)
        settings.cut_sha256, settings.cut_id = ident['sha256'], ident['cut_id']
    work_root = args.work_root or args.evidence_root.resolve().parent / 'work'
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _terminate)
    if host is None:
        host = Host()
        host.stop_grace_s = settings.stop_grace_s
    code, summary = run_night(plan, args.evidence_root, work_root, settings, host)
    print(json.dumps({k: summary[k] for k in ('night', 'status', 'lock', 'wall_s')} | {
        'entries': [{k: e.get(k) for k in ('scenario', 'kind', 'status', 'wall_s')} for e in summary['entries']]}))
    return code


def main(argv=None):
    try:
        return main_with(sys.argv[1:] if argv is None else argv)
    except Violation as error:
        print('nightly refused: ' + str(error), file=sys.stderr)
        return 3


if __name__ == '__main__':
    sys.exit(main())
