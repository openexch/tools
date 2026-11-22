# SPDX-License-Identifier: Apache-2.0
"""The arm64 release set around a cut: the Go tools' reproducible cross-build (arm64_sibling.py go-build, against a stand-in
go command), the sibling assembled from publish-job prefixes and checked by K11, the box self-check's expectations, the
cut-jar upload and read-back (cut_jars.py, against a local stand-in for the S3 cut prefix), and the box self-check script
(box_check.sh) against stub binaries. No AWS, no network, no arm64 machine."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import arm64_sibling
import cut_jars
import release_cut
from test_release_cut import SHAS, World

HERE = Path(__file__).resolve().parent
BOX_CHECK = HERE / 'box_check.sh'
ELF_ARM64 = b'\x7fELF\x02\x01\x01' + b'\x00' * 9 + b'\x02\x00' + (183).to_bytes(2, 'little')

# A stand-in go command: `go env GOVERSION`, and `go build ... -ldflags <flags> -o <out> .` writing an arm64 ELF header and
# the linked commit. With FAKE_GO_DIFFER set, each build also writes its own build cache path, so two builds differ.
FAKE_GO = r'''#!/bin/sh
if [ "$1" = env ]; then echo go1.99.0-fake; exit 0; fi
out=""; flags=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out=$2; shift ;; -ldflags) flags=$2; shift ;; esac
    shift
done
[ -f main.go ] || { echo "no main.go in $(pwd)" >&2; exit 1; }
sha=$(printf '%s' "$flags" | sed -n 's/.*main\.sourceSha=\([0-9a-f]*\).*/\1/p')
printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000\002\000\267\000 market-sim %s %s %s' \
    "$sha" "$CGO_ENABLED/$GOOS/$GOARCH" "${FAKE_GO_DIFFER:+$GOCACHE}" > "$out"
'''


def h(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@t', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1'}
    return subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True, env=env).stdout.strip()


def run_main(main, argv, **kw):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv, **kw)
    return code, out.getvalue()


class GoBuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='go-build-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.repo = self.tmp / 'tools'
        for sub in release_cut.GO_TOOLS.values():
            (self.repo / sub).mkdir(parents=True)
            (self.repo / sub / 'main.go').write_text('package main\n')
        git(self.repo, 'init', '-q')
        git(self.repo, 'add', '.')
        git(self.repo, 'commit', '-q', '-m', 'c')
        self.sha = git(self.repo, 'rev-parse', 'HEAD')
        # the work tree differs from the commit: the build must take the commit's bytes
        for sub in release_cut.GO_TOOLS.values():
            (self.repo / sub / 'main.go').unlink()
        self.go = self.tmp / 'go'
        self.go.write_text(FAKE_GO)
        self.go.chmod(0o755)
        self.out = self.tmp / 'out'

    def build(self, sha=None):
        return run_main(arm64_sibling.main, ['go-build', '--tools-repo', str(self.repo), '--sha', sha or self.sha,
                                             '--out', str(self.out), '--go', str(self.go)])

    def test_two_equal_builds_make_a_sibling_entry(self):
        code, out = self.build()
        self.assertEqual(code, 0, out)
        data = (self.out / 'market-sim').read_bytes()
        self.assertIn(b'0/linux/arm64', data)                 # pure Go, linux/arm64
        entry = json.loads((self.out / 'go-builds.json').read_text())['market-sim']
        self.assertEqual(entry, {'repo': 'tools', 'path': str((self.out / 'market-sim').resolve()), 'sha256': h(data),
                                 'source_sha': self.sha, 'reported_sha': self.sha, 'origin': 'go-cross-build',
                                 'builds': [h(data), h(data)], 'go_version': 'go1.99.0-fake'})
        self.assertEqual(sorted(json.loads((self.out / 'go-builds.json').read_text())), sorted(release_cut.GO_TOOLS))

    def test_two_builds_that_differ_are_refused(self):
        os.environ['FAKE_GO_DIFFER'] = '1'
        self.addCleanup(os.environ.pop, 'FAKE_GO_DIFFER')
        code, out = self.build()
        print(out, end='')                       # the refusal as printed (kept in the test log)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith('go build is not reproducible: market-sim ('), out)
        self.assertFalse((self.out / 'market-sim').exists())
        self.assertFalse((self.out / 'go-builds.json').exists())

    def test_a_short_or_unknown_commit_is_refused(self):
        code, out = self.build(self.sha[:7])
        self.assertEqual(code, 1)
        self.assertIn('--sha must be a full 40-hex commit', out)
        code, out = self.build('0' * 40)
        self.assertEqual(code, 1)
        self.assertIn('git cat-file', out)


class SiblingAssembleTest(unittest.TestCase):
    """A sibling from two publish-job prefixes and the Go builds; refused unless every entry derives from the cut."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sibling-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.w = World(self.tmp / 'world')
        self.cut = self.w.put('cut.json', json.dumps(self.w.m).encode())
        self.ci = {}
        for repo in ('gateway', 'cluster-tools'):
            names = [n for n, e in self.w.m['artifacts'].items()
                     if release_cut.PRODUCT.get(n, {}).get('lang') == 'cpp' and release_cut.PRODUCT[n]['repo'] == repo]
            self.ci[repo] = self.publish(repo, SHAS[repo], names + (['driver.properties'] if repo == 'cluster-tools' else []))
        builds = {}
        for tool in release_cut.GO_TOOLS:
            data = ELF_ARM64 + b' ' + tool.encode() + b' ' + SHAS['tools'].encode()
            p = self.w.put('go/' + tool, data)
            builds[tool] = {'repo': 'tools', 'path': str(p), 'sha256': h(data), 'source_sha': SHAS['tools'],
                            'reported_sha': SHAS['tools'], 'origin': 'go-cross-build', 'builds': [h(data), h(data)],
                            'go_version': 'go1.26.4'}
        self.go = self.w.put('go/go-builds.json', json.dumps(builds).encode())

    def publish(self, repo, sha, names, reported=True):
        d = self.tmp / 'ci' / f'{repo}-{sha[:7]}'
        d.mkdir(parents=True, exist_ok=True)
        items = []
        for name in names:
            body = b' aeron 1.53.1' if name in release_cut.AERON_DRIVER_FILES else b' source ' + sha.encode()
            data = (ELF_ARM64 if name != 'driver.properties' else b'') + b' ' + name.encode() + body
            (d / name).write_bytes(data)
            item = {'name': name, 'sha256': h(data), 'bytes': len(data)}
            if repo == 'gateway' and reported:
                item.update(goos='linux', goarch='arm64', reportedSha=sha)
            items.append(item)
        (d / 'manifest.json').write_text(json.dumps({'repo': repo, 'sha': sha, 'shortSha': sha[:7], 'ref': 'refs/heads/main',
                                                     'tag': '', 'builtAt': '2026-11-22T00:00:00Z', 'runId': '1',
                                                     'artifacts': items}))
        return d

    def assemble(self, ci_dirs):
        out = self.tmp / 'sibling.json'
        argv = ['assemble', '--cut', str(self.cut), '--go', str(self.go), '--out', str(out)]
        for d in ci_dirs:
            argv += ['--ci', str(d)]
        code, text = run_main(arm64_sibling.main, argv)
        return code, text, out

    def test_assembled_sibling_is_accepted(self):
        code, text, out = self.assemble(self.ci.values())
        self.assertEqual(code, 0, text)
        sibling = json.loads(out.read_text())
        self.assertNotIn('driver.properties', sibling['artifacts'])
        self.assertEqual(release_cut.main(['check', str(out), '--cut', str(self.cut)]), 0)
        # the expectations of the box self-check: the binaries it starts, from the accepted sibling
        exp = self.tmp / 'expect.txt'
        code, text = run_main(arm64_sibling.main, ['expect', str(out), '--cut', str(self.cut), '--out', str(exp)])
        self.assertEqual(code, 0, text)
        lines = [line.split() for line in exp.read_text().splitlines() if not line.startswith('#')]
        self.assertEqual([x[0] for x in lines], ['oe-gateway', 'oe-stream', 'oe-projector', 'oe-marketdata', 'market-sim',
                                                     'obs-sampler'])
        self.assertEqual(lines[0], ['oe-gateway', sibling['artifacts']['oe-gateway']['sha256'], SHAS['gateway']])

    def test_a_prefix_of_another_gateway_commit_is_refused(self):
        other = self.publish('gateway', '9' * 40, ['oe-gateway', 'oe-stream', 'oe-projector'])
        code, text, out = self.assemble([other, self.ci['cluster-tools']])
        print(text, end='')
        self.assertEqual(code, 1)
        for name in ('oe-gateway', 'oe-stream', 'oe-projector'):
            self.assertIn(f'K11 arm64 set does not derive from the cut: {name}\n', text)
        self.assertFalse(out.exists())

    def test_cluster_tools_without_a_reported_sha_reads_the_bytes(self):
        code, text, out = self.assemble(self.ci.values())
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(out.read_text())['artifacts']['ct-bridge']['reported_sha'], SHAS['cluster-tools'])

    def test_a_file_edited_after_the_ci_manifest_is_refused(self):
        (self.ci['gateway'] / 'oe-stream').write_bytes(ELF_ARM64 + b' edited')
        code, text, out = self.assemble(self.ci.values())
        self.assertEqual(code, 1)
        self.assertIn(f'gateway/{SHAS["gateway"]}/oe-stream: the fetched file differs from the CI manifest', text)

    def test_an_x86_file_under_the_arm64_name_is_refused(self):
        d = self.ci['gateway']
        m = json.loads((d / 'manifest.json').read_text())
        data = b'\x7fELF\x02\x01\x01' + b'\x00' * 9 + b'\x02\x00' + (62).to_bytes(2, 'little') + b' ' + SHAS['gateway'].encode()
        (d / 'oe-gateway').write_bytes(data)
        next(i for i in m['artifacts'] if i['name'] == 'oe-gateway')['sha256'] = h(data)
        (d / 'manifest.json').write_text(json.dumps(m))
        code, text, _ = self.assemble(self.ci.values())
        self.assertEqual(code, 1)
        self.assertIn('oe-gateway: not an arm64 ELF (e_machine 62)', text)

    def test_expect_refuses_a_sibling_the_cut_does_not_accept(self):
        code, text, out = self.assemble(self.ci.values())
        bad = json.loads(out.read_text())
        bad['artifacts']['oe-gateway']['reported_sha'] = '9' * 40
        out.write_text(json.dumps(bad))
        code, text = run_main(arm64_sibling.main, ['expect', str(out), '--cut', str(self.cut), '--out', str(self.tmp / 'e')])
        self.assertEqual(code, 1)
        self.assertIn('K11 arm64 set does not derive from the cut: oe-gateway', text)
        self.assertFalse((self.tmp / 'e').exists())


class FakeS3:
    """A local directory standing in for the bucket (the scratch prefix); records every call."""

    def __init__(self, root):
        self.root = Path(root)
        self.calls = []

    def factory(self, bucket, region):
        self.bucket = bucket
        return self

    def url(self, key):
        return f's3://{self.bucket}/{key}'

    def describe_put(self, path, key):
        return f'aws s3 cp {path} {self.url(key)} --checksum-algorithm SHA256'

    def list(self, prefix):
        self.calls.append(('list', prefix))
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*') if p.is_file()
                      and str(p.relative_to(self.root)).startswith(prefix))

    def put(self, path, key):
        self.calls.append(('put', key))
        dest = self.root / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)

    def get(self, key, dest):
        self.calls.append(('get', key))
        shutil.copyfile(self.root / key, dest)


class CutJarsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='cut-jars-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.w = World(self.tmp / 'world')
        self.cut = self.w.put('cut.json', json.dumps(self.w.m).encode())
        self.s3 = FakeS3(self.tmp / 'bucket')
        self.prefix = f'cuts/{self.w.m["cut_id"]}/'

    def run_cmd(self, *argv):
        return run_main(cut_jars.main, list(argv) + ['--bucket', 'scratch-bucket'], s3_factory=self.s3.factory)

    def test_dry_run_is_the_default_and_touches_nothing(self):
        code, out = self.run_cmd('upload', str(self.cut))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.s3.calls, [])
        self.assertIn('DRY RUN', out)
        for jar in ('core-cluster.jar', 'core-projector.jar', 'match-cluster.jar', 'cut-manifest.json'):
            self.assertIn(f's3://scratch-bucket/{self.prefix}{jar}', out)

    def test_execute_uploads_and_reads_back(self):
        code, out = self.run_cmd('upload', str(self.cut), '--execute')
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(k for op, k in self.s3.calls if op == 'put'), sorted(
            self.prefix + n for n in ('core-cluster.jar', 'core-projector.jar', 'match-cluster.jar', 'cut-manifest.json')))
        self.assertEqual(sum(1 for op, _ in self.s3.calls if op == 'get'), 4)      # every file read back
        code, out = self.run_cmd('verify', str(self.cut))
        self.assertEqual(code, 0, out)
        self.assertIn('VERIFIED', out)
        # a second upload of the same cut is a verified no-op
        self.s3.calls.clear()
        code, out = self.run_cmd('upload', str(self.cut), '--execute')
        self.assertEqual(code, 0, out)
        self.assertNotIn('put', [op for op, _ in self.s3.calls])

    def test_a_jar_that_differs_from_the_cut_manifest_is_refused_before_upload(self):
        Path(self.w.m['artifacts']['core-cluster.jar']['path']).write_bytes(b'another build')
        code, out = self.run_cmd('upload', str(self.cut), '--execute')
        print(out, end='')
        self.assertEqual(code, 1)
        self.assertIn('jar differs from the cut manifest: core-cluster.jar\n', out)
        self.assertEqual(self.s3.calls, [])

    def test_a_jar_read_back_differently_is_refused(self):
        self.assertEqual(self.run_cmd('upload', str(self.cut), '--execute')[0], 0)
        (self.s3.root / self.prefix / 'match-cluster.jar').write_bytes(b'torn upload')
        code, out = self.run_cmd('verify', str(self.cut))
        print(out, end='')
        self.assertEqual(code, 1)
        self.assertIn('jar differs from the cut manifest: match-cluster.jar (read back', out)
        # and an upload onto that prefix is refused, never an overwrite
        code, out = self.run_cmd('upload', str(self.cut), '--execute')
        self.assertEqual(code, 1)
        self.assertIn('cut prefix already holds a different file', out)

    def test_a_cut_id_that_is_not_a_plain_name_is_refused(self):
        m = copy.deepcopy(self.w.m)
        m['cut_id'] = '../x'
        bad = self.w.put('bad.json', json.dumps(m).encode())
        code, out = self.run_cmd('upload', str(bad))
        self.assertEqual(code, 1)
        self.assertIn('is not a plain name', out)

    def test_usage(self):
        self.assertEqual(run_main(cut_jars.main, ['upload', str(self.cut)])[0], 64)          # no --bucket


def stub(path, name, sha, refusal_key, code=78):
    path.write_text(f'''#!/bin/sh
if [ "$1" = --version ]; then echo "{name} dev source {sha} cluster-tools x"; exit 0; fi
echo "{name} config: {refusal_key} is required (no default)" >&2
exit {code}
''')
    path.chmod(0o755)


class BoxSelfCheckTest(unittest.TestCase):
    """box_check.sh selfcheck against stub binaries (no arm64 machine, no qemu: BOX_ELF_MACHINE=none skips the ELF step)."""

    KEYS = {'oe-gateway': 'GATEWAY_DRIVER_MODE', 'oe-stream': 'STREAM_DRIVER_MODE',
            'oe-projector': 'HISTORY_PROJECTOR_DRIVER_MODE', 'oe-marketdata': 'MD_DRIVER_MODE', 'market-sim': 'SIM_STREAM_URL',
            'obs-sampler': 'OBS_SAMPLER_CONFIG'}

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='b1-test-'))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.scratch = self.tmp / 'scratch'
        self.scratch.mkdir()
        self.source = {n: SHAS['tools'] if n in release_cut.GO_TOOLS else SHAS['gateway'] for n in self.KEYS}
        for name, key in self.KEYS.items():
            stub(self.scratch / name, name, self.source[name], key)
        self.write_expect()

    def write_expect(self):
        lines = ['# expectations']
        for name in self.KEYS:
            lines.append(f'{name} {h((self.scratch / name).read_bytes())} {self.source[name]}')
        (self.tmp / 'expect.txt').write_text('\n'.join(lines) + '\n')

    def run_box(self, *args, machine='none', env=None):
        e = {'PATH': os.environ['PATH'], **({'BOX_ELF_MACHINE': machine} if machine else {}), **(env or {})}
        run = subprocess.run(['bash', str(BOX_CHECK), *args], capture_output=True, text=True, env=e, check=False)
        return run.returncode, run.stdout + run.stderr

    def selfcheck(self, **kw):
        return self.run_box('selfcheck', str(self.scratch), str(self.tmp / 'expect.txt'), **kw)

    def test_the_cut_set_passes(self):
        code, out = self.selfcheck()
        self.assertEqual(code, 0, out)
        self.assertIn('SELFCHECK PASS (6 binaries)', out)
        self.assertIn(f'OK oe-gateway sha256 {h((self.scratch / "oe-gateway").read_bytes())} source {SHAS["gateway"]}; '
                      'empty environment refused with 78 naming GATEWAY_DRIVER_MODE', out)

    def test_a_binary_of_another_commit(self):
        stub(self.scratch / 'oe-gateway', 'oe-gateway', '9' * 40, 'GATEWAY_DRIVER_MODE')
        self.write_expect()        # its sha256 is the expected one and the cut's commit stays expected: only --version can tell
        code, out = self.selfcheck()
        print(out, end='')
        self.assertEqual(code, 1)
        self.assertIn('FAIL source sha differs from the cut: oe-gateway\n', out)
        self.assertIn('SELFCHECK FAIL', out)

    def test_a_file_that_is_not_the_sibling_one(self):
        (self.scratch / 'oe-stream').write_text((self.scratch / 'oe-stream').read_text() + '# edited\n')
        code, out = self.selfcheck()
        self.assertEqual(code, 1)
        self.assertIn('FAIL sha256 differs from the sibling manifest: oe-stream\n', out)

    def test_a_config_refusal_without_78_or_without_the_key(self):
        stub(self.scratch / 'oe-projector', 'oe-projector', SHAS['gateway'], 'HISTORY_PROJECTOR_DRIVER_MODE', code=1)
        stub(self.scratch / 'market-sim', 'market-sim', SHAS['tools'], 'SOMETHING_ELSE')
        self.write_expect()
        code, out = self.selfcheck()
        self.assertEqual(code, 1)
        self.assertIn('FAIL bad config not refused with 78: oe-projector\n', out)
        self.assertIn('FAIL refusal does not name SIM_STREAM_URL: market-sim\n', out)

    def test_the_default_requires_an_arm64_elf(self):
        code, out = self.selfcheck(machine=None)
        self.assertEqual(code, 1)
        self.assertIn('FAIL not an arm64 ELF: oe-gateway\n', out)

    def test_a_missing_binary(self):
        (self.scratch / 'oe-marketdata').unlink()
        code, out = self.selfcheck()
        self.assertEqual(code, 1)
        self.assertIn('FAIL missing from the scratch directory: oe-marketdata\n', out)

    def test_usage_and_the_survey_needs_the_admin_unit(self):
        self.assertEqual(self.run_box()[0], 64)
        code, out = self.run_box('survey')
        self.assertEqual(code, 64)
        self.assertIn('BOX_ADMIN_UNIT is required', out)


if __name__ == '__main__':
    unittest.main()
