#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The arm64 sibling of a release cut: build its Go tools, assemble it, render the box self-check's expectations.

usage: arm64_sibling.py go-build --tools-repo <git work tree> --sha <tools commit> --out <dir>
       arm64_sibling.py assemble --cut <cut manifest> --ci <dir> [--ci <dir> ...] --go <dir>/go-builds.json --out <sibling.json>
       arm64_sibling.py expect <sibling.json> --cut <cut manifest> --out <expect.txt>

The cut's C++ binaries are x86 builds of the dev box; the demo box is aarch64. The sibling (schema ``arm64-sibling/1``)
lists the arm64 file of every C++ artifact of the cut and of every Go tool, each with its sha256 and the commit it was
built from; ``release_cut.py check <sibling> --cut <cut>`` (rule K11) accepts it only when every one is the commit the cut
names for its repo.

go-build   cross-builds each Go tool (release_cut.GO_TOOLS) for linux/arm64 from ``git archive <sha>`` of the tools repo,
           pure Go and reproducible: CGO_ENABLED=0, -trimpath, -buildvcs=false, an empty build id, the commit linked in as
           main.sourceSha (what ``<tool> --version`` prints). It builds TWICE, from two extractions with two empty build
           caches, and refuses with ``go build is not reproducible: <tool>`` when the two sha256 differ. It writes
           <out>/<tool> and <out>/go-builds.json (the sibling entries). Nothing is uploaded.
assemble   reads each ``--ci`` directory (a publish job's manifest.json and the files fetched read-only from its
           ``<repo>/<sha>/`` prefix, e.g. ``aws s3 cp --recursive s3://<bucket>/gateway/<sha>/ <dir>``), checks every file
           against its CI manifest, adds the Go tools, and writes the sibling only when K11 accepts it.
expect     the lines the box self-check reads (box_check.sh selfcheck): ``<name> <sha256> <source sha>``, one per binary
           the box starts at the self-check. Refused unless the sibling is accepted against the cut.

Exit codes: 0 done, 1 refused (the reason is printed), 64 usage.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

import release_cut

HEX40 = re.compile(r'[0-9a-f]{40}')
EM_AARCH64 = 183
# The binaries the self-check starts on the box: the gateway repo's four and the Go tools. Each is fetched to a
# scratch directory, prints its source sha and refuses an empty environment with 78 (box_check.sh).
SELFCHECK = ('oe-gateway', 'oe-stream', 'oe-projector', 'oe-marketdata') + tuple(release_cut.GO_TOOLS)


class Refused(Exception):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def elf_machine(data):
    """e_machine of a 64-bit little-endian ELF, or None."""
    if len(data) < 20 or data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        return None
    return int.from_bytes(data[18:20], 'little')


def _git(repo, *args, binary=False):
    out = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, check=False)
    if out.returncode != 0:
        raise Refused(f'git {" ".join(args)}: {out.stderr.decode(errors="replace").strip()}')
    return out.stdout if binary else out.stdout.decode().strip()


def extract(repo, sha, subdir, dest):
    """``git archive <sha> <subdir>`` into dest: the bytes of the commit, never the work tree."""
    data = _git(repo, 'archive', '--format=tar', sha, subdir, binary=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(dest, filter='data')
    return Path(dest) / subdir


def go_env(cache):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GO') and k not in ('CGO_ENABLED',)}
    env.update(CGO_ENABLED='0', GOOS='linux', GOARCH='arm64', GOCACHE=str(cache), GOFLAGS='-mod=readonly',
               GOTOOLCHAIN='local', GOWORK='off')
    for key in ('GOMODCACHE', 'GOPATH', 'GOPROXY', 'GONOSUMDB', 'GOPRIVATE', 'GOSUMDB'):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def go_build(go, src, out, sha, cache):
    ldflags = f'-buildid= -X main.sourceSha={sha}'
    argv = [go, 'build', '-trimpath', '-buildvcs=false', '-ldflags', ldflags, '-o', str(out), '.']
    run = subprocess.run(argv, cwd=src, env=go_env(cache), capture_output=True, text=True, check=False)
    if run.returncode != 0:
        raise Refused(f'go build in {src} failed (exit {run.returncode}): {run.stderr.strip()}')
    return Path(out).read_bytes()


def go_version(go):
    run = subprocess.run([go, 'env', 'GOVERSION'], env=go_env(tempfile.gettempdir()), capture_output=True, text=True,
                         check=False)
    version = run.stdout.strip()
    if run.returncode != 0 or not version.startswith('go'):
        raise Refused(f'`{go} env GOVERSION` gave no toolchain version: {run.stderr.strip()}')
    return version


def build_go_tools(repo, sha, out, go='go', tools=None):
    """Two builds per Go tool; returns the sibling entries. Raises Refused on any difference or bad input."""
    if not (isinstance(sha, str) and HEX40.fullmatch(sha)):
        raise Refused(f'--sha must be a full 40-hex commit, got {sha!r}')
    _git(repo, 'cat-file', '-e', f'{sha}^{{commit}}')
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    version = go_version(go)
    entries = {}
    for name, subdir in sorted((tools or release_cut.GO_TOOLS).items()):
        with tempfile.TemporaryDirectory(prefix=f'go-build-{name}-') as tmp:
            tmp = Path(tmp)
            builds = []
            for i in (1, 2):
                src = extract(repo, sha, subdir, tmp / f'src{i}')
                (tmp / f'cache{i}').mkdir()
                builds.append(go_build(go, src, tmp / f'{name}.{i}', sha, tmp / f'cache{i}'))
            sums = [sha256_bytes(b) for b in builds]
            if sums[0] != sums[1]:
                raise Refused(release_cut.SIBLING_GO_REPRO.format(name) + f' ({sums[0]} != {sums[1]})')
            data = builds[0]
        if elf_machine(data) != EM_AARCH64:
            raise Refused(f'{name}: the build is not an arm64 ELF (e_machine {elf_machine(data)})')
        if sha.encode() not in data:
            raise Refused(f'{name}: the build does not carry the tools commit {sha} (main.sourceSha not linked)')
        dest = out / name
        dest.write_bytes(data)
        dest.chmod(0o755)
        entries[name] = {'repo': 'tools', 'path': str(dest.resolve()), 'sha256': sums[0], 'source_sha': sha,
                         'reported_sha': sha, 'origin': 'go-cross-build', 'builds': sums, 'go_version': version}
        print(f'{name}: two builds, one sha256 {sums[0]} ({version}, tools {sha})')
    (out / 'go-builds.json').write_text(json.dumps(entries, indent=1, sort_keys=True) + '\n')
    return entries


def ci_entries(ci_dir, cut):
    """The sibling entries of one publish job's prefix, fetched to ci_dir with its manifest.json."""
    ci_dir = Path(ci_dir)
    try:
        manifest = json.loads((ci_dir / 'manifest.json').read_text())
    except (OSError, ValueError) as e:
        raise Refused(f'{ci_dir}: no readable manifest.json ({e})')
    repo, sha = manifest.get('repo'), manifest.get('sha')
    if not (isinstance(sha, str) and HEX40.fullmatch(sha)):
        raise Refused(f'{ci_dir}/manifest.json: sha is not a full commit ({sha!r})')
    if manifest.get('tag'):
        raise Refused(f'{ci_dir}/manifest.json: a release prefix ({manifest["tag"]}); the sibling names the {repo}/<sha>/ build')
    entries = {}
    for item in manifest.get('artifacts') or []:
        name = item.get('name')
        if release_cut.sibling_repo(name, cut) != repo or name in release_cut.GO_TOOLS:
            continue                       # a file the sibling does not list (driver properties, another repo's name)
        if item.get('goarch') not in (None, '', 'arm64'):
            raise Refused(f'{repo}/{sha}/{name}: published for {item.get("goarch")}, not arm64')
        path = ci_dir / name
        if not path.is_file():
            raise Refused(f'{repo}/{sha}/{name}: listed in the CI manifest, not fetched to {ci_dir}')
        data = path.read_bytes()
        got = sha256_bytes(data)
        if got != item.get('sha256'):
            raise Refused(f'{repo}/{sha}/{name}: the fetched file differs from the CI manifest: manifest says '
                          f'{item.get("sha256")}, file is {got}')
        if elf_machine(data) != EM_AARCH64:
            raise Refused(f'{repo}/{sha}/{name}: not an arm64 ELF (e_machine {elf_machine(data)})')
        entry = {'repo': repo, 'path': str(path.resolve()), 'sha256': got, 'source_sha': sha, 'origin': 'ci-publish',
                 'published': f'{repo}/{sha}/'}
        if name not in release_cut.AERON_DRIVER_FILES:
            # what the binary reported when the publish job ran it on arm64; a job that does not record it leaves the
            # commit its bytes carry, read the way K4 reads the x86 binaries (K11 re-checks both)
            reported = item.get('reportedSha')
            entry['reported_sha'] = reported if reported is not None else (sha if sha.encode() in data else None)
        entries[name] = entry
    return entries


def assemble(cut_path, ci_dirs, go_builds, out):
    cut_path = Path(cut_path)
    cut = json.loads(cut_path.read_text())
    artifacts = {}
    for d in ci_dirs:
        for name, entry in ci_entries(d, cut).items():
            if name in artifacts:
                raise Refused(f'{name}: listed by two CI prefixes')
            artifacts[name] = entry
    go = json.loads(Path(go_builds).read_text())
    for name, entry in go.items():
        if name not in release_cut.GO_TOOLS:
            raise Refused(f'{go_builds}: {name} is not a Go tool of the sibling')
        artifacts[name] = entry
    sibling = {'schema': release_cut.SIBLING_SCHEMA, 'cut_id': cut.get('cut_id'),
               'cut_sha256': release_cut.sha256_file(cut_path), 'arch': 'arm64', 'artifacts': artifacts}
    findings = release_cut.check_sibling(sibling, cut, cut_sha256=sibling['cut_sha256'])
    for rule, text in findings.items:
        print(f'{rule} {text}')
    if findings.items:
        raise Refused(f'REFUSED arm64 sibling of {cut.get("cut_id")}: ' + ', '.join(findings.by_rule()) + ' (nothing written)')
    Path(out).write_text(json.dumps(sibling, indent=1, sort_keys=True) + '\n')
    print(f'ACCEPTED arm64 sibling of {cut.get("cut_id")}: {out} ({len(artifacts)} artifacts)')
    return sibling


def expect(sibling_path, cut_path, out):
    sibling = json.loads(Path(sibling_path).read_text())
    cut = json.loads(Path(cut_path).read_text())
    findings = release_cut.check_sibling(sibling, cut, cut_sha256=release_cut.sha256_file(cut_path))
    if findings.items:
        for rule, text in findings.items:
            print(f'{rule} {text}')
        raise Refused(f'{sibling_path}: not accepted against {cut_path}; no expectations written')
    arts = sibling['artifacts']
    lines = [f'# arm64 self-check expectations: cut {cut.get("cut_id")}, sibling sha256 {release_cut.sha256_file(sibling_path)}']
    for name in SELFCHECK:
        if name in arts:
            lines.append(f'{name} {arts[name]["sha256"]} {arts[name]["source_sha"]}')
    Path(out).write_text('\n'.join(lines) + '\n')
    print(f'{out}: {len(lines) - 1} binaries')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    g = sub.add_parser('go-build')
    g.add_argument('--tools-repo', type=Path, required=True)
    g.add_argument('--sha', required=True)
    g.add_argument('--out', type=Path, required=True)
    g.add_argument('--go', default='go', help='the go command (default: go on PATH)')
    a = sub.add_parser('assemble')
    a.add_argument('--cut', type=Path, required=True)
    a.add_argument('--ci', type=Path, action='append', required=True)
    a.add_argument('--go', type=Path, required=True, dest='go_builds')
    a.add_argument('--out', type=Path, required=True)
    e = sub.add_parser('expect')
    e.add_argument('sibling', type=Path)
    e.add_argument('--cut', type=Path, required=True)
    e.add_argument('--out', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return 64 if exit_.code else 0
    try:
        if args.cmd == 'go-build':
            build_go_tools(args.tools_repo, args.sha, args.out, go=args.go)
        elif args.cmd == 'assemble':
            assemble(args.cut, args.ci, args.go_builds, args.out)
        else:
            expect(args.sibling, args.cut, args.out)
    except Refused as e:
        print(str(e))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
