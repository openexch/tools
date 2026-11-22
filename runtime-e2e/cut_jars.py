#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Upload a release cut's own jars to its S3 cut prefix and verify them by reading them back.

usage: cut_jars.py upload <cut manifest> --bucket <bucket> [--region <region>] [--execute]
       cut_jars.py verify <cut manifest> --bucket <bucket> [--region <region>]

The box runs the cut's own jars, not CI builds: a CI jar is not byte-equal to the cut's (the cut's jars carry the full
commit in META-INF/MANIFEST.MF). The cut's jars go to ``s3://<bucket>/cuts/<cut id>/<jar>``, next to a copy of the cut
manifest (``cuts/<cut id>/cut-manifest.json``). Identity is the cut manifest's sha256 per jar: before anything is uploaded
every jar is re-hashed against it, and after the upload every jar is read back from S3 and re-hashed again. The box does the
same after its fetch.

upload   WITHOUT --execute (the default) a dry run: every jar is checked against the cut manifest and the upload plan is
         printed; nothing is written to S3 and nothing is read from it. The real upload is an operator step that needs the
         owner's GO, so it takes the explicit --execute. A prefix that already holds files is never overwritten: if every
         file there reads back equal to the cut manifest the upload is a verified no-op, otherwise it is refused.
verify   read-only: reads every jar and the manifest copy back from the cut prefix and compares each sha256 with the cut
         manifest's.

The jars are the cut's ``artifacts`` whose name ends in ``.jar`` (the core cluster and projector jars, match-cluster.jar)
and the jar of each ``tools`` entry (the CoreDump tool). The cluster-kit jar of ``substrate.kit_jar`` is a build input
inside the engine jars, not a file the box runs, and is not uploaded.

Refusals (exit 1): ``jar differs from the cut manifest: <jar>`` (a local jar before the upload, or a jar read back from
S3); ``cut manifest copy differs: <key>``; ``cut prefix already holds a different file: <key>``. Exit 64: usage. The
AWS calls are the ``aws`` CLI's, with the caller's credentials.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import release_cut

PREFIX_ROOT = 'cuts'
MANIFEST_COPY = 'cut-manifest.json'
CUT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
JAR_DIFFERS = 'jar differs from the cut manifest: {}'


class Refused(Exception):
    pass


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class AwsS3:
    """The three S3 operations the script needs, through the aws CLI. The test seam replaces this class."""

    def __init__(self, bucket, region=None):
        self.bucket = bucket
        self.region = region

    def _aws(self, *args, check=True):
        argv = ['aws', *args] + (['--region', self.region] if self.region else [])
        run = subprocess.run(argv, capture_output=True, text=True, check=False)
        if check and run.returncode != 0:
            raise Refused(f'{" ".join(argv)}: exit {run.returncode}: {run.stderr.strip()}')
        return run

    def url(self, key):
        return f's3://{self.bucket}/{key}'

    def list(self, prefix):
        """The object keys under prefix (``prefix`` ends with /)."""
        run = self._aws('s3api', 'list-objects-v2', '--bucket', self.bucket, '--prefix', prefix, '--output', 'json')
        data = json.loads(run.stdout or '{}')
        return sorted(o['Key'] for o in data.get('Contents') or [])

    def put(self, path, key):
        self._aws('s3', 'cp', str(path), self.url(key), '--checksum-algorithm', 'SHA256', '--no-progress', '--only-show-errors')

    def get(self, key, dest):
        self._aws('s3', 'cp', self.url(key), str(dest), '--no-progress', '--only-show-errors')

    def describe_put(self, path, key):
        return f'aws s3 cp {path} {self.url(key)} --checksum-algorithm SHA256' + (f' --region {self.region}' if self.region else '')


def cut_jars(cut):
    """(jar file name, local path, sha256) of every jar the cut names for the box."""
    jars = []
    for name, entry in sorted((cut.get('artifacts') or {}).items()):
        if name.endswith('.jar'):
            jars.append((name, entry.get('path'), entry.get('sha256')))
    for name, entry in sorted((cut.get('tools') or {}).items()):
        spec = release_cut.TOOLS.get(name)
        if spec is None:
            raise Refused(f'tools.{name}: not a tool this script knows (release_cut.TOOLS)')
        jars.append((spec['file'], entry.get('path'), entry.get('sha256')))
    names = [j[0] for j in jars]
    if len(set(names)) != len(names):
        raise Refused('the cut names one jar file twice: ' + ', '.join(sorted(n for n in names if names.count(n) > 1)))
    if not jars:
        raise Refused('the cut names no jar')
    return jars


def load_cut(cut_path):
    cut_path = Path(cut_path)
    try:
        cut = json.loads(cut_path.read_text())
    except (OSError, ValueError) as e:
        raise Refused(f'{cut_path}: not a readable cut manifest ({e})')
    if not isinstance(cut, dict) or cut.get('schema') not in release_cut.SCHEMAS:
        raise Refused(f'{cut_path}: not a cut manifest (schema {cut.get("schema") if isinstance(cut, dict) else None!r})')
    cut_id = cut.get('cut_id')
    if not (isinstance(cut_id, str) and CUT_ID.fullmatch(cut_id)):
        raise Refused(f'{cut_path}: cut_id {cut_id!r} is not a plain name (it becomes the S3 prefix)')
    return cut


def prefix_of(cut):
    return f'{PREFIX_ROOT}/{cut["cut_id"]}/'


def check_local(jars):
    """Every jar re-hashed against the cut manifest before anything leaves the dev box."""
    bad = []
    for name, path, want in jars:
        p = Path(str(path or ''))
        if not p.is_absolute() or not p.is_file() or sha256_file(p) != want:
            bad.append(name)
    if bad:
        for name in bad:
            print(JAR_DIFFERS.format(name))
        raise Refused(f'refused: {len(bad)} jar(s) differ from the cut manifest; nothing uploaded')


def read_back(s3, cut, cut_path, jars, keys=None):
    """Every jar and the manifest copy read back from S3 and compared. Returns the refusal texts (empty = verified)."""
    prefix = prefix_of(cut)
    want = {prefix + name: (name, sha) for name, _, sha in jars}
    want[prefix + MANIFEST_COPY] = (MANIFEST_COPY, sha256_file(cut_path))
    present = set(s3.list(prefix) if keys is None else keys)
    problems = []
    with tempfile.TemporaryDirectory(prefix='cut-jars-') as tmp:
        for key, (name, sha) in sorted(want.items()):
            if key not in present:
                problems.append((JAR_DIFFERS if name != MANIFEST_COPY else 'cut manifest copy differs: {}').format(
                    name if name != MANIFEST_COPY else key) + ' (absent from the cut prefix)')
                continue
            dest = Path(tmp) / name
            s3.get(key, dest)
            got = sha256_file(dest)
            if got != sha:
                text = JAR_DIFFERS.format(name) if name != MANIFEST_COPY else f'cut manifest copy differs: {key}'
                problems.append(f'{text} (read back {got}, the cut manifest says {sha})')
            else:
                print(f'verified {s3.url(key)} sha256 {got}')
        for key in sorted(present - set(want)):
            problems.append(f'cut prefix holds a file the cut does not name: {key}')
    return problems


def upload(cut_path, s3, execute=False):
    cut = load_cut(cut_path)
    jars = cut_jars(cut)
    check_local(jars)
    prefix = prefix_of(cut)
    plan = [(path, prefix + name, name, sha) for name, path, sha in jars]
    plan.append((str(Path(cut_path).resolve()), prefix + MANIFEST_COPY, MANIFEST_COPY, sha256_file(cut_path)))
    for path, key, name, sha in plan:
        print(f'{"PLAN" if not execute else "upload"} {name} sha256 {sha}: ' + s3.describe_put(path, key))
    if not execute:
        print(f'DRY RUN: every jar equals the cut manifest; nothing was written to {s3.url(prefix)}. The upload is an '
              f'owner-GO step: rerun with --execute.')
        return
    existing = s3.list(prefix)
    if existing:
        problems = read_back(s3, cut, cut_path, jars, existing)
        if problems:
            for p in problems:
                print(p)
            raise Refused(f'cut prefix already holds a different file: {s3.url(prefix)}; nothing uploaded (a cut prefix '
                          f'is never overwritten; deleting it is its own GO)')
        print(f'{s3.url(prefix)} already holds this cut, every file verified; nothing uploaded')
        return
    for path, key, _, _ in plan:
        s3.put(path, key)
    problems = read_back(s3, cut, cut_path, jars)
    if problems:
        for p in problems:
            print(p)
        raise Refused(f'REFUSED: the upload to {s3.url(prefix)} does not read back as the cut manifest')
    print(f'uploaded and verified {len(plan)} files under {s3.url(prefix)}')


def verify(cut_path, s3):
    cut = load_cut(cut_path)
    jars = cut_jars(cut)
    problems = read_back(s3, cut, cut_path, jars)
    if problems:
        for p in problems:
            print(p)
        raise Refused(f'REFUSED: {s3.url(prefix_of(cut))} does not read back as the cut manifest')
    print(f'VERIFIED {s3.url(prefix_of(cut))}: {len(jars)} jars and the manifest copy equal the cut manifest')


def main(argv=None, s3_factory=AwsS3):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('upload', 'verify'):
        p = sub.add_parser(name)
        p.add_argument('cut', type=Path)
        p.add_argument('--bucket', required=True)
        p.add_argument('--region')
        if name == 'upload':
            p.add_argument('--execute', action='store_true', help='really upload (the owner-GO step); without it a dry run')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_:
        return 64 if exit_.code else 0
    s3 = s3_factory(args.bucket, args.region)
    try:
        if args.cmd == 'upload':
            upload(args.cut, s3, execute=args.execute)
        else:
            verify(args.cut, s3)
    except Refused as e:
        print(str(e))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
