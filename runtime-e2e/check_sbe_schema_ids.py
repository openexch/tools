#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One SBE schema id names one wire schema in every repo.

sbe-schema-ids.txt (repo root, the same file in every repo that publishes or decodes a schema) lists every
schema id in use, one line each: <id> <package> <owner>:<path>. This check holds the file, this repo's schema
files, its schema copies and its hand-written id constants to it:

  - every line is well formed, id 1..65535, no id and no package listed twice;
  - every schema XML under the repo is listed under this repo's owner name with its own id and package, and
    every line this repo owns names an existing file;
  - every copy given with --copy (a schema fetched from another repo), and every schema XML under a
    --copies-under directory (copies kept in this repo), declares the id its package is listed with;
  - every constant NAME_SCHEMA_ID = N and every sbeSchemaId() == N in the sources is a listed id, and a named
    constant is mapped (--constant NAME=package) to the package whose id it must equal, so a new constant has to
    say which schema it means;
  - every --lock-key FILE:KEY=package (a JSON lock value) equals the listed id of its package.

Usage: check-sbe-schema-ids.py --root DIR --owner NAME [--registry FILE] [--copy XML]... [--copies-under DIR]...
                               [--constant NAME=PKG]... [--lock-key FILE:KEY=PKG]...
       check-sbe-schema-ids.py --self-test     (the negative controls: every rule fails on a broken input)
Exit 0 when clean, 1 with one line per problem.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

REGISTRY = 'sbe-schema-ids.txt'
SKIP_DIRS = {'.git', 'target', 'node_modules', 'build', '_deps'}
SOURCE_SUFFIXES = ('.h', '.hpp', '.cpp', '.cc', '.py', '.go', '.java')
CONSTANT = re.compile(r'\b([A-Z][A-Z0-9_]*SCHEMA_ID)\s*=\s*(?:static_cast<[^>]*>\()?\s*(\d+)\b')
ASSERTED = re.compile(r'sbeSchemaId\(\)\s*==\s*(\d+)\b')


def read_registry(path, problems):
    by_id, by_package, lines = {}, {}, []
    with open(path, encoding='utf-8') as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            f = line.split()
            if len(f) != 3 or not f[0].isdigit() or ':' not in f[2] or f[2].startswith(':') or f[2].endswith(':'):
                problems.append(f"malformed line {n}: '{line}' (want <id> <package> <owner>:<path>)")
                continue
            sid = int(f[0])
            if not 1 <= sid <= 65535:
                problems.append(f'line {n}: id {sid} out of range 1..65535')
                continue
            owner, rel = f[2].split(':', 1)
            where = f'{f[1]} ({f[2]})'
            if sid in by_id:
                problems.append(f'duplicate schema id {sid}: {by_id[sid]} and {where}')
            else:
                by_id[sid] = where
            if f[1] in by_package:
                problems.append(f'package {f[1]} listed twice')
            else:
                by_package[f[1]] = sid
            lines.append((sid, f[1], owner, rel))
    return by_id, by_package, lines


def schema_attrs(path):
    """(id, package) of an SBE messageSchema XML, or None when the file is not one."""
    with open(path, encoding='utf-8', errors='replace') as fh:
        if 'messageSchema' not in fh.read():
            return None
    top = ET.parse(path).getroot()
    if top.tag.rsplit('}', 1)[-1] != 'messageSchema':
        return None
    return top.get('id'), top.get('package')


def walk(root, suffixes):
    """The files the repo carries: git's tracked and untracked (not ignored) files when root is the top of a git
    work tree (a nested checkout of another repo is not listed by git), else every file below root outside build
    trees."""
    try:
        out = subprocess.run(['git', '-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                             capture_output=True, check=True).stdout
        top = subprocess.run(['git', '-C', root, 'rev-parse', '--show-prefix'], capture_output=True, check=True)
        if top.stdout.strip() == b'':
            for rel in sorted(out.decode('utf-8', 'replace').split('\0')):
                if rel.endswith(suffixes) and os.path.isfile(os.path.join(root, rel)):
                    yield os.path.join(root, rel)
            return
    except (OSError, subprocess.CalledProcessError):
        pass
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith('build-'))
        for name in sorted(files):
            if name.endswith(suffixes):
                yield os.path.join(base, name)


def check(root, owner, registry=None, copies=(), constants=(), lock_keys=(), sources=None, copies_under=()):
    problems = []
    by_id, by_package, lines = read_registry(registry or os.path.join(root, REGISTRY), problems)
    owned = {rel: (sid, pkg) for sid, pkg, who, rel in lines if who == owner}
    found, copies = {}, list(copies)
    under = tuple(d.rstrip('/') + '/' for d in copies_under)
    for path in walk(root, ('.xml',)):
        attrs = schema_attrs(path)
        rel = os.path.relpath(path, root).replace(os.sep, '/')
        if attrs is not None and rel.startswith(under) and under:
            copies.append(path)
        elif attrs is not None:
            found[rel] = attrs
    for rel, (sid, pkg) in sorted(found.items()):
        if rel not in owned:
            problems.append(f'{rel} (id {sid}, package {pkg}) is not in {REGISTRY}')
        elif owned[rel] != (int(sid) if sid and sid.isdigit() else sid, pkg):
            problems.append(f'{rel} declares id {sid} and package {pkg}, {REGISTRY} says id {owned[rel][0]} '
                            f'package {owned[rel][1]}')
    for rel in sorted(set(owned) - set(found)):
        problems.append(f'{rel} is listed but missing')

    for copy in copies:
        attrs = schema_attrs(copy)
        if attrs is None:
            problems.append(f'copy {copy} is not an SBE messageSchema')
            continue
        sid, pkg = attrs
        if pkg not in by_package:
            problems.append(f'copy {copy}: package {pkg} is not in {REGISTRY}')
        elif str(by_package[pkg]) != sid:
            problems.append(f'copy {copy}: declares id {sid} for package {pkg}, {REGISTRY} says {by_package[pkg]}')

    mapping = {}
    for spec in constants:
        name, _, pkg = spec.partition('=')
        if pkg not in by_package:
            problems.append(f'--constant {spec}: package {pkg} is not in {REGISTRY}')
        mapping[name] = pkg
    for path in walk(sources or root, SOURCE_SUFFIXES):
        if os.path.basename(path) == os.path.basename(__file__):
            continue
        rel = os.path.relpath(path, root).replace(os.sep, '/')
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
        for m in CONSTANT.finditer(text):
            name, sid = m.group(1), int(m.group(2))
            if name not in mapping:
                problems.append(f'constant {name} = {sid} in {rel} has no --constant mapping to a schema package')
            elif mapping[name] in by_package and by_package[mapping[name]] != sid:
                problems.append(f'constant {name} = {sid} in {rel}, {REGISTRY} lists {mapping[name]} as id '
                                f'{by_package[mapping[name]]}')
        for m in ASSERTED.finditer(text):
            if int(m.group(1)) not in by_id:
                problems.append(f'sbeSchemaId() == {m.group(1)} in {rel}: id {m.group(1)} is not in {REGISTRY}')

    for spec in lock_keys:
        where, _, pkg = spec.partition('=')
        lock, _, key = where.rpartition(':')
        with open(os.path.join(root, lock), encoding='utf-8') as fh:
            value = json.load(fh).get(key)
        if pkg not in by_package:
            problems.append(f'--lock-key {spec}: package {pkg} is not in {REGISTRY}')
        elif value != by_package[pkg]:
            problems.append(f'{lock} {key} = {value}, {REGISTRY} lists {pkg} as id {by_package[pkg]}')
    return problems


# ---------------------------------------------------------------- negative controls

def _schema(sid, pkg):
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" '
            f'package="{pkg}" id="{sid}" version="1"><types/></sbe:messageSchema>\n')


def _fixture(registry, files):
    root = tempfile.mkdtemp(prefix='sbe-ids-')
    with open(os.path.join(root, REGISTRY), 'w', encoding='utf-8') as fh:
        fh.write(registry)
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(text)
    return root


def self_test():
    one = {'s/one.xml': _schema(7, 'a.one')}
    cases = [
        ('duplicate id', '7 a.one me:s/one.xml\n7 a.two me:s/two.xml\n',
         {**one, 's/two.xml': _schema(7, 'a.two')}, {}, 'duplicate schema id 7'),
        ('duplicate package', '7 a.one me:s/one.xml\n8 a.one me:s/two.xml\n',
         {**one, 's/two.xml': _schema(8, 'a.one')}, {}, 'package a.one listed twice'),
        ('unlisted schema', '7 a.one me:s/one.xml\n', {**one, 's/new.xml': _schema(9, 'a.new')}, {},
         's/new.xml (id 9, package a.new) is not in sbe-schema-ids.txt'),
        ('id differs', '7 a.one me:s/one.xml\n', {'s/one.xml': _schema(9, 'a.one')}, {},
         's/one.xml declares id 9 and package a.one, sbe-schema-ids.txt says id 7 package a.one'),
        ('listed but gone', '7 a.one me:s/one.xml\n8 a.gone me:s/gone.xml\n', one, {}, 's/gone.xml is listed but missing'),
        ('malformed', '7 a.one\n', {}, {}, 'malformed line 1'),
        ('malformed owner', '7 a.one nowhere\n', {}, {}, 'malformed line 1'),
        ('id 0', '0 a.one me:s/one.xml\n', {}, {}, 'id 0 out of range'),
        ('id 65536', '65536 a.one me:s/one.xml\n', {}, {}, 'id 65536 out of range'),
        ('copy id differs', '7 a.one other:s/one.xml\n', {'copies/one.xml': _schema(8, 'a.one')},
         {'copies': ['copies/one.xml']}, 'declares id 8 for package a.one'),
        ('copy unlisted', '7 a.one other:s/one.xml\n', {'copies/x.xml': _schema(8, 'a.x')},
         {'copies': ['copies/x.xml']}, 'package a.x is not in'),
        ('copy under a dir differs', '7 a.one other:s/one.xml\n', {'vendored/one.xml': _schema(8, 'a.one')},
         {'copies_under': ['vendored']}, 'declares id 8 for package a.one'),
        ('constant differs', '7 a.one other:s/one.xml\n', {'src/c.h': 'inline constexpr int ONE_SCHEMA_ID = 8;\n'},
         {'constants': ['ONE_SCHEMA_ID=a.one']}, 'constant ONE_SCHEMA_ID = 8 in src/c.h, sbe-schema-ids.txt lists a.one as id 7'),
        ('constant unmapped', '7 a.one other:s/one.xml\n', {'src/c.h': 'constexpr int NEW_SCHEMA_ID = 7;\n'}, {},
         'constant NEW_SCHEMA_ID = 7 in src/c.h has no --constant mapping'),
        ('static_assert unlisted', '7 a.one other:s/one.xml\n',
         {'src/c.cpp': 'static_assert(x::MessageHeader::sbeSchemaId() == 9);\n'}, {}, 'sbeSchemaId() == 9 in src/c.cpp'),
        ('lock differs', '7 a.one other:s/one.xml\n', {'dependencies.lock': '{"one_id": 8}'},
         {'lock_keys': ['dependencies.lock:one_id=a.one']}, 'dependencies.lock one_id = 8'),
    ]
    failed = 0
    for name, registry, files, kwargs, expected in cases:
        root = _fixture(registry, files)
        kw = dict(kwargs)
        kw['copies'] = [os.path.join(root, c) for c in kw.get('copies', [])]
        problems = check(root, 'me', **kw)
        if not any(expected in p for p in problems):
            failed += 1
            print(f'NEGATIVE CONTROL FAILED: {name}: expected a problem containing {expected!r}, got {problems}')
    clean = _fixture('7 a.one me:s/one.xml\n8 b.other someone-else:not/here.xml\n',
                     {**one, 'src/c.h': 'constexpr int ONE_SCHEMA_ID = 7;\n'})
    problems = check(clean, 'me', constants=['ONE_SCHEMA_ID=a.one'])
    if problems:
        failed += 1
        print(f'CLEAN CONTROL FAILED: {problems}')
    print(f'self-test: {len(cases)} negative controls and 1 clean control, {failed} failed')
    return 1 if failed else 0


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--root')
    p.add_argument('--owner')
    p.add_argument('--registry')
    p.add_argument('--copy', action='append', default=[])
    p.add_argument('--copies-under', action='append', default=[])
    p.add_argument('--constant', action='append', default=[])
    p.add_argument('--lock-key', action='append', default=[])
    p.add_argument('--self-test', action='store_true')
    a = p.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.root or not a.owner:
        p.error('--root and --owner are required')
    problems = check(a.root, a.owner, a.registry, [c for c in a.copy if c], a.constant, a.lock_key,
                     copies_under=a.copies_under)
    for problem in problems:
        print(problem)
    print(f'sbe schema ids: {len(problems)} problem(s)')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
