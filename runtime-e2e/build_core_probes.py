# SPDX-License-Identifier: Apache-2.0
"""Explicit core-topology probe preparation. Never called by run.sh; never rebuilds product jars.

CoreProbe compiles against the frozen AE jar, JournalProbe against the frozen ME jar. Both run in the
probe container with that same frozen jar on the class path, so the probe jar carries only its own
classes. Copy the objects from probe-manifest.json into the core manifest (``core_probe``,
``journal_probe``).

``--ct-dir <cluster-tools>`` also compiles the two T1 drivers, T1MeDriver (against the ME
jar) and T1CoreDriver (against the AE jar), FROM ``<ct>/app/forwarder/it/`` and never copies them into tools; the
manifest keys ``t1_me_driver`` / ``t1_core_driver`` pin each source file's sha256, and ``ct_head`` records the
cluster-tools commit the sources came from. ``--ct-dir`` is optional so the probe-only call keeps working.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DRIVER_DIR = Path('app') / 'forwarder' / 'it'
DRIVERS = {'t1_me_driver': ('T1MeDriver', '--me-jar'), 't1_core_driver': ('T1CoreDriver', '--ae-jar')}


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def driver_sources(ct_dir):
    """{manifest key: {source, main_class, classpath_arg}} for the T1 drivers under a cluster-tools tree."""
    found = {}
    for key, (main_class, arg) in DRIVERS.items():
        source = Path(ct_dir) / DRIVER_DIR / (main_class + '.java')
        if not source.is_file():
            raise SystemExit(f'--ct-dir: {source} does not exist; {main_class}.java is compiled from cluster-tools, never copied')
        found[key] = {'source': source, 'main_class': main_class, 'classpath_arg': arg}
    return found


def compile_program(name, source, dependency, directory):
    classes = directory / 'classes'; classes.mkdir(parents=True)
    copy = directory / (name + '.java')
    shutil.copyfile(source, copy)
    artifact = directory / (name + '.jar')
    commands = [['javac', '-proc:none', '--release', '21', '-cp', str(dependency.absolute()), '-d', str(classes), str(copy)],
                ['jar', '--create', '--date=2000-01-01T00:00:00Z', '--file', str(artifact), '-C', str(classes), '.']]
    for command in commands:
        subprocess.run(command, check=True)
    return artifact, copy, commands


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ae-jar', required=True, type=Path)
    parser.add_argument('--me-jar', required=True, type=Path)
    parser.add_argument('--ct-dir', type=Path, help='cluster-tools tree holding app/forwarder/it/T1*Driver.java')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    drivers = driver_sources(args.ct_dir) if args.ct_dir else {}
    output = args.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    compiler = subprocess.check_output(['javac', '-version'], text=True).strip()
    result = {}
    jars = {'--ae-jar': args.ae_jar, '--me-jar': args.me_jar}
    plan = [('CoreProbe', 'core_probe', args.ae_jar, Path(__file__).parent / 'java' / 'CoreProbe.java'),
            ('JournalProbe', 'journal_probe', args.me_jar, Path(__file__).parent / 'java' / 'JournalProbe.java')]
    plan += [(d['main_class'], key, jars[d['classpath_arg']], d['source']) for key, d in drivers.items()]
    for name, key, dependency, source in plan:
        directory = output / name; directory.mkdir()
        artifact, copy, commands = compile_program(name, source, dependency, directory)
        result[key] = {'path': str(artifact), 'sha256': sha(artifact), 'source_path': str(copy),
                       'source_sha256': sha(copy), 'compiler': compiler, 'main_class': name,
                       'compile_classpath_sha256': sha(dependency), 'commands': commands}
        if key in drivers:
            result[key]['origin_path'] = str(source)
            result[key]['origin_sha256'] = sha(source)
    if drivers:
        head = subprocess.run(['git', '-C', str(args.ct_dir), 'rev-parse', 'HEAD'], capture_output=True, text=True)
        dirty = subprocess.run(['git', '-C', str(args.ct_dir), 'status', '--porcelain', '--', str(DRIVER_DIR)], capture_output=True, text=True)
        result['ct_head'] = head.stdout.strip() or None
        result['ct_driver_sources_dirty'] = bool(dirty.stdout.strip())
    (output / 'probe-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
