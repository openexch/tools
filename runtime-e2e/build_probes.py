# SPDX-License-Identifier: Apache-2.0
"""Explicit test-probe preparation. Never called by run.sh and never rebuilds product jars."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--me-jar', required=True, type=Path)
    parser.add_argument('--oms-jar', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    compiler = subprocess.check_output(['javac', '-version'], text=True).strip()
    result = {}
    for name, key, dependency in [('FixtureProbe', 'test_helper', args.me_jar),
                                   ('BenchmarkProbe', 'benchmark_helper', args.oms_jar)]:
        directory = output / name; directory.mkdir(); classes = directory / 'classes'; classes.mkdir()
        source = directory / (name + '.java')
        shutil.copyfile(Path(__file__).parent / 'java' / source.name, source)
        commands = [['javac', '-proc:none', '--release', '21', '-cp', str(dependency.absolute()),
                     '-d', str(classes), str(source)],
                    ['jar', '--create', '--date=2000-01-01T00:00:00Z', '--file', str(directory / (name + '.jar')),
                     '-C', str(classes), '.']]
        for command in commands: subprocess.run(command, check=True)
        artifact = directory / (name + '.jar')
        result[key] = {'path':str(artifact), 'sha256':sha(artifact), 'source_path':str(source),
                       'source_sha256':sha(source), 'compiler':compiler,
                       'compile_classpath_sha256':sha(dependency), 'commands':commands}
    (output / 'probe-manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
