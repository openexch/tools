# SPDX-License-Identifier: Apache-2.0
"""Artifact-only scenario runner. Unknown, incomplete and skipped evidence exits nonzero."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import sys
import time
import traceback

from contracts import Inconclusive, Violation, check_result, validate_manifest
from fixture import Fixture
from scenarios import critical_path_smoke


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--scenario', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    # Refuse to overwrite evidence of a prior run, including failed attempts.
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = None
    started = time.time_ns()
    result = {'status': 'NOT_RUN', 'scenario': args.scenario, 'started_ns': started,
              'assertions': 0, 'processed': 0, 'skipped': 0}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda number, frame: (_ for _ in ()).throw(Inconclusive('runner interrupted: ' + str(number))))
    try:
        manifest = json.loads(args.manifest.read_text())
        validate_manifest(manifest, args.manifest)
        result['manifest_sha256'] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        (args.output / 'manifest.json').write_bytes(args.manifest.read_bytes())
        result['harness_sources'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted(Path(__file__).parent.glob('*.py'))}
        if args.scenario == 'harness-negative-controls':
            from negative_controls import run
            result.update(run(args.output, manifest, args.manifest))
        elif args.scenario == 'critical-path-smoke':
            fixture = Fixture(args.manifest)
            result['state_root'] = str(fixture.root)
            fixture.start()
            result.update(critical_path_smoke(fixture))
        else:
            raise Inconclusive('scenario is not implemented and cannot pass: ' + args.scenario)
        check_result(result)
    except Violation as error:
        result.update(status='FAIL', error=str(error), traceback=traceback.format_exc())
    except Exception as error:
        result.update(status='INCONCLUSIVE', error=str(error), traceback=traceback.format_exc())
    finally:
        if fixture:
            try:
                fixture.close()
                result['teardown'] = 'COMPLETE_OWNED_RESOURCES_ONLY'
            except Exception as error:
                result.update(status='INCONCLUSIVE', teardown_error=str(error))
            commands = fixture.root / 'commands.jsonl'
            if commands.exists():
                result['child_exit_codes'] = [json.loads(line)['exit_code'] for line in commands.read_text().splitlines()]
                if result['status'] == 'PASS':
                    try: check_result(result)
                    except Exception as error: result.update(status='INCONCLUSIVE', error=str(error))
        result['elapsed_ns'] = time.time_ns() - started
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1 if result['status'] == 'FAIL' else 2


if __name__ == '__main__':
    sys.exit(main())
