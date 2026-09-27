# SPDX-License-Identifier: Apache-2.0
"""Artifact-only scenario runner. Unknown, incomplete and skipped evidence exits nonzero."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import shutil
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
        sources = args.output / 'harness-source'; sources.mkdir()
        for source in Path(__file__).parent.iterdir():
            if source.is_file() and source.suffix in {'.py', '.sh', '.md'}:
                shutil.copyfile(source, sources / source.name)
        if (Path(__file__).parent / 'java').is_dir():
            shutil.copytree(Path(__file__).parent / 'java', sources / 'java')
        if args.scenario == 'harness-negative-controls':
            from negative_controls import run
            result.update(run(args.output, manifest, args.manifest))
        elif args.scenario == 'baseline-fault-reproduction':
            from aggregate import baseline_fault_reproduction
            result.update(baseline_fault_reproduction(manifest, args.manifest, args.output))
        elif args.scenario == 'readiness-lag-election-idle':
            from aggregate import readiness_lag_election_idle
            result.update(readiness_lag_election_idle(manifest, args.manifest, args.output))
        elif args.scenario in {'critical-path-smoke', 'false-ready', 'false-ready-ae', 'pruner-exception', 'offline-purge-rejoin',
                              'benchmark-preflight', 'benchmark-normal', 'benchmark-n-minus-one', 'readiness-me', 'readiness-ae',
                              'log-channel-me', 'log-channel-ae'}:
            fixture = Fixture(args.manifest)
            result['state_root'] = str(fixture.root)
            fixture.start()
            if args.scenario == 'critical-path-smoke':
                result.update(critical_path_smoke(fixture))
            elif args.scenario.startswith('log-channel-'):
                from log_channel_fault import log_channel_lag
                result.update(log_channel_lag(fixture, args.scenario[-2:]))
            elif args.scenario.startswith('readiness-'):
                from readiness import readiness_scenario
                result.update(readiness_scenario(fixture, args.scenario[-2:]))
            elif args.scenario.startswith('benchmark-'):
                from benchmark import benchmark
                result.update(benchmark(fixture, 'n_minus_one' if args.scenario == 'benchmark-n-minus-one' else 'normal',
                                        preflight=args.scenario == 'benchmark-preflight'))
            else:
                from faults import false_ready, pruner_exception, offline_purge
                if args.scenario == 'pruner-exception': critical_path_smoke(fixture)
                result.update({'false-ready': false_ready, 'false-ready-ae': lambda f: false_ready(f, 'ae'),
                               'pruner-exception': pruner_exception,
                               'offline-purge-rejoin': offline_purge}[args.scenario](fixture))
        else:
            raise Inconclusive('scenario is not implemented and cannot pass: ' + args.scenario)
        if result['status'] == 'PASS': check_result(result)
        elif result['status'] not in {'FAIL', 'INCONCLUSIVE'}:
            raise Inconclusive('unsupported scenario decision: ' + str(result['status']))
    except Violation as error:
        result.update(status='FAIL', error=str(error), traceback=traceback.format_exc())
    except Exception as error:
        result.update(status='INCONCLUSIVE', error=str(error), traceback=traceback.format_exc())
    finally:
        if fixture:
            fault_name = {'false-ready': 'false-ready.json', 'false-ready-ae': 'false-ready-ae.json',
                          'log-channel-me': 'log-channel-me.json', 'log-channel-ae': 'log-channel-ae.json',
                          'readiness-me': 'readiness-me.json', 'readiness-ae': 'readiness-ae.json',
                          'pruner-exception': 'pruner-exception.json',
                          'offline-purge-rejoin': 'offline-purge.json'}.get(args.scenario)
            if fault_name and (fixture.root / fault_name).is_file():
                witness = json.loads((fixture.root / fault_name).read_text())
                (args.output / fault_name).write_text(json.dumps(witness, indent=2) + '\n')
                result['fault_evidence'] = str(args.output / fault_name)
                result['known_product_red'] = witness.get('known_product_red', False)
                result['observed_money'] = witness.get('after_fault_money', witness.get('baseline_money'))
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
