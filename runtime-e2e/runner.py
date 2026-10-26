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
        core_topology = manifest.get('schema_version') == 2
        if core_topology:
            from core_contracts import validate_core_manifest
            validate_core_manifest(manifest, args.manifest)
        else:
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
        if core_topology != args.scenario.startswith('core-'):
            raise Inconclusive('core-* scenarios need a schema v2 core manifest and only they accept one')
        if args.scenario.startswith('core-boots-'):
            from core_scenarios import consecutive_boots
            count = int(args.scenario.rsplit('-', 1)[1])
            if not 1 <= count <= 20: raise Inconclusive('boot count must be 1..20')
            result.update(consecutive_boots(manifest, args.manifest, args.output, count))
        elif args.scenario in {'core-boot', 'core-smoke'}:
            from core_fixture import CoreFixture
            import core_scenarios
            fixture = CoreFixture(args.manifest)
            result['state_root'] = str(fixture.root)
            fixture.start()
            result.update({'core-boot': core_scenarios.core_boot, 'core-smoke': core_scenarios.core_smoke}[args.scenario](fixture))
        elif args.scenario == 'harness-negative-controls':
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
                              'log-channel-me', 'log-channel-ae', 'journal-oms-restart', 'oms-recovery-admission', 'oms-durable-request-id', 'execution-projector-replay-crash', 'oms-hold-release-authority'}:
            fixture = Fixture(args.manifest)
            result['state_root'] = str(fixture.root)
            fixture.start()
            if args.scenario == 'critical-path-smoke':
                result.update(critical_path_smoke(fixture))
            elif args.scenario == 'oms-hold-release-authority':
                from r02_acceptance import oms_hold_release_authority
                result.update(oms_hold_release_authority(fixture))
            elif args.scenario == 'execution-projector-replay-crash':
                from r02_acceptance import execution_projector_replay_crash
                result.update(execution_projector_replay_crash(fixture))
            elif args.scenario == 'oms-durable-request-id':
                from r02_acceptance import oms_durable_request_id
                result.update(oms_durable_request_id(fixture))
            elif args.scenario == 'oms-recovery-admission':
                from r02_acceptance import oms_recovery_admission
                result.update(oms_recovery_admission(fixture))
            elif args.scenario == 'journal-oms-restart':
                from journal_cutover import journal_oms_restart
                result.update(journal_oms_restart(fixture))
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
                          'pruner-exception': 'pruner-exception.json', 'journal-oms-restart': 'journal-oms-restart.json', 'oms-recovery-admission': 'oms-recovery-admission.json', 'oms-durable-request-id': 'oms-durable-request-id.json', 'execution-projector-replay-crash': 'execution-projector-replay-crash.json', 'oms-hold-release-authority': 'oms-hold-release-authority.json',
                          'offline-purge-rejoin': 'offline-purge.json', 'core-boot': 'core-boot.json',
                          'core-smoke': 'core-smoke.json'}.get(args.scenario)
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
                # A row may declare exit codes that are evidence (a probe's REFUSED/UNKNOWN), judged by the scenario.
                rows = [json.loads(line) for line in commands.read_text().splitlines()]
                result['child_exit_codes'] = [0 if r['exit_code'] in r.get('accepted_exit_codes', [0]) else r['exit_code']
                                              for r in rows]
                if result['status'] == 'PASS':
                    try: check_result(result)
                    except Exception as error: result.update(status='INCONCLUSIVE', error=str(error))
        result['elapsed_ns'] = time.time_ns() - started
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1 if result['status'] == 'FAIL' else 2


if __name__ == '__main__':
    sys.exit(main())
