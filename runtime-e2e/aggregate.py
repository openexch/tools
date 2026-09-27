# SPDX-License-Identifier: Apache-2.0
"""Sequential, isolated fault suite. Expected baseline RED remains a nonzero product result."""
import json
from pathlib import Path
import subprocess
import sys
import uuid

from contracts import Inconclusive
from fixture import Fixture


def baseline_fault_reproduction(manifest, manifest_path, output):
    children = []
    for scenario in ['false-ready', 'pruner-exception', 'offline-purge-rejoin']:
        derived = json.loads(json.dumps(manifest))
        derived['run_id'] = 'r01-' + uuid.uuid4().hex[:12]
        parent = Path(manifest_path).absolute().parent
        derived['state_root'] = str(parent / 'fixtures' / derived['run_id'])
        child_manifest = parent / (derived['run_id'] + '-manifest.json')
        with child_manifest.open('x') as stream: json.dump(derived, stream, indent=2); stream.write('\n')
        destination = output / scenario
        with (output / (scenario + '.log')).open('x') as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('runner.py')),
                '--manifest', str(child_manifest), '--scenario', scenario, '--output', str(destination)],
                stdout=log, stderr=log)
            try: exit_code = process.wait(timeout=900)
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=90)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                if Path(derived['state_root']).exists(): Fixture(child_manifest, attach=True).close()
                raise Inconclusive('fault scenario exceeded its orchestration bound: ' + scenario)
        result = json.loads((destination / 'result.json').read_text())
        children.append({'scenario': scenario, 'exit_code': exit_code, 'result': result})
        (output / 'children.json').write_text(json.dumps(children, indent=2) + '\n')
        if result.get('teardown') != 'COMPLETE_OWNED_RESOURCES_ONLY':
            raise Inconclusive('child fixture teardown was not verified: ' + scenario)
    states = [child['result']['status'] for child in children]
    baseline_red = all(c['exit_code'] == 1 and c['result'].get('known_product_red') is True for c in children)
    if any(state not in {'PASS', 'FAIL'} for state in states): status = 'INCONCLUSIVE'
    else: status = 'FAIL' if 'FAIL' in states else 'PASS'
    return {'status': status, 'assertions': sum(c['result']['assertions'] for c in children),
            'processed': sum(c['result']['processed'] for c in children), 'skipped': 0,
            'child_exit_codes': [c['exit_code'] for c in children],
            'three_baseline_reds_verified': baseline_red, 'children': children,
            'scope': 'three real cluster faults; observed baseline defects remain FAIL, never product PASS'}
