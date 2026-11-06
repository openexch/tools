# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import subprocess
import sys

from contracts import Violation
from test_contracts import money_sample


def run(output, manifest, manifest_path):
    proof_dir = output / 'negative-proofs'; proof_dir.mkdir()
    checker = Path(__file__).with_name('proof_check.py')
    passing = {'status': 'PASS', 'assertions': 1, 'processed': 1, 'skipped': 0, 'child_exit_codes': [0]}
    cases = [('valid-result', 'result', passing, 0), ('valid-money', 'money', money_sample(), 0)]
    for name, update in [('zero-tests', {'assertions': 0}), ('zero-work', {'processed': 0}),
                         ('child-failed', {'child_exit_codes': [0, 17]}), ('skipped', {'skipped': 1}),
                         ('unknown', {'status': 'UNKNOWN'}),
                         ('kill-noop', {'fault': {'kind': 'kill', 'before_running': True,
                                                 'after_running': True, 'exit_observed': False}})]:
        cases.append((name, 'result', {**passing, **update}, None))
    missing = money_sample(); del missing['initial_balances']
    cases.append(('missing-genesis', 'money', missing, None))
    invalid_endpoint = copy.deepcopy(manifest); invalid_endpoint['nodes']['oms'] = '8.8.8.8'
    cases.append(('external-endpoint', 'manifest', invalid_endpoint, None))
    missing_jar = copy.deepcopy(manifest); missing_jar['artifacts']['me']['path'] = str(proof_dir / 'absent.jar')
    cases.append(('missing-artifact', 'manifest', missing_jar, None))
    changed_jar = copy.deepcopy(manifest); changed_jar['artifacts']['me']['sha256'] = '0' * 64
    cases.append(('changed-artifact', 'manifest', changed_jar, None))
    rows = []
    for name, kind, proof, expected in cases:
        path = proof_dir / (name + '.json')
        if kind == 'manifest':
            proof['state_root'] = str(path.absolute().parent / 'fixtures' / proof['run_id'])
        path.write_text(json.dumps(proof, indent=2) + '\n')
        process = subprocess.run([sys.executable, str(checker), kind, str(path)],
                                 text=True, capture_output=True, timeout=30)
        row = {'name': name, 'exit_code': process.returncode, 'stdout': process.stdout,
               'stderr': process.stderr, 'expected': 'zero' if expected == 0 else 'nonzero'}
        rows.append(row)
        (output / 'negative-results.json').write_text(json.dumps(rows, indent=2) + '\n')
        # A crash or import failure is not a valid rejection by the proof contract.
        try: decision = json.loads(process.stdout)
        except ValueError as error: raise Violation('negative control did not reach validator: ' + name) from error
        if (expected == 0 and (process.returncode != 0 or decision['status'] != 'PASS_LOCAL_CONTRACT')) or (
                expected is None and (process.returncode not in (1, 2) or decision['status'] not in {'FAIL', 'INCONCLUSIVE'})):
            raise Violation('unexpected control outcome: ' + name)
    return {'status': 'PASS', 'assertions': len(rows), 'processed': len(rows), 'skipped': 0,
            'child_exit_codes': [0], 'scope': 'proof-validator subprocess controls; not cluster fault proof',
            'expected_negative_process_exits': rows}
