# SPDX-License-Identifier: Apache-2.0
"""Separate-process validation entry point, also used by harness negative controls."""
import json
from pathlib import Path
import sys

from contracts import Inconclusive, Violation, check_result, reconcile, validate_manifest


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in {'result', 'money', 'manifest'}:
            raise Inconclusive('expected result|money|manifest and a proof file')
        kind, path = sys.argv[1:]
        proof = json.loads(Path(path).read_text())
        if kind == 'result': check_result(proof)
        elif kind == 'money': reconcile(proof)
        else: validate_manifest(proof, path)
        print(json.dumps({'status': 'PASS_LOCAL_CONTRACT', 'kind': kind}))
        return 0
    except Violation as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error)})); return 1
    except Exception as error:
        print(json.dumps({'status': 'INCONCLUSIVE', 'error': str(error)})); return 2


if __name__ == '__main__':
    sys.exit(main())
