# SPDX-License-Identifier: Apache-2.0
"""T2 nightly on the dev box (critic D20): a local systemd timer runs this, never a GitHub runner.

Each scenario gets a fresh run identity derived from one pinned template manifest; artifacts,
resource profile and production timeouts are the template's. Results stay local under the evidence
root for sealing into notebook (H10); nothing is pushed or published.
"""
import argparse
import datetime
import json
from pathlib import Path
import subprocess
import sys

from core_contracts import child_manifest, validate_core_manifest

DEFAULT_SCENARIOS = ['core-boots-10', 'core-smoke']


def derive(template, template_path, scenario):
    """A fresh run identity from the template; the child file keeps the template's kind in its name (20.1 line 20)."""
    path, _ = child_manifest(template, Path(template_path).absolute().parent, scenario)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--template', required=True, type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--scenario', action='append')
    args = parser.parse_args()
    template = json.loads(args.template.read_text())
    validate_core_manifest(template, args.template)
    night = args.evidence_root / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    night.mkdir(parents=True, exist_ok=False)
    summary = []
    for scenario in args.scenario or DEFAULT_SCENARIOS:
        manifest = derive(template, args.template, scenario)
        output = night / scenario
        code = subprocess.call([sys.executable, str(Path(__file__).with_name('runner.py')), '--manifest', str(manifest),
                                '--scenario', scenario, '--output', str(output)],
                               stdout=(night / (scenario + '.log')).open('x'), stderr=subprocess.STDOUT)
        result = json.loads((output / 'result.json').read_text()) if (output / 'result.json').exists() else {}
        summary.append({'scenario': scenario, 'exit_code': code, 'status': result.get('status', 'NOT_RUN'),
                        'error': result.get('error')})
        (night / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if all(s['status'] == 'PASS' for s in summary) else 1


if __name__ == '__main__':
    sys.exit(main())
