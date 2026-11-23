# SPDX-License-Identifier: Apache-2.0
"""The confirmation plan of a release cut and its judge.

usage: confirmation.py check-plan <plan.json>
       confirmation.py judge <plan.json> --results <runs.jsonl> --cut <cut manifest> --out <summary.json>

A confirmation plan (``confirmation-cut.json``) lists entries. Each entry has an ``id`` (unique), its ``scenario``, a mode
``class`` and its ``legs``: one leg per run, ``{kind}`` (a cut-derived manifest kind; the engine driver mode is the kind's,
``mk_manifests.CUT_KINDS``) or, for an entry that is not a fixture run, ``{kind, mode}`` with ``mode`` embedded or external.
A leg may carry ``settings`` (the run's environment additions, part of the leg's identity). The ``rows`` map names, for each
acceptance row the plan must cover (``REQUIRED_ROWS``), the entry ids that serve it.

Mode classes (the engine driver axis):
  both       at least one embedded and one external leg
  one-mode   one engine mode by design; ``cite`` names the reason (a file and line, or a decision)
An entry with one engine mode and no cite is refused: ``single-mode entry without a reason: <id>``. A required row with no
entry is refused: ``confirmation plan does not cover <row>``.

The judge reads one line per run (``runs.jsonl``: kind, scenario, settings, status, manifest, evidence) and decides:
  * every leg ran once at least and its last run is PASS (an INCONCLUSIVE or FAIL last run is named; a re-run is kept with
    the first, in order);
  * a control leg (``control: true`` on the entry) whose result records a control block held on its own text;
  * every fixture leg's manifest is accepted by ``release_cut.check`` against THIS cut: a manifest derived from another cut
    is refused with the checker's own text (K4 ``... is not an artifact of cut <id> ...``);
  * the mode table (entry, class, cite, modes required, modes run) is written into the summary.
Exit codes: 0 PASS, 1 FAIL (the findings are printed), 64 usage.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

MODES = ('embedded', 'external')
CLASSES = ('both', 'one-mode')
# The rows a confirmation of a core cut covers: the plan rows of RC1 to RC4 served by fixture entries, the cutover rows of
# the smoke, the red proofs, the observation drill and the market-data drills, the kept cross-version and activation cases,
# and the console's rollout gate
REQUIRED_ROWS = ('RC1', 'RC2-A01', 'RC2-A02', 'RC2-A03', 'RC2-A04', 'RC2-A05', 'RC2-A06', 'RC2-X', 'RCS', 'RC3', 'RC4',
                 '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '2.1', '2.3', '2.4', '3.2', 'M3', 'M4', 'M5', 'M6', 'M9', 'M16',
                 'console-roll-gate')


class PlanError(Exception):
    pass


def engine_mode(leg):
    """The engine driver mode of a leg: its own ``mode``, else its kind's engine driver."""
    if leg.get('mode'):
        if leg['mode'] not in MODES:
            raise PlanError(f'leg {leg!r}: mode is embedded or external')
        return leg['mode']
    import mk_manifests
    spec = mk_manifests.CUT_KINDS.get(leg.get('kind'))
    if spec is None:
        raise PlanError(f'leg {leg!r}: unknown cut kind {leg.get("kind")!r} and no mode')
    return spec[1]


def leg_key(kind, scenario, settings):
    return (kind, scenario, tuple(sorted((settings or {}).items())))


def check_plan(plan):
    """The plan's own findings (texts), empty when the plan is acceptable."""
    findings = []
    entries = plan.get('entries')
    if not isinstance(entries, list) or not entries:
        raise PlanError('the plan has no entries')
    seen, keys = set(), set()
    for entry in entries:
        eid = entry.get('id')
        if not eid or eid in seen:
            raise PlanError(f'entry id missing or repeated: {eid!r}')
        seen.add(eid)
        if entry.get('class') not in CLASSES:
            raise PlanError(f'{eid}: class is one of {", ".join(CLASSES)}')
        legs = entry.get('legs') or []
        if not legs:
            raise PlanError(f'{eid}: no legs')
        for leg in legs:
            key = leg_key(leg.get('kind'), entry.get('scenario'), leg.get('settings'))
            if key in keys:
                raise PlanError(f'{eid}: leg {leg!r} repeats another entry\'s leg')
            keys.add(key)
        modes = {engine_mode(leg) for leg in legs}
        if entry['class'] == 'both' and modes != set(MODES):
            findings.append(f'single-mode entry without a reason: {eid}')
        if entry['class'] == 'one-mode' and (len(modes) != 1 or not str(entry.get('cite') or '').strip()):
            findings.append(f'single-mode entry without a reason: {eid}')
    rows = plan.get('rows') or {}
    for row in REQUIRED_ROWS:
        served = [eid for eid in rows.get(row) or [] if eid in seen]
        if not served:
            findings.append(f'confirmation plan does not cover {row}')
    for row, ids in rows.items():
        for eid in ids:
            if eid not in seen:
                findings.append(f'row {row} names an entry the plan does not have: {eid}')
    return findings


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def judge(plan, runs, cut_path, old_pins=None, check=None):
    """The summary of a confirmation: status, findings, the mode table and every leg's runs."""
    findings = check_plan(plan)
    cut = json.loads(Path(cut_path).read_text())
    if check is None:
        import mk_manifests
        import release_cut
        pins = release_cut.load_old_pins(release_cut.old_pins_path()) if old_pins is None else old_pins

        def check(manifest, kind):
            return [item for item in release_cut.check(manifest, cut, mk_manifests.cut_class(kind), old_pins=pins).items]
    by_leg = {}
    for run in runs:
        by_leg.setdefault(leg_key(run.get('kind'), run.get('scenario'), run.get('settings')), []).append(run)
    table, legs_out = [], []
    for entry in plan['entries']:
        eid, modes_run = entry['id'], set()
        for leg in entry['legs']:
            mode = engine_mode(leg)
            runs_ = by_leg.get(leg_key(leg['kind'], entry['scenario'], leg.get('settings')), [])
            last = runs_[-1] if runs_ else None
            where = f'{eid} on {leg["kind"]}'
            row = {'entry': eid, 'kind': leg['kind'], 'mode': mode, 'settings': leg.get('settings') or {},
                   'runs': [{k: r.get(k) for k in ('status', 'wall_s', 'evidence', 'error', 'label')} for r in runs_]}
            legs_out.append(row)
            if last is None:
                findings.append(f'leg not run: {where}')
                continue
            status = last.get('status')
            if status == 'INCONCLUSIVE':
                findings.append(f'INCONCLUSIVE left: {where}: {last.get("error") or ""}'.rstrip(': '))
            elif status != 'PASS':
                findings.append(f'leg {status}: {where}: {last.get("error") or ""}'.rstrip(': '))
            else:
                modes_run.add(mode)
            control = last.get('control')
            if entry.get('control') and isinstance(control, dict) and control.get('held') is not True:
                findings.append(f'control did not hold on its own text: {where}: {control.get("expected_text")!r}')
            if last.get('manifest') and not leg.get('mode'):
                manifest = json.loads(Path(last['manifest']).read_text())
                for item in check(manifest, leg['kind']):
                    findings.append(f'{where}: {item}')
        table.append({'entry': eid, 'scenario': entry['scenario'], 'class': entry['class'], 'cite': entry.get('cite'),
                      'control': bool(entry.get('control')),
                      'modes_required': sorted({engine_mode(leg) for leg in entry['legs']}),
                      'modes_passed': sorted(modes_run), 'legs': [leg['kind'] for leg in entry['legs']]})
    return {'status': 'PASS' if not findings else 'FAIL', 'cut_id': cut.get('cut_id'), 'cut_sha256': _sha(cut_path),
            'findings': findings, 'mode_table': table, 'legs': legs_out,
            'counts': {'entries': len(plan['entries']), 'legs': len(legs_out),
                       'runs': sum(len(r['runs']) for r in legs_out)}}


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('check-plan'); p.add_argument('plan', type=Path)
    j = sub.add_parser('judge'); j.add_argument('plan', type=Path)
    j.add_argument('--results', required=True, type=Path); j.add_argument('--cut', required=True, type=Path)
    j.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        plan = json.loads(args.plan.read_text())
        if args.cmd == 'check-plan':
            findings = check_plan(plan)
        else:
            runs = [json.loads(line) for line in args.results.read_text().splitlines() if line.strip()]
            summary = judge(plan, runs, args.cut)
            summary['plan'] = {'path': str(args.plan), 'sha256': _sha(args.plan)}
            args.out.write_text(json.dumps(summary, indent=1) + '\n')
            findings = summary['findings']
    except PlanError as error:
        print('refused: ' + str(error)); return 1
    for text in findings:
        print(text)
    print('PASS' if not findings else 'FAIL')
    return 0 if not findings else 1


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).parent))
    sys.exit(main())
