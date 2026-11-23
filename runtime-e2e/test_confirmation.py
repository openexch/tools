# SPDX-License-Identifier: Apache-2.0
"""The confirmation plan and its judge: the plan's own refusals and the judge's findings, each with its exact text."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import confirmation
import core_contracts
import mk_manifests

HERE = Path(__file__).parent
PLAN = json.loads((HERE / 'confirmation-cut.json').read_text())
NIGHTS = ('nightly-cut-embedded.json', 'nightly-cut-external.json')
# the failover entries that ran embedded engines only before their external legs
FOURTEEN = ('core-drill-lostack', 'core-drill-coreleader', 'core-drill-meleader', 'core-drill-partition', 'core-drill-fwdpause',
            'core-drill-driverkill', 'core-drill-lifecycle-faults', 'core-drill-a04-one-bridge-halt', 'core-drill-a05-fwd-kill',
            'core-drill-a05-bridge-upgrade', 'core-drill-a06-two-forwarders-ticks', 'core-drill-a01-fwdring',
            'core-drill-a05-keep', 'core-boots-10')


def entry(plan, eid):
    return next(e for e in plan['entries'] if e['id'] == eid)


def runs_for(plan, status='PASS'):
    return [{'kind': leg['kind'], 'scenario': e['scenario'], 'settings': leg.get('settings') or {}, 'status': status}
            for e in plan['entries'] for leg in e['legs']]


class PlanTest(unittest.TestCase):
    def test_the_plan_is_accepted(self):
        self.assertEqual(confirmation.check_plan(PLAN), [])

    def test_every_night_entry_is_a_leg(self):
        legs = {(leg['kind'], e['scenario']) for e in PLAN['entries'] for leg in e['legs']}
        for name in NIGHTS:
            for x in json.loads((HERE / name).read_text())['entries']:
                self.assertIn((x['kind'], x['scenario']), legs, name)

    def test_the_fourteen_have_an_external_engine_leg(self):
        for eid in FOURTEEN:
            with self.subTest(eid):
                modes = {confirmation.engine_mode(leg) for leg in entry(PLAN, eid)['legs']}
                self.assertEqual(modes, {'embedded', 'external'})

    def test_one_of_the_fourteen_legs_removed_is_refused(self):
        plan = copy.deepcopy(PLAN)
        e = entry(plan, 'core-drill-lostack')
        e['legs'] = [leg for leg in e['legs'] if leg['kind'] != 's17-ext']
        self.assertIn('single-mode entry without a reason: core-drill-lostack', confirmation.check_plan(plan))

    def test_one_mode_without_a_cite_is_refused(self):
        plan = copy.deepcopy(PLAN)
        entry(plan, 'core-drill-a04-regenesis')['cite'] = ' '
        self.assertEqual(confirmation.check_plan(plan), ['single-mode entry without a reason: core-drill-a04-regenesis'])

    def test_a_row_without_entries_is_refused(self):
        plan = copy.deepcopy(PLAN)
        plan['entries'] = [e for e in plan['entries'] if e['id'] != 'core-history-loss']
        self.assertIn('confirmation plan does not cover 1.6', confirmation.check_plan(plan))
        plan = copy.deepcopy(PLAN); plan['rows'].pop('M16')
        self.assertEqual(confirmation.check_plan(plan), ['confirmation plan does not cover M16'])

    def test_the_new_kinds(self):
        self.assertEqual(mk_manifests.CUT_KINDS['s17-a05-ext'][:2], ('external', 'external'))
        self.assertEqual(mk_manifests.CUT_KINDS['s17-a05-keep-ext'][:2], ('external', 'external'))
        self.assertEqual(mk_manifests.CUT_KINDS['s17-a03-ext'][:2], ('external', 'external'))
        self.assertEqual(mk_manifests.CUT_KINDS['s17-act-embedded'][:2], ('external', 'embedded'))
        self.assertIn('s17-a03-ext', core_contracts.A03_KINDS)
        for new, base in (('s17-a05-ext', 's17-a05'), ('s17-a05-keep-ext', 's17-a05-keep'), ('s17-a03-ext', 's17-a03'),
                          ('s17-act-embedded', 's17-act')):
            self.assertEqual(mk_manifests.CUT_KINDS[new][2:], mk_manifests.CUT_KINDS[base][2:], new)


class JudgeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.cut = Path(tmp.name) / 'cut.json'; self.cut.write_text(json.dumps({'cut_id': 'c-1'}))
        self.plan = {'entries': [entry(PLAN, 'core-drill-lostack'), entry(PLAN, 'core-red-1')]}
        self.patch_rows()

    def patch_rows(self):
        saved = confirmation.REQUIRED_ROWS
        confirmation.REQUIRED_ROWS = ()
        self.addCleanup(setattr, confirmation, 'REQUIRED_ROWS', saved)

    def judge(self, runs, check=lambda m, k: []):
        return confirmation.judge(self.plan, runs, self.cut, check=check)

    def test_all_pass(self):
        s = self.judge(runs_for(self.plan))
        self.assertEqual((s['status'], s['findings']), ('PASS', []))
        self.assertEqual({r['entry']: r['modes_passed'] for r in s['mode_table']},
                         {'core-drill-lostack': ['embedded', 'external'], 'core-red-1': ['embedded']})

    def test_inconclusive_then_pass_is_pass_and_both_are_kept(self):
        runs = runs_for(self.plan)
        runs.insert(0, dict(runs[0], status='INCONCLUSIVE', error='startup deadline exceeded'))
        s = self.judge(runs)
        self.assertEqual(s['status'], 'PASS')
        self.assertEqual([r['status'] for r in s['legs'][0]['runs']], ['INCONCLUSIVE', 'PASS'])

    def test_inconclusive_left_and_missing_leg(self):
        runs = runs_for(self.plan)
        runs[1]['status'] = 'INCONCLUSIVE'; runs[1]['error'] = 'x'
        s = self.judge(runs[:2])
        self.assertEqual(s['findings'], ['INCONCLUSIVE left: core-drill-lostack on s17-ext: x', 'leg not run: core-red-1 on s17-red1'])

    def test_a_control_that_did_not_hold(self):
        runs = runs_for(self.plan)
        runs[2]['control'] = {'held': False, 'expected_text': 'gap'}
        self.assertEqual(self.judge(runs)['findings'], ["control did not hold on its own text: core-red-1 on s17-red1: 'gap'"])

    def test_a_manifest_of_another_cut_is_refused_with_the_checker_text(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        man = Path(tmp.name) / 'm.json'; man.write_text('{}')
        runs = runs_for(self.plan)
        runs[0]['manifest'] = str(man)
        text = 'K4 ae: sha256 ab is not an artifact of cut c-1 and not pinned in the old-artifact pins'
        s = self.judge(runs, check=lambda m, k: [text])
        self.assertEqual(s['findings'], ['core-drill-lostack on s17: ' + text])


if __name__ == '__main__':
    unittest.main()
