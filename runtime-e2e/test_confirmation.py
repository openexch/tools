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

    def judge(self, runs, check=lambda m, k: [], **kw):
        return confirmation.judge(self.plan, runs, self.cut, check=check, **kw)

    def test_all_pass(self):
        s = self.judge(runs_for(self.plan))
        self.assertEqual((s['status'], s['findings']), ('PASS', []))
        self.assertEqual({r['entry']: r['modes_passed'] for r in s['mode_table']},
                         {'core-drill-lostack': ['embedded', 'external'], 'core-red-1': ['embedded']})

    def test_inconclusive_then_pass_is_pass_and_both_are_kept(self):
        runs = runs_for(self.plan)
        runs.insert(0, dict(runs[0], status='INCONCLUSIVE', error='startup deadline exceeded', label='lostack-1'))
        s = self.judge(runs, explanations={'lostack-1': 'harness startup deadline on a loaded box'})
        self.assertEqual(s['status'], 'PASS')
        self.assertEqual([r['status'] for r in s['legs'][0]['runs']], ['INCONCLUSIVE', 'PASS'])

    def test_inconclusive_left_and_missing_leg(self):
        runs = runs_for(self.plan)
        runs[1]['status'] = 'INCONCLUSIVE'; runs[1]['error'] = 'x'
        s = self.judge(runs[:2])
        self.assertEqual(s['findings'], ['INCONCLUSIVE left: core-drill-lostack on s17-ext: x', 'leg not run: core-red-1 on s17-red1'])

    def test_a_control_held_with_a_fail_status(self):
        runs = runs_for(self.plan)
        runs[2]['status'] = 'FAIL'
        runs[2]['control'] = {'held': True, 'expected_text': 'gap'}
        self.assertEqual(self.judge(runs)['findings'], [])
        runs[2]['control'] = {'held': False, 'expected_text': 'gap'}
        self.assertEqual(len(self.judge(runs)['findings']), 2)

    def test_a_control_that_did_not_hold(self):
        runs = runs_for(self.plan)
        runs[2]['control'] = {'held': False, 'expected_text': 'gap'}
        self.assertEqual(self.judge(runs)['findings'], ["control did not hold on its own text: core-red-1 on s17-red1: 'gap'"])

    def test_a_core_control_without_a_block_is_judged_on_its_status(self):
        runs = runs_for(self.plan)
        self.assertEqual(self.judge(runs)['findings'], [])
        runs[2]['status'] = 'FAIL'
        self.assertEqual(self.judge(runs)['findings'], [
            'leg FAIL: core-red-1 on s17-red1',
            f"control did not hold on its own text: core-red-1 on s17-red1: {confirmation.CONTROL_STATUS_TEXT!r}"])

    def test_a_gateway_control_block_holds_on_status_and_failed_lines(self):
        self.plan = {'entries': [entry(PLAN, 'gw-b3')]}
        text = 'stored acceptance answered ADMISSION_CLOSED'
        runs = runs_for(self.plan)
        runs[0]['control'] = {'expected_text': text, 'failed_lines': ['stored_acceptance_answered'],
                              'observed': {'stored_acceptance_answered': text}}
        self.assertEqual(self.judge(runs)['findings'], [])
        runs[0]['control'] = {'expected_text': text, 'failed_lines': [], 'observed': {}}
        self.assertEqual(self.judge(runs)['findings'], [f'control did not hold on its own text: gw-b3 on gw-b3: {text!r}'])
        runs[0]['status'] = 'FAIL'
        self.assertEqual(self.judge(runs)['findings'], ['leg FAIL: gw-b3 on gw-b3',
                                                        f'control did not hold on its own text: gw-b3 on gw-b3: {text!r}'])

    def test_a_projection_control_block_holds_with_no_other_failed_line(self):
        self.plan = {'entries': [entry(PLAN, 'pj-nc-dropone')]}
        text = 'journalSeq missing in projection'
        runs = runs_for(self.plan)
        for r in runs:
            r['control'] = {'control': text, 'failed_lines': ['events_dense_to_head'], 'other_failed_lines': [],
                            'observed': {'events_dense_to_head': text}}
        self.assertEqual(self.judge(runs)['findings'], [])
        runs[1]['control'] = dict(runs[1]['control'], other_failed_lines=['history'])
        self.assertEqual(self.judge(runs)['findings'],
                         [f'control did not hold on its own text: pj-nc-dropone on pj-nc-dropone-ext: {text!r}'])

    def test_a_held_block_with_other_failures_did_not_hold(self):
        runs = runs_for(self.plan)
        runs[2]['control'] = {'name': 'x', 'expected_text': 'gap', 'held': True, 'failed_lines': ['a'],
                              'other_failures': {'money_oracle': 'money oracle not PASS'}}
        self.assertEqual(self.judge(runs)['findings'], ["control did not hold on its own text: core-red-1 on s17-red1: 'gap'"])

    def test_the_smoke_nomatch_block(self):
        self.plan = {'entries': [entry(PLAN, 'core-control-smoke-nomatch')]}
        runs = runs_for(self.plan, status='FAIL')
        for r in runs:
            r['control'] = {'name': 'nomatch', 'expected': 'not PASS; the order oracle names O7 or O10', 'held': True,
                            'other_failures': {}}
        self.assertEqual(self.judge(runs)['findings'], [])
        runs[0]['control'] = dict(runs[0]['control'], held=False, other_failures={'money_oracle': 'money oracle not PASS'})
        self.assertEqual(self.judge(runs)['findings'], [
            'leg FAIL: core-control-smoke-nomatch on cps-nofwd',
            "control did not hold on its own text: core-control-smoke-nomatch on cps-nofwd: "
            "'not PASS; the order oracle names O7 or O10'"])

    def test_more_than_two_reruns_is_a_finding(self):
        runs = runs_for(self.plan)
        first = [dict(runs[0], status='INCONCLUSIVE', label=f'r{n}') for n in range(3)]
        s = self.judge(first + runs, explanations={'r0': 'a', 'r1': 'b', 'r2': 'c'})
        self.assertEqual(s['findings'], ['more than 3 runs: core-drill-lostack on s17: 4 runs'])
        s = self.judge(first[1:] + runs, explanations={'r1': 'b', 'r2': 'c'})
        self.assertEqual(s['findings'], [])

    def test_a_rerun_needs_an_explanation(self):
        runs = runs_for(self.plan)
        runs[0]['label'] = 'lostack-2'
        runs.insert(0, dict(runs[0], status='FAIL', label='lostack-1', error='boom'))
        s = self.judge(runs)
        self.assertEqual(s['findings'], ['re-run without an explanation: lostack-1'])
        s = self.judge(runs, explanations={'lostack-1': 'the box rebooted under the run'})
        self.assertEqual((s['status'], s['findings']), ('PASS', []))
        self.assertEqual(s['legs'][0]['runs'][0]['explanation'], 'the box rebooted under the run')
        self.assertNotIn('explanation', s['legs'][0]['runs'][1])
        # a PASS before the last run needs no explanation
        runs[0]['status'] = 'PASS'
        self.assertEqual(self.judge(runs)['findings'], [])

    def test_an_accepted_failure_is_a_deviation(self):
        runs = runs_for(self.plan)
        runs[1].update(status='FAIL', label='lostack-ext', error='x')
        s = self.judge(runs, accepted={'lostack-ext': 'owner: known ME defect, fixed in the next cut'})
        self.assertEqual((s['status'], s['findings']), ('PASS', []))
        self.assertEqual(s['accepted'], [{'entry': 'core-drill-lostack', 'kind': 's17-ext', 'label': 'lostack-ext',
                                          'status': 'FAIL', 'error': 'x', 'evidence': None,
                                          'accepted': 'owner: known ME defect, fixed in the next cut',
                                          'findings': ['leg FAIL: core-drill-lostack on s17-ext: x']}])
        # another finding keeps the status FAIL; the deviation is still listed
        s = self.judge(runs[:2], accepted={'lostack-ext': 'owner'})
        self.assertEqual((s['status'], s['findings'], len(s['accepted'])), ('FAIL', ['leg not run: core-red-1 on s17-red1'], 1))
        # an INCONCLUSIVE last run is not accepted
        runs[1]['status'] = 'INCONCLUSIVE'
        s = self.judge(runs, accepted={'lostack-ext': 'owner'})
        self.assertEqual(s['findings'], ['INCONCLUSIVE left: core-drill-lostack on s17-ext: x',
                                         'accepted deviation names no last-run FAIL: lostack-ext'])

    def test_an_accepted_control_failure_covers_its_control_text(self):
        runs = runs_for(self.plan)
        runs[2].update(status='FAIL', label='red1')
        s = self.judge(runs, accepted={'red1': 'owner'})
        self.assertEqual((s['status'], len(s['accepted'][0]['findings'])), ('PASS', 2))

    def test_the_explain_file(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        f = Path(tmp.name) / 'explain.json'
        f.write_text(json.dumps({'a-1': 'why', 'explanations': {'b-1': 'why b'}, 'accepted': {'c': 'owner'}}))
        self.assertEqual(confirmation.load_explanations(f), ({'a-1': 'why', 'b-1': 'why b'}, {'c': 'owner'}))
        f.write_text(json.dumps({'a-1': ' '}))
        with self.assertRaises(confirmation.PlanError):
            confirmation.load_explanations(f)
        self.assertEqual(confirmation.load_explanations(None), ({}, {}))

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
