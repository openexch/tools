# SPDX-License-Identifier: Apache-2.0
"""The observation drill's pure parts: its settings and refusals, the kinds it runs on, the line that judges the
verdict against the planted fault, and the sampler configuration it writes for the fixture host."""
import json
from pathlib import Path
import unittest

from contracts import Inconclusive
import observation_drill as od


class Settings(unittest.TestCase):
    def test_defaults_and_refusals(self):
        s, fault, control = od.drill_settings({})
        self.assertEqual((s, fault, control), (od.SETTINGS, 'none', None))
        with self.assertRaisesRegex(Inconclusive, 'OBS_DRILL_FAULT is one of'):
            od.drill_settings({'OBS_DRILL_FAULT': 'meteor'})
        with self.assertRaisesRegex(Inconclusive, 'unknown control: x'):
            od.drill_settings({'OBS_DRILL_FAULT': 'kill-core', 'OBS_DRILL_CONTROL': 'x'})
        with self.assertRaisesRegex(Inconclusive, 'needs a fault to skip'):
            od.drill_settings({'OBS_DRILL_CONTROL': 'skip-plant'})

    def test_kinds(self):
        od.check_scenario({'manifest_kind': 'cps-ext'}, 'core-observation-drill', {})
        with self.assertRaisesRegex(Inconclusive, 'runs on cps or cps-ext'):
            od.check_scenario({'manifest_kind': 'cps-nofwd'}, 'core-observation-drill', {})
        with self.assertRaisesRegex(Inconclusive, 'unknown observation scenario'):
            od.check_scenario({'manifest_kind': 'cps'}, 'core-observation-x', {})


def verdict(status, failures=(), inconclusive=()):
    return {'status': status, 'failures': list(failures), 'inconclusive': list(inconclusive)}


class VerdictLine(unittest.TestCase):
    def test_clean_run(self):
        self.assertTrue(od.verdict_line(verdict('PASS'), 'none', None)['holds'])
        line = od.verdict_line(verdict('FAIL', ['V12 history stale outside a recorded window']), 'none', None)
        self.assertEqual(line['text'], 'clean run did not pass: V12 history stale outside a recorded window')

    def test_exactly_the_planted_line_and_service(self):
        ok = od.verdict_line(verdict('FAIL', ['V3 alive and unreachable: ct-bridge/bridge0']), 'freeze-bridge', 'bridge0')
        self.assertTrue(ok['holds'])
        more = od.verdict_line(verdict('FAIL', ['V3 alive and unreachable: ct-bridge/bridge0', 'V5 spin: core/ae1']),
                               'freeze-bridge', 'bridge0')
        self.assertFalse(more['holds'])
        self.assertTrue(more['text'].startswith('the verdict named more than the planted line and service'))
        missed = od.verdict_line(verdict('PASS'), 'kill-core', 'ae2')
        self.assertEqual(missed['text'], 'verdict line V2 is vacuous')
        grown = od.verdict_line(verdict('FAIL', ['V7 unexplained disk growth: core/ae0 state 268435456']), 'grow-file', 'ae0')
        self.assertTrue(grown['holds'])


class FakeFixture:
    root = Path('/state/root')
    pg = Path('/pg/bin')
    gateway = '172.30.1.1'
    m = {'nodes': {'ae0': '10.0.0.10', 'me0': '10.0.0.17', 'bridge0': '10.0.0.13', 'projector': '10.0.0.21',
                   'gw0': '10.0.0.40', 'pj0': '10.0.0.44', 'md0': '10.0.0.46', 'probe': '10.0.0.20'},
         'ports': {'ae_base': 19300, 'me_base': 9000, 'stride': 100, 'bridge_http': 9600, 'projector_http': 9601,
                   'gateway_admin': 8081, 'projector_admin': 8095, 'md_admin': 8111},
         'postgres_port': 55000}
    registry = {'containers': {k: 'c-' + k for k in ('ae0', 'me0', 'bridge0', 'projector', 'gw0', 'pj0', 'md0', 'probe',
                                                       'gw0-driver')}}


class ExtFixture(FakeFixture):
    m = dict(FakeFixture.m, engine_driver='external', probe_libs={'aeronmd': {'path': '/a/aeronmd', 'sha256': 'x'}},
             nodes=dict(FakeFixture.m['nodes'], ae1='10.0.0.11', ae2='10.0.0.12'),
             ports=dict(FakeFixture.m['ports'], ae_base=9300))

    def engine_driver(self):
        return self.m.get('engine_driver', 'embedded')


class EmbFixture(ExtFixture):
    m = {k: v for k, v in ExtFixture.m.items() if k != 'engine_driver'}


class MoneyCheckCommand(unittest.TestCase):
    def test_the_driver_mode_is_the_fixtures(self):
        ext = od.money_check_argv(ExtFixture(), 'Q0', [93001, 93002])
        self.assertEqual(od.money_check_driver(ExtFixture()), ('external', '/dev/shm/probe-aeron'))
        self.assertEqual(ext[ext.index('--driver-mode') + 1], 'external')
        self.assertEqual(ext[ext.index('--aeron-dir') + 1], '/dev/shm/probe-aeron')
        emb = od.money_check_argv(EmbFixture(), 'Q2', [93001, 93002])
        self.assertEqual(od.money_check_driver(EmbFixture()), ('embedded', None))
        self.assertEqual(emb[emb.index('--driver-mode') + 1], 'embedded')
        self.assertNotIn('--aeron-dir', emb)       # money-check refuses --aeron-dir with embedded
        # everything else is the same command in both modes
        strip = lambda argv: [a for a in argv if a not in ('external', 'embedded', '--aeron-dir', '/dev/shm/probe-aeron')]
        self.assertEqual(strip(ext), strip([a.replace('Q2', 'Q0') for a in emb]))
        self.assertEqual(emb[emb.index('--zero-hold-users') + 1], '93001-93002')
        self.assertEqual(emb[emb.index('--funding-file') + 1], '/data/mc/funding-Q2.json')
        self.assertEqual(ext[ext.index('--core-metrics') + 1],
                         'http://10.0.0.10:9306/metrics,http://10.0.0.11:9406/metrics,http://10.0.0.12:9506/metrics')

    def test_an_external_kind_never_falls_back_to_embedded(self):
        class NoDriver(ExtFixture):
            m = {k: v for k, v in ExtFixture.m.items() if k != 'probe_libs'}
        with self.assertRaisesRegex(Inconclusive, "external driver mode needs the probe's aeronmd"):
            od.money_check_argv(NoDriver(), 'Q0', [93001, 93002])

        class Odd(ExtFixture):
            m = dict(ExtFixture.m, engine_driver='shared')
        with self.assertRaisesRegex(Inconclusive, 'no driver mode'):
            od.money_check_driver(Odd())


class SamplerConfig(unittest.TestCase):
    def test_every_slot_with_its_kind_and_routes(self):
        c = od.sampler_config(FakeFixture(), '/out/samples/s.jsonl', [11, 12])
        by = {s['name']: s for s in c['services']}
        self.assertEqual(sorted(by), ['core/ae0', 'ct-bridge/bridge0', 'match/me0', 'money-projector/projector',
                                      'oe-gateway/gw0', 'oe-marketdata/md0', 'oe-projector/pj0'])
        self.assertEqual(by['core/ae0']['kind'], 'core member')
        self.assertEqual(by['oe-gateway/gw0']['metrics'], 'http://10.0.0.40:8081/metrics')
        self.assertNotIn('ready', by['money-projector/projector'])
        self.assertEqual(c['shm'], ['/proc/11/root/dev/shm', '/proc/12/root/dev/shm'])
        self.assertEqual(c['supervisor'], 'docker')
        models = {d['name']: d['model'] for d in c['dirs']}
        self.assertEqual(models['core/ae0 state'], 'core_log')
        self.assertEqual(models['samples'], 'sampler_file')
        json.dumps(c)


if __name__ == '__main__':
    unittest.main()
