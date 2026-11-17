# SPDX-License-Identifier: Apache-2.0
import unittest

import core_contracts
import gateway_drills
import gateway_measure as gm
from contracts import Violation

MEMBERS = {'ae0': '172.30.216.10', 'ae1': '172.30.216.11', 'ae2': '172.30.216.12'}
COUNTERS = """-P INPUT ACCEPT -c 10 2000
-A INPUT -p udp -m udp --dport 20480 -c 120 98304
-A INPUT -s 172.30.216.12/32 -p udp -c 5 400
-A INPUT -s 172.30.216.11/32 -p udp -c 7 500
-A INPUT -s 172.30.216.10/32 -p udp -c 130 99000
-A INPUT -s 172.30.216.10/32 -p udp -m udp --dport 20480 -j DROP -c 3 300
-A INPUT -s 172.30.216.99/32 -p udp -c 1 1
"""


class MeasurementTableTest(unittest.TestCase):
    def test_a_measurement_is_dispatched_but_is_no_drill(self):
        self.assertTrue(gateway_drills.is_scenario('gateway-egress-cost'))
        self.assertNotIn('gateway-egress-cost', gateway_drills.SCENARIOS)
        self.assertFalse(gateway_drills.is_scenario('gateway-egress-costs'))

    def test_settings_default_and_env_override(self):
        self.assertEqual(gm.settings({})['MEASURE_PAIRS'], 200)
        self.assertEqual(gm.settings({'SIM_S': '30'})['SIM_S'], 30)
        with self.assertRaises(Violation):
            gm.settings({'MEASURE_RATE': '0'})
        with self.assertRaises(Violation):
            gm.settings({'MEASURE_RATE': 'fast'})

    def test_sim_population_is_the_simulator_default(self):
        users = gm.sim_users()
        self.assertEqual(len(users), 51)
        self.assertEqual((users[0], users[-2], users[-1]), (900001, 900050, 900999))


class CounterTest(unittest.TestCase):
    def test_rules_count_only(self):
        gw = gm.counting_rules('gw0', MEMBERS, 20480)
        fwd = gm.counting_rules('fwd0', MEMBERS, 20480)
        self.assertEqual(len(gw), 4)
        self.assertEqual(len(fwd), 3)
        for rule in gw + fwd:
            self.assertNotIn('-j', rule)
            self.assertEqual(rule[:4], ['-w', '2', '-I', 'INPUT'])
        self.assertIn(['-w', '2', '-I', 'INPUT', '-p', 'udp', '--dport', '20480'], gw)
        self.assertFalse(any('--dport' in r for r in fwd))

    def test_parse_takes_only_the_counting_rules(self):
        out = gm.parse_counters(COUNTERS, MEMBERS, 20480)
        self.assertEqual(out['response_port'], 98304)
        self.assertEqual((out['from_ae0'], out['from_ae1'], out['from_ae2']), (99000, 500, 400))
        self.assertEqual(out['packets']['response_port'], 120)
        self.assertEqual(set(out), {'response_port', 'from_ae0', 'from_ae1', 'from_ae2', 'packets'})

    def test_a_missing_rule_is_absent_never_zero(self):
        out = gm.parse_counters('-A INPUT -s 172.30.216.10/32 -p udp -c 1 64\n', MEMBERS, 20480)
        self.assertNotIn('response_port', out)
        cost = gm.phase_cost({'st0': dict(out, at_ns=0)}, {'st0': dict(out, at_ns=10**9)})
        self.assertIsNone(cost['st0']['response_port_bytes'])
        self.assertIsNone(cost['st0']['from_core_bytes'])


class PhaseCostTest(unittest.TestCase):
    def snap(self, at_s, port, a0, a1=0, a2=0):
        return {'at_ns': int(at_s * 1e9), 'response_port': port, 'from_ae0': a0, 'from_ae1': a1, 'from_ae2': a2}

    def test_idle_rate_and_per_order_net_of_idle(self):
        idle = gm.phase_cost({'st0': self.snap(0, 0, 0)}, {'st0': self.snap(10, 1000, 1200)})
        self.assertEqual(idle['st0']['response_port_bytes_per_s'], 100.0)
        self.assertEqual(idle['st0']['from_core_bytes_per_s'], 120.0)
        load = gm.phase_cost({'st0': self.snap(10, 1000, 1200)}, {'st0': self.snap(30, 103000, 104600)}, orders=100,
                             idle=idle)
        # 102 000 bytes over 20 s less 100 B/s idle = 100 000 bytes for 100 orders
        self.assertEqual(load['st0']['response_port_bytes'], 102000)
        self.assertEqual(load['st0']['response_port_bytes_per_order'], 1000.0)
        self.assertEqual(load['st0']['from_core_bytes_per_order'], 1010.0)

    def test_stream_view_is_the_watermark_delta(self):
        before = {'st0': {'stream_watermark': 10.0, 'stream_event_queries_total': 3.0}}
        after = {'st0': {'stream_watermark': 1010.0, 'stream_event_queries_total': 15.0}}
        view = gm.stream_view(before, after, 'st0')
        self.assertEqual((view['events'], view['event_queries']), (1000.0, 12.0))
        self.assertIsNone(view['snapshot_queries'])


class FootprintTest(unittest.TestCase):
    STATUS = 'Name:\toe-gateway\nVmSize:\t  300000 kB\nVmHWM:\t   60000 kB\nVmRSS:\t   58000 kB\nRssAnon:\t    9000 kB\n' \
             'RssFile:\t    4000 kB\nRssShmem:\t   45000 kB\noe-gateway\n49180\t/dev/shm\n'

    def test_status_and_du(self):
        out = gm.parse_status(self.STATUS)
        self.assertEqual(out, {'VmSize_kib': 300000, 'VmHWM_kib': 60000, 'VmRSS_kib': 58000, 'RssAnon_kib': 9000,
                               'RssFile_kib': 4000, 'RssShmem_kib': 45000, 'shm_kib': 49180})

    def test_summary_keeps_peak_and_last(self):
        samples = [{'containers': {'gw0': {'VmRSS_kib': 10, 'shm_kib': 50, 'docker_mem': '1MiB / 1GiB'}}},
                   {'containers': {'gw0': {'VmRSS_kib': 30, 'shm_kib': 40}}},
                   {'containers': {'gw0': {'VmRSS_kib': 20, 'shm_kib': 45}}}]
        out = gm.footprint_summary(samples)['gw0']
        self.assertEqual((out['samples'], out['peak_VmRSS_kib'], out['last_VmRSS_kib'], out['peak_shm_kib']), (3, 30, 20, 50))
        self.assertNotIn('peak_docker_mem', out)


class SimTest(unittest.TestCase):
    def test_argv_names_its_settings_and_no_secret(self):
        argv = gm.sim_argv('/data/market-sim', '10.0.0.1:8080', '10.0.0.2:8090', '/data/sim-keys', '10.0.0.3:8095', 600,
                           '/data/k.json', {1: '15', 0: '3000000'})
        self.assertEqual(argv[:4], ['timeout', '-s', 'INT', '600'])
        self.assertIn('http://10.0.0.1:8080', argv)
        self.assertIn('ws://10.0.0.2:8090/ws/v2', argv)
        self.assertEqual(argv[argv.index('-faucet-max') + 1], '0:3000000,1:15')
        self.assertEqual(argv[argv.index('-api-keys-file') + 1], '/data/sim-keys')
        self.assertEqual(argv[argv.index('-bridge-health-url') + 1], '')
        self.assertFalse(any('X-API-Key' in a or 'Bearer' in a for a in argv))

    def test_caps_cover_the_simulator_floats_in_one_deposit(self):
        floats = {0: 3_000_000, 1: 15, 2: 300, 3: 6000, 4: 300_000, 5: 3_000_000}      # three times each per-bot float
        for asset, want in floats.items():
            self.assertGreaterEqual(float(gm.SIM_FAUCET_CAPS[asset]), want)

    def test_sim_metrics_parse(self):
        text = '# TYPE x counter\nsim_orders_placed_total 12\nsim_rejects_total{reason="TOO_MANY_PENDING_REQUESTS"} 3\nbad\n'
        out = gm.sim_metrics(text)
        self.assertEqual(out['sim_orders_placed_total'], 12.0)
        self.assertEqual(out['sim_rejects_total{reason="TOO_MANY_PENDING_REQUESTS"}'], 3.0)

    def test_count_slots_are_fixture_slots(self):
        for slot in gm.COUNT_SLOTS:
            self.assertTrue(slot in core_contracts.GATEWAY_SLOTS or slot in ('fwd0', 'fwd1'), slot)


if __name__ == '__main__':
    unittest.main()
