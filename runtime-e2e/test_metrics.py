# SPDX-License-Identifier: Apache-2.0
import copy
import unittest
from metrics import evaluate
from contracts import Violation


def measurement():
    events = [{'event':'window','start_ns':0,'warmup_seconds':0,'measurement_seconds':1,'rate':2,'total_scheduled':2}]
    for i, oid in enumerate([11, 12]):
        intended = i * 500_000_000
        events += [{'event':'intent','index':i,'intended_ns':intended,'started_ns':intended + 9_000_000},
                   {'event':'http','index':i,'response':{'status':201,'body':'{"accepted":true,"omsOrderId":"'+str(oid)+'"}'}},
                   {'event':'durable','index':i,'order_id':oid,'status':'FILLED','intended_ns':intended,
                    'started_ns':intended+9_000_000,'observed_ns':intended+10_000_000}]
    events.append({'event':'settled','trade_id':7,'observed_ns':600_000_000})
    sample = {'executions':[{'trade':7,'order':11},{'trade':7,'order':12}]}
    budget = {'minimum_latency_samples':2,'generator_p99_lateness_ms':20,'p99_ms':50,'p999_ms':100,
              'normal_committed_orders_per_s':2,'normal_settled_tps':1,'steady_success_ratio':1}
    return events, sample, budget


class MeasurementTest(unittest.TestCase):
    def test_lost_http_response_counts_durable_work_but_fails_http_success_gate(self):
        events, sample, budget = measurement()
        next(e for e in events if e['event'] == 'intent')['request'] = {'clientOrderId':'request-11'}
        next(e for e in events if e['event'] == 'http')['response'] = {'status':0, 'body':'{"error":"timeout"}'}
        next(e for e in events if e['event'] == 'durable')['client_id'] = 'request-11'
        sample['orders'] = [{'id':11, 'client':'request-11'}]
        result = evaluate(events, sample, budget, 'normal')
        self.assertEqual(result['durable_completed'], 2)
        self.assertEqual(result['http_success_ratio'], .5)
        self.assertEqual(result['status'], 'FAIL')
        sample['orders'][0]['client'] = 'different-request'
        with self.assertRaises(Violation): evaluate(events, sample, budget, 'normal')

    def test_http_callback_order_does_not_change_durable_latency(self):
        events, sample, budget = measurement()
        http = [e for e in events if e['event'] == 'http']
        events = [e for e in events if e['event'] != 'http'] + http
        self.assertEqual(evaluate(events, sample, budget, 'normal')['status'], 'PASS')

    def test_unaccepted_identity_cannot_supply_durable_latency(self):
        events, sample, budget = measurement()
        next(e for e in events if e['event'] == 'durable')['order_id'] = 999
        with self.assertRaises(Violation): evaluate(events, sample, budget, 'normal')

    def test_intended_arrival_latency_includes_generator_delay(self):
        events, sample, budget = measurement(); budget['p99_ms'] = 5
        result = evaluate(events, sample, budget, 'normal')
        self.assertEqual(result['p99_ms'], 10)
        self.assertEqual(result['status'], 'FAIL')

    def test_http_acceptance_does_not_count_as_durable_work(self):
        events, sample, budget = measurement(); events = [e for e in events if not(e['event']=='durable' and e['index']==1)]
        result = evaluate(events, sample, budget, 'normal')
        self.assertEqual(result['durable_completed'], 1)
        self.assertEqual(result['failed_or_uncompleted'], 1)
        self.assertEqual(result['success_ratio'], .5)
        self.assertEqual(result['status'], 'INCONCLUSIVE')

    def test_settlement_outside_window_does_not_inflate_goodput(self):
        events, sample, budget = measurement(); events[-1]['observed_ns'] = 1_500_000_000
        result = evaluate(events, sample, budget, 'normal')
        self.assertEqual(result['settled_trades_per_s'], 0)
        self.assertEqual(result['status'], 'FAIL')

    def test_all_valid_samples_pass_and_histogram_keeps_count(self):
        events, sample, budget = measurement(); result = evaluate(events, sample, budget, 'normal')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(sum(result['histogram_upper_bound_ms'].values()), 2)

    def test_generator_noise_is_inconclusive_not_product_pass(self):
        events, sample, budget = measurement(); budget['generator_p99_lateness_ms'] = 1
        self.assertEqual(evaluate(events, sample, budget, 'normal')['status'], 'INCONCLUSIVE')
