# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from contracts import Violation, Inconclusive
from observe import request_outcomes, stable_sample
from test_contracts import money_sample, observe as bind_observations


class RequestOutcomeTest(unittest.TestCase):
    def test_stable_journal_divergence_is_failure_after_deadline_not_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sample = money_sample()
            sample['journal'].append(dict(sample['journal'][-1],seq=3,trade=8))
            for entry in sample['journal']: entry['seq'] += 1
            for row in sample['barrier']['samples']:
                row.update(journal_seq=4,last_trade=8)
            requests = []
            for order in sample['orders']:
                order['client'] = 'request-' + str(order['id'])
                requests.append({'method':'POST','path':'/api/v1/orders','user':order['user'],
                    'request':{'clientOrderId':order['client'],'marketId':1,'side':order['side'],
                               'price':'10.00000000','quantity':'1.00000000'},
                    'response':{'status':201,'body':json.dumps({'accepted':True,'omsOrderId':str(order['id'])})}})
            (root/'requests.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in requests))
            bind_observations(sample)
            state = {k:sample[k] for k in ['orders','executions','journal','balances','holds']}
            captured = {'state':state,'observation':sample['barrier']['samples'][0]}
            with patch('observe.collect',return_value=captured), patch('observe.time.sleep'), \
                    patch('observe.time.monotonic',side_effect=[0,0,1,3]):
                with self.assertRaisesRegex(Violation,'committed executions and applied settlements differ'):
                    stable_sample(SimpleNamespace(root=root),sample['initial_balances'],sample['funding'],[11,12],1,timeout=2)
            changing = dict(captured, observation=dict(captured['observation'],ae_position=641))
            with patch('observe.collect',side_effect=[captured,changing]), patch('observe.time.sleep'), \
                    patch('observe.time.monotonic',side_effect=[0,0,1,3]):
                with self.assertRaises(Inconclusive):
                    stable_sample(SimpleNamespace(root=root),sample['initial_balances'],sample['funding'],[11,12],1,timeout=2)

    def test_reject_and_lost_response_have_distinct_proven_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'requests.jsonl'
            def request(client, status, body):
                return {'method':'POST','path':'/api/v1/orders','user':7,
                        'request':{'clientOrderId':client,'marketId':1,'side':'BUY',
                                   'price':'10.00000000','quantity':'1.00000000'},
                        'response':{'status':status,'body':json.dumps(body)}}
            requests = [request('rejected',400,{'accepted':False}),
                        request('response-lost',0,{'error':'timeout'}),
                        request('unobserved',0,{'error':'timeout'})]
            path.write_text(''.join(json.dumps(r)+'\n' for r in requests))
            rows = [{'id':11,'client':'rejected'}, {'id':12,'client':'response-lost'}]
            result = request_outcomes(path, rows)
            self.assertEqual([r['id'] for r in result['rejected_order_specs']], [11])
            self.assertEqual([r['id'] for r in result['unacknowledged_order_specs']], [12])
            self.assertEqual(result['unobserved_ambiguous_requests'], ['unobserved'])
            self.assertEqual(result['unacknowledged_order_specs'][0]['price'], 1_000_000_000)
            with self.assertRaises(Violation): request_outcomes(path, rows + [{'id':13,'client':'rejected'}])
            path.write_text(path.read_text() + json.dumps(requests[0])+'\n')
            with self.assertRaises(Violation): request_outcomes(path, rows)
