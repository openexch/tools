# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import unittest

from contracts import Violation
from observe import request_outcomes


class RequestOutcomeTest(unittest.TestCase):
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
