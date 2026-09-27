# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from contracts import Inconclusive, Violation, check_result, reconcile, validate_manifest

FP = 100_000_000


def money_sample():
    sample = {
        'initial_balances': [{'user': 1, 'asset': 0, 'total': 0}, {'user': 1, 'asset': 1, 'total': 0},
                             {'user': 2, 'asset': 0, 'total': 0}, {'user': 2, 'asset': 1, 'total': 0}],
        'initial_snapshot_verified': True,
        'funding': [{'kind': 'deposit', 'user': 1, 'asset': 0, 'amount': 100 * FP},
                    {'kind': 'deposit', 'user': 2, 'asset': 1, 'amount': 2 * FP}],
        'journal_first_seq': 0,
        'journal': [{'seq': 0, 'kind': 'deposit', 'user': 1, 'asset': 0, 'amount': 100 * FP},
                    {'seq': 1, 'kind': 'deposit', 'user': 2, 'asset': 1, 'amount': 2 * FP},
                    {'seq': 2, 'kind': 'settle', 'trade': 7, 'buyer': 1, 'seller': 2,
                     'market': 1, 'price': 10 * FP, 'quantity': FP}],
        'markets': {'1': {'base': 1, 'quote': 0}},
        'accepted_order_ids': [11, 12],
        'accepted_order_specs': [
            {'id': 11, 'user': 1, 'market': 1, 'side': 'BUY', 'price': 10 * FP, 'quantity': FP},
            {'id': 12, 'user': 2, 'market': 1, 'side': 'SELL', 'price': 10 * FP, 'quantity': FP}],
        'orders': [{'id': 11, 'user': 1, 'market': 1, 'side': 'BUY', 'status': 'FILLED',
                    'price': 10 * FP, 'quantity': FP, 'filled': FP},
                   {'id': 12, 'user': 2, 'market': 1, 'side': 'SELL', 'status': 'FILLED',
                    'price': 10 * FP, 'quantity': FP, 'filled': FP}],
        'executions': [{'trade': 7, 'order': 11, 'user': 1, 'market': 1, 'side': 'BUY', 'price': 10 * FP, 'quantity': FP},
                       {'trade': 7, 'order': 12, 'user': 2, 'market': 1, 'side': 'SELL', 'price': 10 * FP, 'quantity': FP}],
        'balances': [{'user': 1, 'asset': 0, 'available': 90 * FP, 'locked': 0},
                     {'user': 1, 'asset': 1, 'available': FP, 'locked': 0},
                     {'user': 2, 'asset': 0, 'available': 10 * FP, 'locked': 0},
                     {'user': 2, 'asset': 1, 'available': FP, 'locked': 0}],
        'holds': [],
        'barrier': {'input_closed': True, 'pending_orders': 0, 'samples': [
            {'ae_position': 640, 'last_trade': 7, 'journal_seq': 2, 'orders_digest': 'a' * 64,
             'executions_digest': 'b' * 64, 'balances_digest': 'c' * 64, 'holds_digest': 'd' * 64},
            {'ae_position': 640, 'last_trade': 7, 'journal_seq': 2, 'orders_digest': 'a' * 64,
             'executions_digest': 'b' * 64, 'balances_digest': 'c' * 64, 'holds_digest': 'd' * 64}]}}
    return observe(sample)


def observe(sample):
    # Model two completed, stable observations, including a stable WRONG product state.
    # Changing a barrier position is deliberately not repaired by this test helper.
    for observation in sample['barrier']['samples']:
        for collection in ['orders', 'executions', 'balances', 'holds']:
            observation[collection + '_digest'] = hashlib.sha256(
                json.dumps(sample[collection], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return sample


class MoneyContractTest(unittest.TestCase):
    def test_proven_rejected_order_is_zero_effect_not_unfinished_accepted_work(self):
        sample = money_sample()
        spec = {'id': 13, 'user': 1, 'market': 1, 'side': 'BUY', 'price': 10 * FP, 'quantity': FP}
        sample['rejected_order_specs'] = [spec]
        sample['orders'].append(dict(spec, status='REJECTED', filled=0))
        self.assertEqual(reconcile(observe(sample))['orders'], 3)
        sample['orders'][-1]['status'] = 'NEW'
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_http_response_loss_does_not_hide_a_proven_durable_order(self):
        sample = money_sample()
        sample['accepted_order_ids'] = [11]
        sample['unacknowledged_order_specs'] = [sample['accepted_order_specs'].pop()]
        self.assertEqual(reconcile(observe(sample))['trades'], 1)
        sample['unacknowledged_order_specs'][0]['quantity'] += 1
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_submitted_order_price_cannot_silently_change_while_money_balances(self):
        sample = money_sample(); sample['orders'][0]['price'] = 9 * FP
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_exact_trade_has_expected_nonzero_counts(self):
        result = reconcile(money_sample())
        self.assertEqual(result, {'orders': 2, 'trades': 1, 'funding_events': 2, 'journal_rows': 3})

    def test_missing_genesis_is_indeterminate(self):
        sample = money_sample(); del sample['initial_balances']
        with self.assertRaises(Inconclusive): reconcile(observe(sample))

    def test_unverified_initial_snapshot_is_indeterminate(self):
        sample = money_sample(); sample['initial_snapshot_verified'] = False
        with self.assertRaises(Inconclusive): reconcile(observe(sample))

    def test_changing_barrier_never_passes(self):
        sample = money_sample(); sample['barrier']['samples'][1]['ae_position'] += 64
        with self.assertRaises(Inconclusive): reconcile(observe(sample))

    def test_one_satoshi_balance_error_is_a_failure(self):
        sample = money_sample(); sample['balances'][0]['available'] += 1
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_missing_accepted_order_fails_even_if_money_balances(self):
        sample = money_sample(); sample['accepted_order_ids'].append(99)
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_duplicate_financial_effect_does_not_hide_in_totals(self):
        sample = money_sample(); extra = copy.deepcopy(sample['journal'][-1]); extra['seq'] = 3; sample['journal'].append(extra)
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_lost_execution_cannot_pass(self):
        sample = money_sample(); sample['executions'].pop()
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_extra_deposit_cannot_be_tolerated(self):
        sample = money_sample(); extra = copy.deepcopy(sample['journal'][0]); extra['seq'] = 3; sample['journal'].append(extra)
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_hold_leak_fails(self):
        sample = money_sample(); sample['holds'] = [{'order': 11, 'user': 1, 'asset': 0, 'remaining': 1}]
        with self.assertRaises(Violation): reconcile(observe(sample))

    def test_no_executed_work_is_not_pass(self):
        sample = money_sample(); sample['orders'] = []; sample['executions'] = []; sample['accepted_order_ids'] = []
        with self.assertRaises(Inconclusive): reconcile(observe(sample))


class ResultContractTest(unittest.TestCase):
    def test_success_requires_assertions_and_processed_work(self):
        check_result({'status': 'PASS', 'assertions': 4, 'processed': 10, 'child_exit_codes': [0], 'skipped': 0})

    def test_zero_tests_or_work_is_rejected(self):
        for field in ['assertions', 'processed']:
            r = {'status': 'PASS', 'assertions': 4, 'processed': 10, 'child_exit_codes': [0], 'skipped': 0}; r[field] = 0
            with self.subTest(field=field), self.assertRaises(Inconclusive): check_result(r)

    def test_failed_child_skip_unknown_and_missing_kill_are_rejected(self):
        for update in [{'child_exit_codes': [0, 17]}, {'skipped': 1}, {'status': 'INDETERMINATE'},
                       {'fault': {'kind': 'kill', 'before_running': True, 'after_running': True, 'exit_observed': False}}]:
            r = {'status': 'PASS', 'assertions': 4, 'processed': 10, 'child_exit_codes': [0], 'skipped': 0}; r.update(update)
            with self.subTest(update=update), self.assertRaises((Inconclusive, Violation)): check_result(r)


class ManifestContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'manifest.json'
        jar = Path(self.tmp.name) / 'frozen.jar'; jar.write_bytes(b'contract-only synthetic artifact')
        artifact = {'path': str(jar), 'sha256': hashlib.sha256(jar.read_bytes()).hexdigest(), 'source_sha': 'a' * 40}
        self.m = {'schema_version': 1, 'run_id': 'r01-aabbccddeeff', 'image': 'sha256:' + 'b' * 64,
                  'state_root': str(self.path.parent / 'fixtures/r01-aabbccddeeff'),
                  'network': {'subnet': '172.30.217.0/24', 'internal': True},
                  'nodes': {name: '172.30.217.' + str(i + 10) for i, name in enumerate(['me0','me1','me2','ae0','ae1','ae2','bridge','oms','market','projector','probe'])},
                  'artifacts': {name: copy.deepcopy(artifact) for name in ['me','ae','bridge','oms','market','projector']},
                  'seed': 27092026, 'failure_domain': 'single_host_process_loss',
                  'limits': {'shm_mb': 256, 'memory_mb': 768, 'disk_min_free_mb': 20480},
                  'budgets': {'p99_ms': 50, 'p999_ms': 100, 'normal_settled_tps': 400, 'n_minus_one_settled_tps': 200}}

    def test_valid_isolated_manifest_is_accepted(self):
        validate_manifest(self.m, self.path)

    def test_endpoint_outside_fixture_is_rejected(self):
        self.m['nodes']['oms'] = '18.192.0.1'
        with self.assertRaises(Violation): validate_manifest(self.m, self.path)

    def test_escape_path_is_rejected(self):
        self.m['state_root'] = '/tmp'
        with self.assertRaises(Violation): validate_manifest(self.m, self.path)

    def test_missing_or_modified_artifact_is_rejected(self):
        for mode in ['missing', 'changed']:
            m = copy.deepcopy(self.m)
            if mode == 'missing': m['artifacts']['me']['path'] += '-missing'
            else: m['artifacts']['me']['sha256'] = '0' * 64
            with self.subTest(mode=mode), self.assertRaises((Violation, Inconclusive)): validate_manifest(m, self.path)

    def test_fake_host_ha_mutable_image_or_unbounded_memory_is_rejected(self):
        for key, value in [('image', 'openexch-mh:latest'), ('failure_domain', 'host_ha')]:
            m = copy.deepcopy(self.m); m[key] = value
            with self.subTest(key=key), self.assertRaises(Violation): validate_manifest(m, self.path)
        self.m['limits']['shm_mb'] = 0
        with self.assertRaises(Violation): validate_manifest(self.m, self.path)


if __name__ == '__main__':
    unittest.main()
