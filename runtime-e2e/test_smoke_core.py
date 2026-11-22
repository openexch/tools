# SPDX-License-Identifier: Apache-2.0
"""The critical-path drills' pure parts and their fixture pieces: the market-data slot (contract, keys, environment,
the cut kinds and the checker), the scenario registry and its controls, the verdict, the oracle rows rebuilt from the
REST client's log, the request-log, workload, history, stream, tape, book, gate and history-loss lines, the REST client
and the runner's hold point (no Docker)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from contracts import FP, Inconclusive, Violation
import core_contracts
from core_contracts import validate_core_manifest
from credentials import KeyRing
import gateway_probe
import nightly
import runner
import smoke_core as sc
from test_core_fixture import fixture_for, write
from test_projection import projection_manifest

A, B, C = 91001, 91002, 91003
KEY1, KEY2 = '11111111-2222-4333-8444-555555555555', '66666666-7777-4888-8999-aaaaaaaaaaaa'


def marketdata_manifest(directory, driver='external', kind='cps'):
    """A projection manifest (the projector binary in pj0 and pj1) with the market-data role md0 and its artifact."""
    m = projection_manifest(directory, driver, slots={'pj0': 'history_projector', 'pj1': 'history_projector'})
    m['nodes']['md0'] = '172.30.99.46'
    m['ports'] = core_contracts.ports_of(m)
    entry = dict(write(directory, 'oe-marketdata', b'elf-oe-marketdata'), target='oe-marketdata', driver=driver)
    if driver == 'external':
        entry['libs'] = copy.deepcopy(m['artifacts']['forwarder']['libs'])
    m['artifacts']['marketdata'] = entry
    m['slot_artifacts']['md0'] = 'marketdata'
    if kind:
        m['manifest_kind'] = kind
    return m


def marketdata_fixture(directory, driver='external'):
    f = fixture_for(marketdata_manifest(directory, driver), directory)
    f.gateway_slots = f.projection_slots = f.marketdata_slots = True
    f.keys = KeyRing(gateway=True, projection=True, marketdata=True)
    f.secret_values = f.keys.secrets()
    return f


def call(method, path, status, reply=None, user=A, key=None, body=None, tag=None, sent=1, gate=None):
    return {'user': user, 'method': method, 'path': path, 'key': key, 'body': body, 'tag': tag, 'status': status,
            'reply': reply, 'sent_ns': sent, 'recv_ns': sent + 1, 'gate': gate,
            'attempts': [{'status': status, 'reply': reply, 'sent_ns': sent, 'recv_ns': sent + 1}]}


class MarketDataContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'
        self.m = marketdata_manifest(self.dir, kind=None)

    def tearDown(self):
        self.temp.cleanup()

    def bad(self, edit, text):
        m = copy.deepcopy(self.m); edit(m)
        with self.assertRaises(Violation) as caught:
            validate_core_manifest(m, self.path, cpu_count=24)
        self.assertIn(text, str(caught.exception))

    def test_a_market_data_manifest_passes_in_both_driver_modes(self):
        validate_core_manifest(self.m, self.path, cpu_count=24)
        validate_core_manifest(marketdata_manifest(self.dir, 'embedded', kind=None), self.path, cpu_count=24)
        self.assertTrue(core_contracts.marketdata_manifest(self.m))
        self.assertIn('md0', core_contracts.roles_of(self.m))
        self.assertEqual(core_contracts.slots_of(self.m)['md0'], 'marketdata')
        self.assertEqual(core_contracts.ports_of(self.m)['md_admin'], 8111)

    def test_the_slot_is_pinned_like_any_slot_and_needs_the_gateway_roles(self):
        self.bad(lambda m: m['artifacts']['marketdata'].__setitem__('target', 'oe-gateway'), 'target must be oe-marketdata')
        self.bad(lambda m: m['artifacts']['marketdata'].pop('libs'), 'an external slot stages aeronmd')
        self.bad(lambda m: m['artifacts']['marketdata'].__setitem__('mode', 'x'), 'artifact keys are')
        self.bad(lambda m: m['artifacts'].pop('marketdata'), 'declares its artifact explicitly')
        self.bad(lambda m: m['slot_artifacts'].__setitem__('md0', 'gateway'), 'cannot run artifact')
        self.bad(lambda m: m['ports'].pop('md_public'), 'port profile')
        m = copy.deepcopy(self.m)
        for role in core_contracts.GATEWAY_ROLES:
            m['nodes'].pop(role)
        with self.assertRaisesRegex(Violation, 'needs the gateway roles'):
            core_contracts.marketdata_manifest(m)

    def test_the_me_key_table_holds_a_gateway_key_only_for_a_market_data_manifest(self):
        with_md, without = KeyRing(gateway=True, marketdata=True), KeyRing(gateway=True)
        self.assertIn(':GATEWAY:', with_md.table('me'))
        self.assertNotIn(':GATEWAY:', without.table('me'))
        self.assertTrue(with_md.credential('md0', 'me').startswith('131:GATEWAY:'))

    def test_the_kinds(self):
        import mk_manifests
        self.assertEqual(core_contracts.MARKETDATA_KINDS, {'cps', 'cps-ext', 'cps-nofwd', 'cps-nofwd-ext', 'cps-nc-dropone'})
        for kind in core_contracts.MARKETDATA_KINDS:
            spec = core_contracts.GATEWAY_KINDS[kind]
            self.assertIn(kind, core_contracts.CUT_KINDS)
            self.assertIn(kind, core_contracts.PROJECTOR_BINARY_KINDS)
            self.assertEqual(spec['marketdata'], {'md0': 'marketdata'})
            self.assertEqual(mk_manifests.CUT_KINDS[kind][3], 'NOFWD' if 'nofwd' in kind else 'A')
            self.assertEqual(spec['driver'], 'external' if kind.endswith('-ext') else 'embedded')
        self.assertEqual(mk_manifests.SLOTS['NOFWD'], {'fwd0': None, 'fwd1': None, 'bridge0': 'bridge', 'bridge1': 'bridge'})
        self.assertEqual(core_contracts.GATEWAY_KINDS['cps-nc-dropone']['projector_define'], 'PROJ_NC_DROP_ONE')


class MarketDataFixtureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_the_environment_in_both_driver_modes(self):
        for driver in ('external', 'embedded'):
            f = marketdata_fixture(self.dir, driver)
            env = f.marketdata_env('md0')
            core_contracts.assert_production_timeouts(env, f.allowed_env())
            self.assertEqual(env['MD_DRIVER_MODE'], driver)
            self.assertEqual('AERON_DIR' in env, driver == 'external')
            self.assertEqual('MD_DRIVER_DIR' in env, driver == 'embedded')
            self.assertTrue(env['ME_AUTH_CREDENTIAL'].startswith('131:GATEWAY:'))
            self.assertEqual(env['MD_ME_CLUSTER_ADDRESSES'], ','.join(f.m['nodes'][f'me{i}'] for i in range(3)))
            self.assertEqual(env['MD_ME_JOURNAL_ARCHIVES'].split(',')[1], f.m['nodes']['me1'] + ':9110')
            self.assertEqual(env['MD_PG_USER'], 'oe_marketdata_writer')
            self.assertTrue(env['MD_PG_URL'].endswith('/oe_marketdata'))
            self.assertEqual(env['MD_EXPECTED_MARKETS'], '1,2,3,4,5')
            self.assertEqual(env['MD_PUBLIC_BIND'], '172.30.99.46:8110')
            self.assertNotIn('MD_DRIVER_TIMEOUT_MS', env)       # bounds and timeouts stay at the binary's defaults
            command = f.marketdata_command('md0')
            self.assertEqual('aeronmd' in command[-1], driver == 'external')
        self.assertEqual(f.ready_target('md0'), (8111, '/ready/session'))

    def test_the_order_history_databases_go_down_and_return(self):
        f = marketdata_fixture(self.dir)
        sql = []
        f.psql = lambda db, text: (sql.append((db, text)), '2' if 'pg_terminate_backend' in text else 'x')[1]
        f.record_fault = lambda w: w
        down = f.history_databases_down(True)
        self.assertEqual(down['kind'], 'history_databases_down')
        self.assertEqual(down['backends_ended'], 2)
        self.assertIn(('postgres', 'ALTER DATABASE r01_gateway ALLOW_CONNECTIONS false'), sql)
        self.assertIn(('postgres', 'ALTER DATABASE r01_history_b ALLOW_CONNECTIONS false'), sql)
        self.assertFalse(any('r01_money' in s or 'oe_marketdata' in s for _, s in sql))
        sql.clear()
        self.assertEqual(f.history_databases_down(False)['kind'], 'history_databases_up')
        self.assertIn(('postgres', 'ALTER DATABASE r01_gateway ALLOW_CONNECTIONS true'), sql)
        self.assertFalse(any('pg_terminate_backend' in s for _, s in sql))

    def test_faucet_caps_are_the_drills_when_named(self):
        f = marketdata_fixture(self.dir)
        self.assertEqual(f.faucet_caps(), f.GATEWAY_FAUCET_CAPS)
        f.gateway_faucet_caps = dict(sc.FAUCET_CAPS)
        self.assertEqual(f.faucet_caps(), sc.FAUCET_CAPS)
        self.assertEqual(f.registry['gateway_faucet_caps']['0'], '1000')
        self.assertIn('0:1000', f.gateway_slot_env('gw0')['GATEWAY_FAUCET_MAX_AMOUNT'])


class MarketDataCutTest(unittest.TestCase):
    """The checker on the market-data artifact: the cut's gateway commit, a product build tree, rig kinds only."""

    def setUp(self):
        import test_mk_manifests
        self.builder = test_mk_manifests.CutManifestBuilderTest('test_every_s17_kind_builds_validates_and_passes_the_checker')
        self.builder.setUp()
        self.addCleanup(self.builder.tearDown)

    def check(self, m):
        import release_cut
        return [rule + ' ' + text for rule, text in
                release_cut.check(m, self.builder.world.m, 'rig', old_pins=self.builder.world.pins).items]

    def test_a_build_of_the_cut_s_gateway_commit_is_accepted_and_others_refused(self):
        for kind in sorted(core_contracts.MARKETDATA_KINDS):
            _, m = self.builder.built(kind)
            self.assertEqual(m['artifacts']['marketdata']['source_sha'], self.builder.world.m['repos']['gateway'])
            self.assertEqual(m['nodes']['md0'][-3:], '.46')
            self.assertEqual(self.check(m), [], kind)
            fwd = (m['slot_artifacts']['fwd0'], m['slot_artifacts']['fwd1'])
            self.assertEqual(fwd, (None, None) if 'nofwd' in kind else ('forwarder', 'forwarder'))
        _, m = self.builder.built('cps')
        root = self.builder.root
        other = root / 'other/bin/oe-marketdata'; other.parent.mkdir(parents=True); other.write_bytes(b'ELF oe-marketdata of another commit')
        import hashlib
        bad = copy.deepcopy(m)
        bad['artifacts']['marketdata'].update(path=str(other), sha256=hashlib.sha256(other.read_bytes()).hexdigest())
        self.assertTrue(any('is not a build of the cut\'s gateway' in t for t in self.check(bad)))
        (root / 'gw/CMakeCache.txt').write_text('CMAKE_CXX_FLAGS:STRING=-DMD_NC_COMMIT_SPLIT\n')
        self.assertTrue(any(t.startswith('K3') and 'control define' in t for t in self.check(m)))
        import release_cut
        refused = release_cut.check(m, self.builder.world.m, 'product', old_pins=self.builder.world.pins).items
        self.assertTrue(any('not an artifact of cut' in text for _, text in refused))


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_the_scenarios_are_known_to_the_runner_and_the_night(self):
        for name in sc.SCENARIOS:
            self.assertTrue(sc.is_scenario(name))
            self.assertTrue(nightly.scenario_known(name))
        self.assertFalse(nightly.scenario_known('core-control-smoke-other'))
        plan = nightly.parse_plan([{'kind': 'cps', 'scenario': 'critical-path-smoke-core'},
                                   {'kind': 'cps-nofwd-ext', 'scenario': 'core-control-smoke-nomatch'}])
        self.assertEqual(len(plan), 2)

    def test_check_scenario(self):
        m = marketdata_manifest(self.dir)
        for name in sc.SCENARIOS:
            self.assertIsNone(sc.check_scenario(m, name, {}))
        with self.assertRaisesRegex(Inconclusive, 'unknown critical-path scenario'):
            sc.check_scenario(m, 'critical-path-smoke', {})
        nofwd = dict(copy.deepcopy(m), manifest_kind='cps-nofwd')
        nofwd['slot_artifacts'].update(fwd0=None, fwd1=None)
        self.assertIsNone(sc.check_scenario(nofwd, 'core-control-smoke-nomatch', {}))
        with self.assertRaisesRegex(Inconclusive, 'needs the forwarders'):
            sc.check_scenario(nofwd, 'critical-path-smoke-core', {})
        pj = projection_manifest(self.dir, slots={'pj0': 'history_projector', 'pj1': 'history_projector'})
        with self.assertRaisesRegex(Inconclusive, 'runs on a critical-path kind'):
            sc.check_scenario(dict(pj, manifest_kind='pj'), 'critical-path-smoke-core', {})
        stubbed = copy.deepcopy(m); stubbed['slot_artifacts']['gw0'] = 'gateway_stub'
        with self.assertRaisesRegex(Inconclusive, 'product binaries'):
            sc.check_scenario(stubbed, 'critical-path-smoke-core', {})

    def test_controls(self):
        m = marketdata_manifest(self.dir)
        self.assertEqual(sc.check_scenario(m, 'critical-path-smoke-core', {'CPS_CONTROL': 'skip-withdraw'}),
                         ('skip-withdraw', 'smoke workload incomplete: withdraw', False))
        self.assertEqual(sc.check_scenario(m, 'core-history-loss', {'CPS_CONTROL': 'never-down'})[2], True)
        with self.assertRaisesRegex(Inconclusive, 'is a control of core-gate-brake'):
            sc.check_scenario(m, 'critical-path-smoke-core', {'CPS_CONTROL': 'skip-gate'})
        with self.assertRaisesRegex(Violation, 'CPS_CONTROL is one of'):
            sc.check_scenario(m, 'critical-path-smoke-core', {'CPS_CONTROL': 'nope'})
        dropone = dict(copy.deepcopy(m), manifest_kind='cps-nc-dropone')
        self.assertEqual(sc.check_scenario(dropone, 'critical-path-smoke-core', {})[1], sc.HISTORY_MISSING_TEXT)
        with self.assertRaisesRegex(Inconclusive, 'is the control of critical-path-smoke-core'):
            sc.check_scenario(dropone, 'core-gate-brake', {})
        with self.assertRaisesRegex(Inconclusive, 'one control a run'):
            sc.check_scenario(dropone, 'critical-path-smoke-core', {'CPS_CONTROL': 'skip-withdraw'})
        texts = {text for _, text, _ in sc.CONTROLS.values()}
        self.assertIn("request log differs from the core's decided set", texts)
        self.assertIn('history fault surfaced with the wrong code', texts)

    def test_settings(self):
        self.assertEqual(sc.settings({})['SMOKE_PAIRS'], 12)
        self.assertEqual(sc.settings({'SMOKE_PAIRS': '3'})['SMOKE_PAIRS'], 3)
        with self.assertRaisesRegex(Violation, 'positive integer'):
            sc.settings({'GATE_CYCLES': '0'})


class VerdictTest(unittest.TestCase):
    def test_drill_runs(self):
        ok, bad = sc.line(True, {}), sc.line(False, {}, 'x')
        self.assertEqual(sc.verdict({'a': ok}), ('PASS', None))
        self.assertEqual(sc.verdict({'a': ok, 'b': bad})[0], 'FAIL')
        self.assertEqual(sc.verdict({'a': bad, 'b': sc.line(False, {}, 'y', inconclusive=True)})[0], 'INCONCLUSIVE')
        # a consequence of a failing line is listed, not judged
        lines = {'a': sc.line(False, {}, 'x'), 'b': sc.consequence(sc.line(False, {}, 'y', inconclusive=True), 'a')}
        self.assertEqual(sc.verdict(lines)[0], 'FAIL')
        self.assertEqual(set(sc.judged(lines)), {'a'})

    def test_control_runs_fail_on_their_own_text_only(self):
        control = ('md-off', sc.NO_TRADE_TEXT, False)
        lines = {'tape': sc.line(False, {}, sc.NO_TRADE_TEXT + ' 7'), 'md': sc.line(False, {}, sc.NO_TRADE_TEXT + ' 7'),
                 'money': sc.line(True, {})}
        status, block = sc.verdict(lines, control)
        self.assertEqual(status, 'PASS')
        self.assertTrue(block['held'])
        lines['other'] = sc.line(False, {}, 'something else')
        status, block = sc.verdict(lines, control)
        self.assertEqual(status, 'FAIL')
        self.assertEqual(block['other_failures'], {'other': 'something else'})
        self.assertEqual(sc.verdict({'m': sc.line(True, {})}, control)[0], 'FAIL')        # the rule never failed
        self.assertFalse(sc.text_matches(sc.NO_TRADE_TEXT + 'x', sc.NO_TRADE_TEXT))
        never = ('never-down', 'history database was never down', True)
        self.assertEqual(sc.verdict({'o': sc.line(False, {}, never[1], inconclusive=True)}, never)[0], 'INCONCLUSIVE')


class OracleRowsTest(unittest.TestCase):
    def test_creates_amends_cancels_and_funding(self):
        body = gateway_probe.order_body(1, 'BUY', 'LIMIT', 'GTC', 90 * FP, 10 * sc.UNIT)
        log = [call('POST', '/api/v2/orders', 201, {'orderId': '5', 'status': 'NEW'}, key=KEY1, body=body),
               call('POST', '/api/v2/orders', 422, {'code': 'REJECTED', 'reason': 'INSUFFICIENT_FUNDS'}, user=C, key=KEY2, body=body, sent=3)]
        gate = call('POST', '/api/v2/orders', 503, {'code': 'ADMISSION_CLOSED'}, key='33333333-2222-4333-8444-555555555555',
                    body=body, sent=5)
        settled = dict(gate, status=201, reply={'orderId': '9', 'status': 'NEW'}, sent_ns=9,
                       attempts=[{'status': 201, 'reply': {'orderId': '9'}, 'sent_ns': 9, 'recv_ns': 10}])
        log += [gate, settled]
        creates = sc.oracle_creates(log)
        self.assertEqual([c['reply']['outcome'] for c in creates], ['ACK', 'REJECT', 'ACK'])
        self.assertEqual(creates[2]['reply']['order'], 9)            # the gate's 503 was not a decision
        log += [call('PUT', '/api/v2/orders/5', 200, {'orderId': '5', 'status': 'PENDING_REPLACE'}, key=KEY1,
                     body={'price': '91'}),
                call('PUT', '/api/v2/orders/5', 503, {'code': 'ADMISSION_CLOSED'}, key=KEY2, body={'price': '81'})]
        amends = sc.oracle_amends(log)
        self.assertEqual(amends[0]['new_price'], 91 * FP)
        self.assertEqual([a['reply']['outcome'] for a in amends], ['ACK', 'REJECT'])
        self.assertEqual(amends[1]['reply']['reason'], 'GATE_CLOSED')
        log += [call('DELETE', '/api/v2/orders/5', 200, {'orderId': '5', 'status': 'PENDING_CANCEL'}, key=KEY1),
                call('POST', '/api/v2/orders/cancel', 200, {'results': [{'orderId': '9', 'state': 'CANCEL_PENDING'},
                                                                        {'orderId': '4', 'state': 'NOT_OPEN'}],
                                                            'requested': 2, 'accepted': 1}, body={'all': True})]
        cancels = sc.oracle_cancels(log)
        self.assertEqual([(c['order'], c['reply']['outcome']) for c in cancels], [(5, 'ACK'), (9, 'ACK'), (4, 'REJECT')])
        self.assertEqual(cancels[1]['request'], [0, 0])
        log += [call('POST', '/api/v2/balances/deposit', 200, {}, key=KEY1, body={'assetId': '0', 'amount': '1000'}, gate='OPEN'),
                call('POST', '/api/v2/balances/withdraw', 422, {'reason': 'INSUFFICIENT_FUNDS'}, user=C, key=KEY2,
                     body={'assetId': '2', 'amount': '1'}, gate='SUSPENDED'),
                call('POST', '/api/v2/balances/withdraw', 504, None, key=KEY2, body={'assetId': '0', 'amount': '1'})]
        funding = sc.oracle_funding(log)
        self.assertEqual([(f['kind'], f['outcome'], f['amount'], f['gate']) for f in funding],
                         [('deposit', 'ACK', 1000 * FP, 'OPEN'), ('withdraw', 'REJECT', FP, 'SUSPENDED'),
                          ('withdraw', 'UNKNOWN', FP, None)])
        return log

    def test_request_log_against_the_core(self):
        log = self.test_creates_amends_cancels_and_funding()
        sample = {'dispatch_tap': [{'user': A, 'order': 5, 'kind': 'CREATE'}, {'user': A, 'order': 9, 'kind': 'CREATE'},
                                   {'user': A, 'order': 5, 'kind': 'AMEND'}, {'user': A, 'order': 5, 'kind': 'CANCEL'},
                                   {'user': A, 'order': 9, 'kind': 'CANCEL'}, {'user': 4242, 'order': 77, 'kind': 'CREATE'}],
                  'money_journal': [{'kind': 'deposit', 'user': A, 'asset': 0, 'amount': 1000 * FP},
                                    {'kind': 'settle', 'trade': 1}]}
        self.assertTrue(sc.request_log_line(log, sample, [A, B, C])['holds'])
        dropped = [r for r in log if r['path'] != '/api/v2/balances/deposit']
        out = sc.request_log_line(dropped, sample, [A, B, C])
        self.assertFalse(out['holds'])
        self.assertEqual(out['text'], sc.REQUEST_LOG_TEXT)
        self.assertIn('funding', out['detail']['differences'])
        extra = dict(sample, dispatch_tap=sample['dispatch_tap'] + [{'user': A, 'order': 5, 'kind': 'AMEND'}])
        self.assertIn('amends', sc.request_log_line(log, extra, [A, B, C])['detail']['differences'])


def ev(seq, order, status, filled=0, quantity=50, kind='UPDATE', trade=0):
    return {'seq': seq, 'order': order, 'status': status, 'filled': filled, 'quantity': quantity, 'kind': kind, 'trade': trade}


class WorkloadAndHistoryTest(unittest.TestCase):
    def work(self):
        return {'fund': [call('POST', '/api/v2/balances/deposit', 200)],
                'pairs': [call('POST', '/api/v2/orders', 201)],
                'amend': call('PUT', '/api/v2/orders/5', 200), 'cancel': call('DELETE', '/api/v2/orders/5', 200),
                'cancel_all': [call('POST', '/api/v2/orders/cancel', 200, {'accepted': 1})],
                'refused': call('POST', '/api/v2/orders', 422, {'code': 'REJECTED', 'reason': 'INSUFFICIENT_FUNDS'}),
                'replay': [call('POST', '/api/v2/orders', 201, {'orderId': '8'}),
                           call('POST', '/api/v2/orders', 200, {'orderId': '8', 'duplicate': True})],
                'withdraw': [call('POST', '/api/v2/balances/withdraw', 200),
                             call('POST', '/api/v2/balances/withdraw', 422, {'reason': 'INSUFFICIENT_FUNDS'})]}

    def test_workload_lines(self):
        sample = {'core_events': [ev(1, 5, 'NEW'), ev(2, 5, 'PARTIALLY_FILLED', 20), ev(3, 5, 'CANCELLED', 20)]}
        lines = sc.workload_lines([], sample, self.work(), 5)
        self.assertTrue(all(v['holds'] for v in lines.values()), {k: v for k, v in lines.items() if not v['holds']})
        work = self.work(); work.pop('withdraw')
        self.assertEqual(sc.workload_lines([], sample, work, 5)['workload_withdraw']['text'], 'smoke workload incomplete: withdraw')
        no_partial = {'core_events': [ev(1, 5, 'NEW'), ev(3, 5, 'CANCELLED')]}
        self.assertEqual(sc.workload_lines([], no_partial, self.work(), 5)['workload_partial_fill']['text'],
                         'smoke workload incomplete: partial fill')

    def test_history_line(self):
        sample = {'core_events': [ev(1, 5, 'NEW'), ev(2, 5, 'PARTIALLY_FILLED', 20, kind='FILL', trade=3),
                                  ev(4, 5, 'CANCELLED', 20), ev(3, 6, 'FILLED', 20, 20, kind='FILL', trade=3)]}
        rows = {5: {'status': 'CANCELLED', 'filledQuantity': '0.0000002'}, 6: {'status': 'FILLED', 'filledQuantity': '0.0000002'}}
        trails = {5: [1, 2, 4], 6: [3]}
        fills = {(3, 5), (3, 6)}
        self.assertTrue(sc.history_line(sample, {5, 6}, rows, trails, fills)['holds'])
        out = sc.history_line(sample, {5, 6}, rows, {5: [1, 4], 6: [3]}, fills)
        self.assertEqual(out['text'], sc.HISTORY_MISSING_TEXT)
        self.assertEqual(sc.history_line(sample, {5, 6}, rows, trails, {(3, 6)})['text'], sc.HISTORY_MISSING_TEXT)
        out = sc.history_line(sample, {5, 6}, {**rows, 5: {'status': 'NEW', 'filledQuantity': '0'}}, trails, fills)
        self.assertEqual(out['text'], 'history differs from the core: status')
        self.assertTrue(sc.history_line({'core_events': []}, set(), {}, {}, set())['inconclusive'])

    def test_stream_line(self):
        sample = {'core_events': [ev(1, 5, 'NEW'), ev(2, 5, 'FILLED', 50, kind='FILL', trade=3)]}
        frames = {A: [{'frame': {'type': 'order', 'order': {'orderId': '5', 'status': 'NEW'}}},
                      {'frame': {'type': 'fill', 'fill': {'tradeId': '3', 'orderId': '5'}}},
                      {'frame': {'type': 'order', 'order': {'orderId': '5', 'status': 'FILLED'}}}]}
        self.assertTrue(sc.stream_line(sample, {A: {5}}, frames)['holds'])
        self.assertFalse(sc.stream_line(sample, {A: {5}}, {A: frames[A][:2]})['holds'])
        self.assertFalse(sc.stream_line(sample, {A: {5}}, {A: [frames[A][0], frames[A][2]]})['holds'])


def tape_frame(*trades, market=1):
    return {'recv_ns': 5, 'frame': {'type': 'TRADES_BATCH', 'marketId': market,
                                    'trades': [{'tradeId': str(t), 'price': '90', 'quantity': '0.01', 'tradeCount': 1,
                                                'side': 'BUY', 'timestamp': 1} for t in trades]}}


JOURNAL = [{'type': 'trade', 'trade_id': t, 'market': 1, 'price': 90 * FP, 'quantity': FP // 100, 'taker_is_buy': True}
           for t in (1, 2)]


class MarketDataLinesTest(unittest.TestCase):
    def test_tape_against_the_journal(self):
        self.assertTrue(sc.public_trades_line(JOURNAL, sc.tape_of([tape_frame(1), tape_frame(2)]), 'tape')['holds'])
        out = sc.public_trades_line(JOURNAL, sc.tape_of([tape_frame(1)]), 'tape')
        self.assertEqual(out['text'], sc.NO_TRADE_TEXT + ' 2')
        out = sc.public_trades_line(JOURNAL, sc.tape_of([tape_frame(1, 2, 1)]), 'tape')
        self.assertEqual(out['text'], sc.EXTRA_TRADE_TEXT)
        frames, planted = sc.plant_extra_trade([tape_frame(1, 2)])
        self.assertEqual(planted, str(10 ** 12 + 1))
        self.assertEqual(sc.public_trades_line(JOURNAL, sc.tape_of(frames), 'tape')['text'], sc.EXTRA_TRADE_TEXT)
        sold = [dict(JOURNAL[0], taker_is_buy=False), JOURNAL[1]]
        self.assertEqual(sc.public_trades_line(sold, sc.tape_of([tape_frame(1, 2)]), 'tape')['text'],
                         'public tape differs from the journal: price, quantity or side')
        self.assertEqual(sc.public_trades_line(JOURNAL, [], 'md_trades')['text'], sc.NO_TRADE_TEXT + ' 1')
        self.assertTrue(sc.public_trades_line([], [], 'tape')['inconclusive'])

    def test_book_line(self):
        snap = {'recv_ns': 10, 'frame': {'type': 'BOOK_SNAPSHOT', 'marketId': 1, 'bids': [],
                                         'asks': [{'price': '96', 'quantity': '0.03', 'orderCount': 1}]}}
        gone = {'recv_ns': 30, 'frame': {'type': 'BOOK_DELTA', 'changes': [{'price': '96', 'quantity': '0', 'orderCount': 0,
                                                                          'side': 'ASK', 'updateType': 'DELETE_LEVEL'}]}}
        self.assertTrue(sc.book_line([snap, gone], 96 * FP, 3 * FP // 100, 5, 20)['holds'])
        self.assertFalse(sc.book_line([snap], 96 * FP, 3 * FP // 100, 5, 20)['holds'])           # never gone
        self.assertFalse(sc.book_line([snap, gone], 96 * FP, 3 * FP // 100, 15, 20)['holds'])    # shown before the window
        self.assertTrue(sc.book_line([], 96 * FP, 1, 0, 1)['inconclusive'])


class GateAndHistoryLossTest(unittest.TestCase):
    def cycle(self, n, ready=503):
        under = [call('POST', '/api/v2/orders', 503, {'code': 'ADMISSION_CLOSED'}, tag='gate-create'),
                 call('PUT', '/api/v2/orders/1', 503, {'code': 'ADMISSION_CLOSED'}, tag='gate-amend'),
                 call('DELETE', '/api/v2/orders/2', 200, tag='gate-cancel'),
                 call('GET', '/api/v2/balances', 200, tag='gate-balances')]
        return {'cycle': n, 'under': under, 'after': [call('POST', '/api/v2/orders', 201)],
                'ready': {'status': ready, 'body': '{"ready":false,"failing":["gate_open"]}'},
                'ready_session': {'status': 200}, 'in_flight': [10 + n, 20 + n]}

    def sample(self, cycles):
        admission = [{'market': 0, 'state': 'SUSPENDED', 'reason': 'GENESIS'}, {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN'}]
        for _ in range(cycles):
            admission += [{'market': 0, 'state': 'SUSPENDED', 'reason': 'ADMIN'}, {'market': 0, 'state': 'OPEN', 'reason': 'ADMIN'}]
        trades = [{'type': 'trade', 'trade_id': n, 'taker_order': 20 + n, 'maker_order': 10 + n} for n in (1, 2)]
        settles = [{'kind': 'settle', 'trade': n} for n in (1, 2)]
        return {'admission': admission, 'me_journal': trades, 'money_journal': settles}

    FUNDING = [{'kind': 'deposit', 'outcome': 'ACK', 'gate': 'SUSPENDED'}, {'kind': 'withdraw', 'outcome': 'ACK', 'gate': 'SUSPENDED'}]

    def test_gate_lines(self):
        self.assertEqual(sc.gate_cycles(self.sample(2)['admission']), 2)
        lines = sc.gate_lines([self.cycle(1), self.cycle(2)], self.sample(2), self.FUNDING)
        self.assertTrue(all(v['holds'] for v in lines.values()), lines)
        lines = sc.gate_lines([self.cycle(1)], self.sample(1), self.FUNDING)
        self.assertEqual(sc.verdict(lines, ('one-cycle', 'gate cycle ran once', False))[0], 'PASS')
        lines = sc.gate_lines([self.cycle(1), self.cycle(2)], self.sample(0), self.FUNDING)
        self.assertEqual(sc.verdict(lines, ('skip-gate', 'gate was never SUSPENDED', False))[0], 'PASS')
        open_funding = [dict(r, gate='OPEN') for r in self.FUNDING]
        lines = sc.gate_lines([self.cycle(1), self.cycle(2)], self.sample(2), open_funding)
        self.assertEqual(sc.verdict(lines, ('funding-before-gate', 'no deposit or withdrawal was sent under a suspended gate',
                                            False))[0], 'PASS')
        lines = sc.gate_lines([self.cycle(1), self.cycle(2, ready=200)], self.sample(2), self.FUNDING)
        self.assertEqual(lines['gate_rules']['text'], 'gate rule broken under SUSPENDED')
        unsettled = dict(self.sample(2), money_journal=[{'kind': 'settle', 'trade': 1}])
        self.assertFalse(sc.gate_lines([self.cycle(1), self.cycle(2)], unsettled, self.FUNDING)['in_flight_fill_settled']['holds'])

    def outage(self, n, status=503):
        return {'cycle': n, 'pairs': [100 + n, 200 + n],
                'reads': [call('GET', '/api/v2/orders/history', status, {'code': 'HISTORY_UNAVAILABLE'})],
                'catchup': {'caught_up': True, 'waited_s': 1.0}}

    def test_history_loss_lines(self):
        sample = {'me_journal': [{'type': 'trade', 'taker_order': 200 + n, 'maker_order': 100 + n} for n in (1, 2)]}
        two = [self.outage(1), self.outage(2)]
        lines = sc.history_loss_lines(two, two, sample, 60)
        self.assertTrue(all(v['holds'] for v in lines.values()), lines)
        self.assertEqual(sc.verdict(sc.history_loss_lines([], [], sample, 60),
                                    ('never-down', 'history database was never down', True))[0], 'INCONCLUSIVE')
        self.assertEqual(sc.verdict(sc.history_loss_lines(two[:1], two[:1], sample, 60),
                                    ('one-stop', 'history loss ran once', False))[0], 'PASS')
        wrong = [self.outage(1, 500), self.outage(2, 500)]
        self.assertEqual(sc.verdict(sc.history_loss_lines(two, wrong, sample, 60),
                                    ('history-500', 'history fault surfaced with the wrong code', False))[0], 'PASS')
        late = [self.outage(1), dict(self.outage(2), catchup={'caught_up': False, 'head': 9, 'applied': 3})]
        self.assertEqual(sc.history_loss_lines(late, late, sample, 60)['history_catchup']['text'],
                         'history did not catch up after the return')
        stuck = {'me_journal': sample['me_journal'][:1]}
        self.assertFalse(sc.history_loss_lines(two, two, stuck, 60)['money_path_during_outage']['holds'])


class ClientAndHoldTest(unittest.TestCase):
    def test_calls_retry_a_keyed_call_with_its_key_until_decided(self):
        answers = iter([(503, {'code': 'ADMISSION_CLOSED'}, None), (429, None, None), (201, {'orderId': '4'}, None)])
        sent = []
        def sender(method, target, path, headers, body, timeout):
            sent.append(headers.get('Idempotency-Key'))
            return next(answers)
        clock = iter(range(0, 1000))
        rows = gateway_probe.calls({'target': 'h:1', 'calls': [{'user': 1, 'method': 'POST', 'path': '/api/v2/orders',
                                                                 'key': KEY1, 'body': {}}], 'bound_s': 100},
                                   {'1': 'k'}, None, clock=lambda: next(clock), sleep=lambda s: None, sender=sender)
        self.assertEqual(sent, [KEY1] * 3)
        self.assertEqual(rows[0]['status'], 201)
        self.assertEqual([a['status'] for a in rows[0]['attempts']], [503, 429, 201])
        once = gateway_probe.calls({'target': 'h:1', 'calls': [{'user': 1, 'method': 'POST', 'path': '/x', 'key': KEY1,
                                                                 'retry': False}]}, {'1': 'k'}, None,
                                   sender=lambda *a: (503, None, None))
        self.assertEqual(len(once[0]['attempts']), 1)

    def test_hold_point(self):
        self.assertIsNone(runner.hold_seconds({}))
        self.assertEqual(runner.hold_seconds({'RUNNER_HOLD_AFTER_S': '30'}), 30)
        with self.assertRaisesRegex(Violation, 'positive integer'):
            runner.hold_seconds({'RUNNER_HOLD_AFTER_S': '-1'})
        with tempfile.TemporaryDirectory() as d:
            f = mock.Mock(run_id='rc2-x', root=Path(d), registry={'containers': {'ae0': 'c'}}, gateway='172.30.1.1',
                          m={'network': {'subnet': '172.30.1.0/24'}, 'postgres_port': 5})
            ticks = iter(range(100))
            def sleep(_):
                if next(ticks) == 2:
                    (Path(d) / 'hold.release').write_text('go')
            out = runner.hold_point(f, d, 'PASS', 60, clock=lambda: 0, sleep=sleep)
            self.assertEqual(out['released_by'], 'file')
            ready = json.loads((Path(d) / 'hold.ready').read_text())
            self.assertEqual(ready['containers'], {'ae0': 'c'})
            self.assertEqual(ready['status'], 'PASS')
            (Path(d) / 'hold.release').unlink()
            t = iter([0, 0, 61, 61, 61])
            self.assertEqual(runner.hold_point(f, d, 'FAIL', 60, clock=lambda: next(t), sleep=lambda s: None)['released_by'], 'bound')
        with self.assertRaisesRegex(Violation, 'never holds a fixture up'):
            nightly.settings_from_env({'RUNNER_HOLD_AFTER_S': '10'})


if __name__ == '__main__':
    unittest.main()
