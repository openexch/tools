# SPDX-License-Identifier: Apache-2.0
"""The gateway drills' pure parts: the stream client's order view, the oracle rows rebuilt from gateway answers, the
lines of the stored-acceptance, cancel, fill, tick, convergence and slow-close rules, the fuzz cases, the load's pacing,
the probe's pair timing and handshake, and the fixture's SIGSTOP of a slot's pid 1 (no Docker)."""
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
import unittest.mock

from contracts import FP, Inconclusive
import gateway_probe
import gateway_scenarios as gs
from gateway_shim import request_id

KEY = '6f1c2a3b-4d5e-4f60-8a7b-8c9d0e1f2a3b'


class OrderViewTest(unittest.TestCase):
    def test_snapshot_events_and_resync(self):
        v = gateway_probe.OrderView()
        v.apply({'type': 'order', 'eventSeq': 1, 'order': {'orderId': '9', 'status': 'NEW'}}, 1)
        self.assertEqual(v.final()['open'], [])                 # before the first snapshot nothing is applied
        v.apply({'type': 'snapshot', 'channel': 'orders', 'orders': [{'orderId': '5', 'status': 'NEW'}]}, 2)
        v.apply({'type': 'order', 'eventSeq': 3, 'order': {'orderId': '7', 'status': 'PENDING_NEW'}}, 3)
        v.apply({'type': 'order', 'eventSeq': 4, 'order': {'orderId': '5', 'status': 'FILLED'}}, 4)
        v.apply({'type': 'fill', 'eventSeq': 5, 'fill': {'orderId': '5'}}, 5)
        self.assertEqual(v.final()['open'], ['7'])
        self.assertEqual(v.fills, {'5': [5]})
        self.assertEqual(v.last_seq, 5)
        v.apply({'type': 'resync', 'reason': 'RESUME_TOO_OLD'}, 6)
        v.apply({'type': 'order', 'eventSeq': 6, 'order': {'orderId': '8', 'status': 'NEW'}}, 7)
        self.assertEqual(v.final()['open'], ['7'])
        self.assertTrue(v.final()['awaiting_snapshot'])

    def test_stream_diffs(self):
        views = [{'user': 1, 'target': 's', 'open': ['1', '2'], 'awaiting_snapshot': False},
                 {'user': 2, 'target': 's', 'open': ['3'], 'awaiting_snapshot': False}]
        self.assertEqual(gs.stream_diffs(views, {1: {'1', '2'}, 2: {'3'}}), [])
        diff = gs.stream_diffs(views, {1: {'1'}, 2: {'3', '4'}})
        self.assertEqual([(d['user'], d['missing'], d['extra']) for d in diff], [(1, [], ['2']), (2, ['4'], [])])


class OracleRowsTest(unittest.TestCase):
    body = {'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC', 'price': '50', 'quantity': '0.001'}

    def req(self, status, reply, t):
        return {'method': 'POST', 'path': '/api/v2/orders', 'user': 7, 'key': KEY, 'body': self.body, 'status': status,
                'reply': reply, 'sent_ns': t, 'recv_ns': t + 1}

    def test_first_2xx_decides_and_a_duplicate_is_a_replay(self):
        ok = {'orderId': '11', 'duplicate': True, 'status': 'PENDING_NEW', 'hold': {'assetId': '0', 'amount': '0.05'}}
        rows = gs.creates_from([self.req(0, None, 1), self.req(200, ok, 2), self.req(200, ok, 3)])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r['request'], list(request_id(KEY)))
        self.assertEqual((r['price'], r['quantity']), (50 * FP, FP // 1000))
        self.assertEqual(r['reply'], {'outcome': 'ACK', 'order': 11, 'duplicate': False, 'hold_asset': 0,
                                      'hold_amount': 5_000_000, 'status': 'PENDING_NEW', 'source': 'replay'})

    def test_reject_and_unknown(self):
        rej = gs.creates_from([self.req(422, {'code': 'REJECTED', 'reason': 'INSUFFICIENT_FUNDS'}, 1)])[0]['reply']
        self.assertEqual((rej['outcome'], rej['reason']), ('REJECT', 'INSUFFICIENT_FUNDS'))
        self.assertEqual(gs.creates_from([self.req(504, {}, 1), self.req(0, None, 2)])[0]['reply'], {'outcome': 'UNKNOWN'})

    def test_cancels(self):
        rows = gs.cancels_from([{'method': 'DELETE', 'path': '/api/v2/orders/42', 'user': 7, 'key': None, 'status': 200,
                                 'reply': {'reoffered': True, 'duplicate': True}, 'sent_ns': 1},
                                {'method': 'DELETE', 'path': '/api/v2/orders/43', 'user': 7, 'key': KEY, 'status': 404,
                                 'reply': {'reason': 'UNKNOWN_ORDER'}, 'sent_ns': 2}])
        self.assertEqual(rows[0]['request'], [0, 0])
        self.assertTrue(rows[0]['reply']['reoffered'])
        self.assertEqual(rows[1]['reply']['outcome'], 'REJECT')


class LinesTest(unittest.TestCase):
    def test_stored_acceptance(self):
        def r(tag, status, code=None):
            return {'tag': tag, 'status': status, 'reply': {'code': code} if code else {'orderId': '1'}}
        good = {'close': 'ANSWERED', 'log': [r('stored', 200), r('fresh', 503, 'ADMISSION_CLOSED')]}
        self.assertTrue(gs.stored_line(good)['holds'])
        bad = {'log': [r('stored', 503, 'ADMISSION_CLOSED'), r('fresh', 503, 'ADMISSION_CLOSED')]}
        self.assertEqual(gs.stored_line(bad)['text'], gs.STORED_TEXT)
        open_gate = {'log': [r('stored', 200), r('fresh', 201)]}
        self.assertTrue(gs.stored_line(open_gate).get('inconclusive'))      # no witness that the gate was closed

    def test_cancel_lines(self):
        log = [{'tag': 'cancel-resting', 'status': 200, 'reply': {'reoffered': True, 'status': 'NOT_OPEN', 'duplicate': True}},
               {'tag': 'cancel-stop', 'status': 200, 'reply': {}},
               {'tag': 'keyed-0', 'status': 200, 'reply': {'status': 'PENDING_CANCEL', 'duplicate': False}},
               {'tag': 'keyed-1', 'status': 200, 'reply': {'status': 'PENDING_CANCEL', 'duplicate': True}},
               {'tag': 'unknown', 'status': 404, 'reply': {'code': 'NOT_FOUND'}}]
        lines = gs.cancel_lines({'targets': [1, 2], 'requests': log})
        self.assertTrue(all(v['holds'] for v in lines.values()), lines)
        # a re-offer acked PENDING_CANCEL met no earlier effect: the rule was never exercised
        log[0]['reply'] = {'reoffered': True, 'status': 'PENDING_CANCEL', 'duplicate': False}
        self.assertTrue(gs.cancel_lines({'requests': log})['cancel_never_not_found'].get('inconclusive'))
        log[1] = {'tag': 'cancel-stop', 'status': 404, 'reply': {'code': 'NOT_FOUND'}}
        row = gs.cancel_lines({'requests': log})['cancel_never_not_found']
        self.assertEqual((row['holds'], row['text'], row.get('inconclusive')), (False, gs.CANCEL_TEXT, None))

    def test_percentiles(self):
        p = gs.percentiles(list(range(1, 101)))
        self.assertEqual((p['n'], p['min'], p['p50'], p['p99'], p['max']), (100, 1, 50, 99, 100))
        self.assertEqual(gs.percentiles([]), {'n': 0})


class ProbeTest(unittest.TestCase):
    def test_fuzz_cases_are_deterministic_and_cover_the_routes(self):
        a, b = gateway_probe.fuzz_cases(5, 200, '9'), gateway_probe.fuzz_cases(5, 200, '9')
        self.assertEqual(a, b)
        kinds = {c['kind'] for c in a}
        self.assertTrue({'nil_key', 'unknown_field', 'user_id', 'cancel', 'amend', 'deposit', 'unknown_asset', 'query'} <= kinds)
        unknown = [c for c in gateway_probe.fuzz_cases(5, 200, '9', unknown_asset=4242) if c['kind'] == 'unknown_asset']
        self.assertTrue(unknown)
        self.assertEqual({(c['path'], c['body']['assetId'], c['body']['amount']) for c in unknown},
                         {('/api/v2/balances/deposit', '4242', '1')})
        # the other deposit cases are malformed: none is a deposit the core could apply
        for c in a:
            if c['kind'] == 'deposit':
                body = c['body']
                self.assertTrue(not isinstance(body['amount'], str) or body['assetId'] == 'x' or body['amount'] == '0'
                                or set(body) - {'assetId', 'amount'}, body)

    def test_only_requests_the_core_decided_enter_the_oracle(self):
        log = [{'tag': 'fuzz-core', 'method': 'POST', 'status': 201, 'reply': {'orderId': '5'}},
               {'tag': 'fuzz-core', 'method': 'POST', 'status': 422, 'reply': {'code': 'REJECTED', 'reason': 'SIZE_TOO_LARGE'}},
               {'tag': 'fuzz-field', 'method': 'POST', 'status': 400, 'reply': {'code': 'VALIDATION'}},
               {'tag': 'fuzz-deposit', 'method': 'POST', 'status': 404, 'reply': {'code': 'FEATURE_DISABLED'}},
               {'tag': 'fuzz-unknown_asset', 'method': 'POST', 'status': 504, 'reply': {'code': 'OUTCOME_UNKNOWN'}},
               {'tag': 'fuzz-core', 'method': 'POST', 'status': 0, 'reply': None},
               {'tag': 'fuzz-core', 'method': 'POST', 'status': 429, 'reply': {'code': 'RATE_LIMITED'}}]
        self.assertEqual([r['status'] for r in gs.core_decided(log)], [201, 422, 504, 0])

    def test_driver_line_needs_the_same_running_driver_and_the_reattached_gateway(self):
        drv = {'container': 'abc', 'started_at': 'S1', 'restart_count': 0, 'running': True, 'state': 'S', 'comm': 'aeronmd'}
        good = {'killed': True, 'driver': {'before': dict(drv), 'while_down': dict(drv, state='R'), 'after_restart': dict(drv),
                                           'gw0_pid1': 'bin', 'restart_witness': {'reused': True},
                                           'gw0_health_driver': {'mode': 'external', 'connected': True,
                                                                 'dir': '/dev/shm/aeron-gw0'}}}
        self.assertTrue(gs.driver_line(good)['holds'])
        import copy
        for path, value in ((('while_down', 'running'), False), (('while_down', 'state'), 'T'),
                            (('after_restart', 'started_at'), 'S2'), (('after_restart', 'restart_count'), 1),
                            (('while_down', 'comm'), 'sh'), (('before', 'comm'), None)):
            bad = copy.deepcopy(good); bad['driver'][path[0]][path[1]] = value
            row = gs.driver_line(bad)
            self.assertEqual((row['holds'], row.get('text')), (False, 'gw0 driver did not survive the gateway kill or was not reused'))
        bad = copy.deepcopy(good); bad['driver']['gw0_health_driver']['connected'] = False
        self.assertFalse(gs.driver_line(bad)['holds'])
        bad = copy.deepcopy(good); bad['driver']['gw0_pid1'] = 'aeronmd'
        self.assertFalse(gs.driver_line(bad)['holds'])
        bad = copy.deepcopy(good); bad['driver']['restart_witness'] = None
        self.assertFalse(gs.driver_line(bad)['holds'])
        self.assertTrue(gs.driver_line({'killed': False})['inconclusive'])

    def test_load_paces_attempts(self):
        now = [0.0]
        slept = []
        load = gateway_probe.Load([], ['t'], {}, '/dev/null', rate=4, clock=lambda: now[0], sleep=slept.append)
        for _ in range(3):
            load.pace()
        self.assertEqual(slept, [0.25, 0.5])

    def test_order_body(self):
        self.assertEqual(gateway_probe.order_body(1, 'BUY', 'STOP_LOSS', 'GTC', quantity=FP, stop_price=93 * FP),
                         {'marketId': '1', 'side': 'BUY', 'type': 'STOP_LOSS', 'timeInForce': 'GTC', 'quantity': '1',
                          'stopPrice': '93'})


class FreezeMainTest(unittest.TestCase):
    """The session-timeout freeze stops only the slot's pid 1 (oe-gateway), so an external slot's driver (pid 1 of its
    sidecar) keeps running."""

    def setUp(self):
        from test_core_fixture import Docker
        from test_gateway_fixture import gateway_fixture
        self.temp = tempfile.TemporaryDirectory()
        self.f = gateway_fixture(self.temp.name, 'external')
        self.f.registry.update(fault_targets={}, faults=[])
        self.docker = Docker(self.f, ['gw0', 'gw1', 'st0', 'st1', 'gw0-driver'])
        self.docker.exec_stdout = lambda argv: 'main T\n' if self.docker.state['c-gw0'].get('Stopped') else 'main S\n'
        execute = self.f.execute
        self.f.execute = lambda name, argv, **kw: (types.SimpleNamespace(stdout='S\n6 1.0\n', stderr='', returncode=0)
                                                   if name == 'gw0-driver' else execute(name, argv, **kw))

    def tearDown(self):
        self.temp.cleanup()

    def test_sigstop_of_pid_1_leaves_the_driver_running(self):
        witness = self.f.freeze_main('gw0', duration_s=20)
        self.assertEqual(self.docker.calls[-1], ['docker', 'kill', '--signal=STOP', 'c-gw0'])
        self.assertNotIn(['docker', 'pause', 'c-gw0'], self.docker.calls)
        self.assertEqual((witness['kind'], witness['main_state'], witness['driver_state']), ('sigstop', 'T', 'S'))
        self.assertEqual(self.f.process_states('gw0')['driver_sidecar'], 'c-gw0-driver')
        self.assertTrue(self.docker.state['c-gw0']['Running'])
        self.assertIn('gw0', self.f.registry['fault_targets'])
        thawed = self.f.thaw_main('gw0')
        self.assertEqual(self.docker.calls[-1], ['docker', 'kill', '--signal=CONT', 'c-gw0'])
        self.assertEqual((thawed['kind'], thawed['main_state']), ('sigcont', 'S'))

    def test_an_unobserved_stop_is_inconclusive(self):
        self.docker.exec_stdout = lambda argv: 'main S\n'
        with self.assertRaisesRegex(Inconclusive, 'SIGSTOP of gw0 pid 1 was not observed'):
            self.f.freeze_main('gw0')

    def test_the_drill_freezes_with_sigstop_never_docker_pause(self):
        calls = []
        f = types.SimpleNamespace(freeze_main=lambda *a, **k: calls.append(('freeze_main', a, k)) or {'driver_state': 'S'},
                                  pause=lambda *a, **k: calls.append(('pause', a, k)))
        drill = object.__new__(gs.SessionTimeout)
        drill.f, drill.s = f, {'TIMEOUT_FREEZE_S': 20, 'GW_READY_BOUND_S': 60}
        drill.freeze_gw0()
        self.assertEqual([c[0] for c in calls], ['freeze_main'])
        self.assertEqual(calls[0][1], ('gw0',))


class FillLinesTest(unittest.TestCase):
    live = [{'user': 1, 'target': 's0', 'connects': 1, 'snapshots': 1}, {'user': 2, 'target': 's1', 'connects': 1, 'snapshots': 2}]

    def test_the_control_text_needs_live_streams(self):
        rows = [{'i': 0, 'layout': 'a', 'taker_order': '9', 'accepted_ns': 1, 'sent_ns': 0, 'orders_gone_ns': 5,
                 'failure': 'fill never visible'}]
        muted = gs.fill_lines(rows, 2, self.live, True, 10)
        self.assertEqual(muted['fill_visible']['text'], gs.FILL_TEXT)
        self.assertTrue(muted['pairs_complete']['holds'], muted['pairs_complete'])     # cut short by the control, not refused
        never = [dict(s, connects=0, snapshots=0) for s in self.live]
        unreachable = gs.fill_lines(rows, 2, never, True, 10)
        self.assertEqual(unreachable['fill_visible']['text'], gs.NOT_LIVE_TEXT)
        self.assertEqual(unreachable['streams_live_before_pairs']['text'], gs.NOT_LIVE_TEXT)
        self.assertNotIn(gs.FILL_TEXT, [v.get('text') for v in unreachable.values()])

    def test_a_drill_run(self):
        rows = [{'i': i, 'layout': 'a', 'taker_order': str(i), 'accepted_ns': 1, 'sent_ns': 0, 'fill_frame_ns': 3,
                 'orders_gone_ns': 2} for i in range(2)]
        self.assertTrue(all(v['holds'] for v in gs.fill_lines(rows, 2, self.live, False, 10).values()))
        refused = rows[:1] + [{'i': 1, 'layout': 'a', 'failure': 'taker not accepted'}]
        self.assertEqual(gs.fill_lines(refused, 2, self.live, False, 10)['pairs_complete']['text'], 'pair not accepted')
        self.assertTrue(gs.fill_lines(rows[:1], 2, self.live, False, 10)['pairs_complete'].get('inconclusive'))


class PairsProbeTest(unittest.TestCase):
    """GET /orders is polled from the 201 in its own thread; the probe reports every stream's state and waits for go."""

    FILL_DELAY_S = 0.4

    def run_pairs(self, plan_extra):
        state = {'next': 100, 'taker_at': None}

        class Fills(dict):
            def __contains__(self, oid):
                return state['taker_at'] is not None and time.monotonic() >= state['taker_at'] + PairsProbeTest.FILL_DELAY_S

            def __getitem__(self, oid):
                return [time.time_ns()]

        class Statuses(dict):
            def get(self, oid, default=None):
                return [('NEW', 0)]

        class Conn:
            def __init__(self, target, api_key, **kw):
                self.cond, self.connects = threading.Condition(), 1
                self.view = types.SimpleNamespace(snapshots=1, statuses=Statuses(), fills=Fills(),
                                                  final=lambda: {'open': [], 'snapshots': 1})
                self.closes = []

            def start(self):
                pass

            def stop(self):
                pass

            def wait(self, predicate, timeout_s):
                deadline = time.monotonic() + timeout_s
                while not predicate(self.view):
                    if time.monotonic() >= deadline:
                        return False
                    time.sleep(0.01)
                return True

        def fake_request(method, target, path, headers, body, timeout_s):
            if method == 'GET':
                return 200, {'orders': []}, None
            state['next'] += 1
            if body['side'] == 'BUY':
                state['taker_at'] = time.monotonic()
            return 201, {'orderId': str(state['next'])}, None

        lay = {'name': 'one', 'maker': 1, 'taker': 2, 'maker_gw': 'g:1', 'taker_gw': 'g:1', 'maker_st': 's:2', 'taker_st': 's:2'}
        plan = dict({'pairs': 1, 'layouts': [lay], 'market': 1, 'price': 90 * FP, 'quantity': FP, 'visible_bound_s': 5,
                     'booked_bound_s': 5, 'poll_ms': 5, 'stop_after_failures': 0}, **plan_extra)
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.object(gateway_probe, 'StreamConn', Conn), \
                unittest.mock.patch.object(gateway_probe, 'request', fake_request):
            out = f'{d}/pairs.json'
            if plan.get('signal_dir') == 'tmp':
                plan['signal_dir'] = d
                Path(d, 'pairs.go').write_text('go\n')
            gateway_probe.pairs(plan, {'1': 'k1', '2': 'k2'}, out)
            ready = json.loads(Path(d, 'pairs.ready').read_text()) if plan.get('signal_dir') else None
            return json.loads(Path(out).read_text()), ready

    def test_orders_gone_is_timed_from_the_201_not_after_the_fill_frame(self):
        result, _ = self.run_pairs({})
        row = result['pairs'][0]
        self.assertIsNotNone(row['fill_frame_ns'])
        gone_s = (row['orders_gone_ns'] - row['accepted_ns']) / 1e9
        fill_s = (row['fill_frame_ns'] - row['accepted_ns']) / 1e9
        self.assertGreaterEqual(fill_s, self.FILL_DELAY_S - 0.05)
        self.assertLess(gone_s, self.FILL_DELAY_S / 2, row)

    def test_the_probe_reports_each_stream_and_waits_for_go(self):
        result, ready = self.run_pairs({'signal_dir': 'tmp', 'wait_go_s': 5})
        self.assertEqual(ready['streams'], [{'user': 1, 'target': 's:2', 'connects': 1, 'snapshots': 1},
                                            {'user': 2, 'target': 's:2', 'connects': 1, 'snapshots': 1}])
        self.assertTrue(result['go'])
        self.assertEqual(result['streams_at_go'], ready['streams'])


class TickLinesTest(unittest.TestCase):
    def answer(self, status, reason=None):
        return {'status': status, 'reply': {'reason': reason} if reason else {'orderId': '5', 'status': 'PENDING_NEW'},
                'sent_ns': 0, 'recv_ns': 10_000_000}

    def test_a_priced_market_is_answered_from_its_last_tick_and_recorded(self):
        lines = gs.noref_lines({'traded_market': self.answer(201), 'empty_market': self.answer(422, 'NO_REFERENCE_PRICE')},
                               [{'slot': 'fwd0'}], 10)
        self.assertTrue(lines['no_reference_price']['holds'])
        self.assertTrue(lines['priced_market_answered']['holds'])
        self.assertFalse(lines['priced_market_answered']['detail']['refused'])

    def test_a_never_priced_market_must_be_refused_and_a_hang_fails(self):
        both = {'traded_market': self.answer(422, 'NO_REFERENCE_PRICE'), 'empty_market': self.answer(422, 'NO_REFERENCE_PRICE')}
        self.assertTrue(all(v['holds'] for v in gs.noref_lines(both, [], 10).values()))
        other = dict(both, empty_market=self.answer(201))
        self.assertEqual(gs.noref_lines(other, [], 10)['no_reference_price']['text'],
                         'no 422 NO_REFERENCE_PRICE on a market never priced')
        hung = dict(both, traded_market=dict(self.answer(201), recv_ns=20_000_000_000))
        self.assertEqual(gs.noref_lines(hung, [], 10)['priced_market_answered']['text'],
                         'MARKET order on a priced market unanswered with the forwarders stopped')
        lost = dict(both, traded_market=self.answer(0))
        self.assertFalse(gs.noref_lines(lost, [], 10)['priced_market_answered']['holds'])


class ConvergenceTest(unittest.TestCase):
    def view(self, user, open_):
        return {'user': user, 'target': 's', 'open': open_, 'awaiting_snapshot': False, 'resyncs': 0, 'closes': [], 'snapshots': 1}

    def test_empty_sets_prove_nothing(self):
        result = gs.convergence([self.view(1, []), self.view(2, [])], {1: set(), 2: set()})
        self.assertTrue(result.get('inconclusive'))
        self.assertEqual(result['detail']['users_without_open_orders'], [1, 2])

    def test_open_orders_on_every_user(self):
        self.assertTrue(gs.convergence([self.view(1, ['5']), self.view(2, ['6'])], {1: {'5'}, 2: {'6'}})['holds'])
        bad = gs.convergence([self.view(1, ['5']), self.view(2, [])], {1: {'5'}, 2: {'6'}})
        self.assertEqual(bad['text'], gs.CONVERGE_TEXT)
        self.assertFalse(bad.get('inconclusive'))


class SlowCloseLineTest(unittest.TestCase):
    clean = ('gw0', 'gw1', 'st1')
    first = {'at_ns': 0, 'ready_st0': 200, 'epoch_st0': 1, 'epoch_gw0': 1, 'epoch_gw1': 1, 'epoch_st1': 1}

    def row(self, at, **kw):
        return dict(self.first, at_ns=at, **kw)

    def test_st0_not_ready_after_the_close(self):
        samples = [self.first, self.row(10), self.row(20, ready_st0=503)]
        self.assertTrue(gs.st0_close_line(samples, self.first, 10, 30, self.clean)['holds'])
        self.assertTrue(gs.st0_saw_close(samples, self.first, 10))

    def test_a_new_st0_epoch_counts_and_a_count_drop_alone_does_not(self):
        self.assertTrue(gs.st0_close_line([self.first, self.row(10, epoch_st0=2)], self.first, 10, 30, self.clean)['holds'])
        quiet = gs.st0_close_line([self.first, self.row(10), self.row(20)], self.first, 10, 30, self.clean)
        self.assertEqual(quiet['text'], "closed session not shown to be st0's")
        late = gs.st0_close_line([self.first, self.row(10), self.row(40, ready_st0=503)], self.first, 10, 30, self.clean)
        self.assertFalse(late['holds'])                     # after the lift it is no witness

    def test_another_role_losing_its_session_fails(self):
        samples = [self.first, self.row(10, ready_st0=503, epoch_gw0=2)]
        result = gs.st0_close_line(samples, self.first, 10, 30, self.clean)
        self.assertEqual(result['detail']['other_epochs_moved'], ['epoch_gw0'])
        self.assertFalse(result['holds'])
        self.assertTrue(gs.st0_close_line(samples, self.first, None, 30, self.clean).get('inconclusive'))


class SessionClosesTest(unittest.TestCase):
    def test_a_close_on_either_path_counts(self):
        first = {'resumable_closed': 0.0, 'discard_closed': 0.0}
        # night 20261119T150409Z entry 20: the core closed st0 through the NOT_CONNECTED path, discard_closed 0 -> 1
        discard = gs.session_closes(first, {'resumable_closed': 0.0, 'discard_closed': 1.0})
        self.assertEqual((discard['total'], discard['resumable_closed'], discard['discard_closed']), (1.0, 0.0, 1.0))
        self.assertEqual(discard['path'], [gs.CLOSE_PATHS['discard_closed']])
        ceiling = gs.session_closes(first, {'resumable_closed': 1.0, 'discard_closed': 0.0})
        self.assertEqual((ceiling['total'], ceiling['path']), (1.0, [gs.CLOSE_PATHS['resumable_closed']]))
        both = gs.session_closes(first, {'resumable_closed': 1.0, 'discard_closed': 1.0})
        self.assertEqual(both['total'], 2.0)                # two closes: the delta == 1 check fails
        none = gs.session_closes(first, dict(first))
        self.assertEqual((none['total'], none['path']), (0.0, None))

    def test_an_unreadable_counter_is_not_a_close(self):
        self.assertIsNone(gs.session_closes({'resumable_closed': None, 'discard_closed': None},
                                            {'resumable_closed': 1.0, 'discard_closed': 1.0})['total'])
        one = gs.session_closes({'resumable_closed': 0.0, 'discard_closed': None},
                                {'resumable_closed': 1.0, 'discard_closed': 1.0})
        self.assertEqual((one['total'], one['discard_closed']), (1.0, None))
        self.assertEqual(gs.session_closes({'resumable_closed': 0.0, 'discard_closed': 0.0},
                                           {'resumable_closed': None, 'discard_closed': 0.0})['total'], 0.0)


class GateSettleTest(unittest.TestCase):
    def test_a_refused_fresh_key_is_resent_until_decided(self):
        answers = iter([(503, {'code': 'ADMISSION_CLOSED'}, None), (503, {'code': 'ADMISSION_CLOSED'}, None),
                        (201, {'orderId': '77', 'status': 'PENDING_NEW', 'hold': {'assetId': '0', 'amount': '0.05'}}, None)])
        body = {'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC', 'price': '50', 'quantity': '0.001'}
        row = {'key': KEY, 'user': 7, 'body': body}
        log = gateway_probe.settle([row], ['g0:1', 'g1:1'], {'7': 'k'}, None, bound_s=60, backoff_s=0,
                                   sender=lambda *a: next(answers), sleep=lambda s: None)
        self.assertEqual([(r['status'], r['target'], r['tag']) for r in log],
                         [(503, 'g0:1', 'settle'), (503, 'g1:1', 'settle'), (201, 'g0:1', 'settle')])
        gate = [dict(log[0], tag='fresh', sent_ns=0)]
        self.assertEqual(gs.creates_from(gate)[0]['reply'], {'outcome': 'UNKNOWN'})
        self.assertEqual(gs.creates_from(gate + log)[0]['reply']['outcome'], 'ACK')

    def test_settle_gives_up_at_its_bound(self):
        now = [0.0]
        def clock():
            now[0] += 1
            return now[0]
        log = gateway_probe.settle([{'key': KEY, 'user': 7, 'body': {}}], ['g'], {'7': 'k'}, None, bound_s=5, backoff_s=0,
                                   sender=lambda *a: (503, {}, None), clock=clock, sleep=lambda s: None)
        self.assertLessEqual(len(log), 5)


class KeyOracleNotLiveTest(unittest.TestCase):
    def test_an_answered_order_must_be_live_where_nothing_fills(self):
        rows = [{'key': 'k1', 'user': 1, 'quantity': 10}]
        attempts = [{'key': 'k1', 'status': 201, 'body': {'orderId': '5'}}]
        self.assertEqual(gateway_probe.key_oracle(rows, attempts, [])['verdict'], 'PASS')
        result = gateway_probe.key_oracle(rows, attempts, [], nothing_fills=True)
        self.assertEqual((result['verdict'], result['failures'], result['not_live_keys']), ('FAIL', [gateway_probe.NOT_LIVE], ['k1']))
        live = [{'user': 1, 'market': 1, 'quantity': 10, 'order': 5}]
        self.assertEqual(gateway_probe.key_oracle(rows, attempts, live, nothing_fills=True)['verdict'], 'PASS')



class ReofferCreateLineTest(unittest.TestCase):
    def row(self, key, user, qty, status, reply):
        return {'tag': 'reoffer-create', 'key': key, 'user': user, 'body': {'quantity': qty}, 'status': status, 'reply': reply}

    def test_one_order_per_key_and_a_duplicate_witness(self):
        log = {'requests': [self.row('k1', 7, '0.02', 200, {'orderId': '1', 'duplicate': True}),
                            self.row('k2', 7, '0.021', 201, {'orderId': '2'})]}
        orders = [{'user': 7, 'market': 1, 'quantity': gs.units('0.02'), 'order': 1},
                  {'user': 7, 'market': 1, 'quantity': gs.units('0.021'), 'order': 2}]
        self.assertTrue(gs.reoffer_create_line(log, orders)['holds'])

    def test_a_second_order_fails_with_the_control_text(self):
        log = {'requests': [self.row('k1', 7, '0.02', 201, {'orderId': '3'})]}
        orders = [{'user': 7, 'market': 1, 'quantity': gs.units('0.02'), 'order': n} for n in (1, 3)]
        row = gs.reoffer_create_line(log, orders)
        self.assertEqual((row['holds'], row['text']), (False, gateway_probe.SECOND_ORDER))

    def test_no_witness_is_inconclusive_and_a_lost_answer_fails(self):
        orders = [{'user': 7, 'market': 1, 'quantity': gs.units('0.02'), 'order': 1}]
        row = gs.reoffer_create_line({'requests': [self.row('k1', 7, '0.02', 201, {'orderId': '1'})]}, orders)
        self.assertTrue(row['inconclusive'])
        row = gs.reoffer_create_line({'requests': [self.row('k1', 7, '0.02', 0, None)]}, orders)
        self.assertEqual(row['text'], 'a re-offered create unanswered or without its order')
        row = gs.reoffer_create_line({'requests': [self.row('k1', 7, '0.02', 201, {'orderId': '1'})]}, [])
        self.assertEqual(row['text'], 'a re-offered create unanswered or without its order')

if __name__ == '__main__':
    unittest.main()
