# SPDX-License-Identifier: Apache-2.0
"""The market-data drills' pure parts and their fixture pieces: the scenario registry and its controls, the verdict and its
text matcher, the market history and candle lines against the journal, the feed lines (one trade twice on a connection,
the book heal, the down-at-start state), the drill kinds and their test builds through mk_manifests and the checker, and
md0's environment (no Docker)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from contracts import Inconclusive, Violation
import core_contracts
import md_drills as md
import nightly
from test_smoke_core import marketdata_fixture, marketdata_manifest


def trade(tid, seq, price=90, qty=1, buy=True, ts=1_800_000_000_000, market=1):
    return {'type': 'trade', 'trade_id': tid, 'journal_seq': seq, 'market': market, 'price': price, 'quantity': qty,
            'taker_is_buy': buy, 'timestamp': ts, 'me_epoch': 7}


def row(tid, seq, price=90, qty=1, buy=True, ts=1_800_000_000_000, market=1):
    return {'trade_id': tid, 'journal_seq': seq, 'market_id': market, 'price': price, 'quantity': qty, 'taker_is_buy': buy,
            'executed_at_ms': ts}


def frame(ns, **body):
    return {'recv_ns': ns, 'frame': body}


def tape(ns, *ids):
    return frame(ns, type='TRADES_BATCH', marketId=1,
                 trades=[{'tradeId': str(t), 'journalSeq': t + 2, 'price': '90', 'quantity': '0.01', 'side': 'BUY'} for t in ids])


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def manifest(self, kind='cps'):
        m = marketdata_manifest(self.dir, kind=kind)
        if core_contracts.GATEWAY_KINDS[kind]['marketdata']['md0'] == 'marketdata_nc':
            m['slot_artifacts']['md0'] = 'marketdata_nc'
        return m

    def test_the_scenarios_are_known_to_the_runner_and_the_night(self):
        for name in md.SCENARIOS:
            self.assertTrue(md.is_scenario(name))
            self.assertTrue(nightly.scenario_known(name))
        self.assertFalse(nightly.scenario_known('core-md-other'))
        plan = nightly.parse_plan([{'kind': 'cps-mdtc', 'scenario': 'core-md-exactly-once'},
                                   {'kind': 'cps-ext', 'scenario': 'core-md-frozen'}])
        self.assertEqual(len(plan), 2)
        for kind, spec in core_contracts.GATEWAY_KINDS.items():
            if spec.get('md_drill'):
                self.assertIn(spec['md_drill'], md.SCENARIOS, kind)

    def test_check_scenario(self):
        m = self.manifest()
        for name in md.SCENARIOS:
            if name != 'core-md-exactly-once':
                self.assertIsNone(md.check_scenario(m, name, {}), name)
        with self.assertRaisesRegex(Inconclusive, 'MD_TC_COMMIT_PAUSE'):
            md.check_scenario(m, 'core-md-exactly-once', {})
        self.assertIsNone(md.check_scenario(self.manifest('cps-mdtc'), 'core-md-exactly-once', {}))
        with self.assertRaisesRegex(Inconclusive, 'runs core-md-exactly-once only'):
            md.check_scenario(self.manifest('cps-mdtc'), 'core-md-frozen', {})
        with self.assertRaisesRegex(Inconclusive, 'unknown market-data scenario'):
            md.check_scenario(m, 'core-md-other', {})
        nofwd = dict(copy.deepcopy(m), manifest_kind='cps-nofwd')
        nofwd['slot_artifacts'].update(fwd0=None, fwd1=None)
        with self.assertRaisesRegex(Inconclusive, 'needs md0 and both forwarders'):
            md.check_scenario(nofwd, 'core-md-frozen', {})
        with self.assertRaisesRegex(Inconclusive, 'runs on a market-data kind'):
            md.check_scenario(dict(m, manifest_kind='pj'), 'core-md-frozen', {})

    def test_controls(self):
        m = self.manifest()
        self.assertEqual(md.check_scenario(m, 'core-md-frozen', {'MD_CONTROL': 'short-freeze'}),
                         ('short-freeze', 'freeze was shorter than the stale time', True))
        with self.assertRaisesRegex(Inconclusive, 'is a control of core-md-failover'):
            md.check_scenario(m, 'core-md-frozen', {'MD_CONTROL': 'no-leader-change'})
        with self.assertRaises(Violation):
            md.check_scenario(m, 'core-md-frozen', {'MD_CONTROL': 'other'})
        split = self.manifest('cps-mdnc-split')
        self.assertEqual(md.check_scenario(split, 'core-md-exactly-once', {}),
                         ('cps-mdnc-split', 'missing trade <id>|duplicate trade <id>', False))
        with self.assertRaisesRegex(Inconclusive, 'one control a run'):
            md.check_scenario(split, 'core-md-exactly-once', {'MD_CONTROL': 'never-killed'})
        for name, (scenario, text, _) in md.CONTROLS.items():
            self.assertIn(scenario, md.SCENARIOS)
            self.assertEqual(text, text.strip())

    def test_settings_are_positive_integers(self):
        self.assertEqual(md.settings({})['MD_FREEZE_S'], 20)
        self.assertEqual(md.settings({'MD_FREEZE_S': '30'})['MD_FREEZE_S'], 30)
        with self.assertRaises(Violation):
            md.settings({'MD_FREEZE_S': '0'})
        self.assertGreater(md.SETTINGS['MD_FREEZE_S'] * 1000, md.SETTINGS['MD_EGRESS_STALE_MS'])


class VerdictTest(unittest.TestCase):
    def test_text_matches(self):
        self.assertTrue(md.text_matches('missing trade 17', 'missing trade <id>|duplicate trade <id>'))
        self.assertTrue(md.text_matches('duplicate trade 3', 'missing trade <id>|duplicate trade <id>'))
        self.assertTrue(md.text_matches('trade 9 sent twice to one connection', 'trade <id> sent twice to one connection'))
        self.assertFalse(md.text_matches('missing trade x', 'missing trade <id>'))
        self.assertFalse(md.text_matches('missing trade 1 more', 'missing trade <id>'))
        self.assertTrue(md.text_matches('followed a stopped recording', 'followed a stopped recording'))
        self.assertFalse(md.text_matches(None, 'x'))

    def test_a_control_holds_only_on_its_own_text(self):
        ok = {'holds': True, 'detail': {}}
        bad = lambda t: {'holds': False, 'detail': {}, 'text': t}
        control = ('cps-mdnc-split', 'missing trade <id>|duplicate trade <id>', False)
        self.assertEqual(md.verdict({'a': ok, 'b': bad('missing trade 4')}, control)[0], 'PASS')
        self.assertEqual(md.verdict({'a': bad('candles differ from the trade set'), 'b': bad('missing trade 4')}, control)[0],
                         'FAIL')
        self.assertEqual(md.verdict({'a': ok}, control)[0], 'FAIL')
        never = ('never-frozen', 'market service was never frozen', True)
        lines = {'frozen': {'holds': False, 'detail': {}, 'text': 'market service was never frozen', 'inconclusive': True},
                 'healed': md.consequence({'holds': False, 'detail': {}, 'text': 'book did not heal after the freeze'}, 'frozen')}
        self.assertEqual(md.verdict(lines, never)[0], 'INCONCLUSIVE')
        self.assertEqual(md.verdict(lines)[0], 'INCONCLUSIVE')
        self.assertEqual(md.verdict({'a': ok})[0], 'PASS')

    def test_a_control_whose_rule_never_acted_is_inconclusive(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        drill = object.__new__(md.MdDrill)
        drill.out, drill.record, drill.log = Path(temp.name), {}, []
        drill.cps_control = ('cps-mdnc-liveemit', 'trade <id> sent twice to one connection', False)
        lines = {'no_trade_twice': {'holds': True, 'detail': {}}}
        drill.vacuous = 'control vacuous: no journal record was read twice'
        result = drill.finish(lines)
        self.assertEqual((result['status'], result['error']), ('INCONCLUSIVE', 'control vacuous: no journal record was read twice'))
        # a control that held is judged as usual, whatever the flag
        lines = {'no_trade_twice': {'holds': False, 'detail': {}, 'text': 'trade 3 sent twice to one connection'}}
        self.assertEqual(drill.finish(lines)['status'], 'PASS')
        drill.vacuous = None
        self.assertEqual(drill.finish({'no_trade_twice': {'holds': True, 'detail': {}}})['status'], 'FAIL')

    def test_count_line(self):
        self.assertEqual(md.count_line(0, 'never', 'once')['text'], 'never')
        self.assertTrue(md.count_line(0, 'never', 'once')['inconclusive'])
        self.assertEqual(md.count_line(1, 'never', 'once')['text'], 'once')
        self.assertTrue(md.count_line(2, 'never', 'once')['holds'])


class HistoryLinesTest(unittest.TestCase):
    def test_the_history_equals_the_journal(self):
        trades = md.journal_trades({'me_journal': [trade(1, 3), trade(2, 4, buy=False), trade(3, 5, market=2)]})
        self.assertEqual(sorted(trades), [1, 2])
        self.assertTrue(md.history_line(trades, [row(1, 3), row(2, 4, buy=False)])['holds'])
        self.assertEqual(md.history_line(trades, [row(1, 3)])['text'], 'missing trade 2')
        self.assertEqual(md.history_line(trades, [row(1, 3), row(2, 4, buy=False), row(9, 9)])['text'], 'duplicate trade 9')
        self.assertEqual(md.history_line(trades, [row(1, 3), row(2, 4, buy=False), row(2, 4, buy=False)])['text'],
                         'duplicate trade 2')
        self.assertEqual(md.history_line(trades, [row(1, 3), row(2, 4, price=91, buy=False)])['text'],
                         'market history differs from the journal: trade 2')
        self.assertTrue(md.history_line({}, [])['inconclusive'])

    def test_candles_are_a_function_of_the_trade_set(self):
        base = 1_800_000_000_000 - 1_800_000_000_000 % 86_400_000
        rows = [row(1, 3, price=90, qty=2, ts=base + 1000), row(2, 4, price=95, qty=1, ts=base + 2000),
                row(3, 5, price=91, qty=3, ts=base + 61_000)]
        candles = md.candles_of(rows)
        self.assertEqual(len(candles), 2 + 5)                       # two 1m buckets, one bucket of each wider interval
        day = candles[(1, 86400, base)]
        self.assertEqual((day['open'], day['high'], day['low'], day['close']), (90, 95, 90, 91))
        self.assertEqual((day['volume_base'], day['volume_quote'], day['trade_count'], day['last_trade_id']),
                         (6, 90 * 2 + 95 + 91 * 3, 3, 3))
        self.assertEqual(candles[(1, 60, base)]['close'], 95)
        # the order of the input does not matter: journal order is restored
        self.assertEqual(md.candles_of(list(reversed(rows))), candles)
        big = [row(1, 3, price=10 ** 12, qty=10 ** 12)]
        self.assertEqual(md.candles_of(big)[(1, 60, 1_800_000_000_000 - 1_800_000_000_000 % 60_000)]['volume_quote'], 10 ** 24)
        stored = [dict(market_id=k[0], interval_s=k[1], bucket_start_ms=k[2], **v) for k, v in candles.items()]
        self.assertTrue(md.candles_line(rows, stored)['holds'])
        stored[0] = dict(stored[0], close=1)
        self.assertEqual(md.candles_line(rows, stored)['text'], 'candles differ from the trade set')


class FeedLinesTest(unittest.TestCase):
    def test_one_trade_twice_on_one_connection(self):
        frames = [{'recv_ns': 1, 'connect': 'x'}, tape(2, 1, 2), tape(3, 3), {'recv_ns': 4, 'close': 'x'},
                  {'recv_ns': 5, 'connect': 'x'}, tape(6, 3, 4)]
        self.assertTrue(md.twice_line(frames)['holds'])                 # 3 again, but on a new connection
        self.assertEqual(len(md.connections(frames)), 2)
        frames.append(tape(7, 4))
        self.assertEqual(md.twice_line(frames)['text'], 'trade 4 sent twice to one connection')
        self.assertTrue(md.twice_line([{'recv_ns': 1, 'connect': 'x'}])['inconclusive'])

    def test_the_book_heals_after_a_change(self):
        snap = lambda ns, stale=False: frame(ns, type='BOOK_SNAPSHOT', marketId=1, bids=[], asks=[], **({'stale': True} if stale else {}))
        delta = lambda ns: frame(ns, type='BOOK_DELTA', marketId=1, changes=[])
        frames = [snap(1), delta(5), snap(12, stale=True), delta(13), snap(20)]
        heal = md.book_heal(frames, 10)
        self.assertEqual((heal['stale_at_ns'], heal['fresh_at_ns']), (12, 20))
        self.assertTrue(md.heal_line([{'cycle': 1, 'killed': 'me0', 'heal': heal}])['holds'])
        across = md.book_heal([delta(11), snap(12)], 10)
        self.assertEqual(md.heal_line([{'cycle': 1, 'killed': 'me0', 'heal': across}])['text'],
                         'book served across an ME session change')
        never = md.book_heal([snap(12, stale=True)], 10)
        self.assertEqual(md.heal_line([{'cycle': 1, 'killed': 'me0', 'heal': never}])['text'],
                         'book did not go stale and heal after a leader change')

    def test_the_initial_state_while_the_history_was_down_at_the_start(self):
        error = frame(3, type='ERROR', code='HISTORY_UNAVAILABLE', message='m', parts=['tape', 'candles', 'ticker'])
        good = [frame(1, type='SUBSCRIPTION_CONFIRMED', marketId=1), frame(2, type='BOOK_SNAPSHOT', marketId=1), error,
                frame(11, type='TICKERS', tickers=[]), frame(12, type='BOOK_SNAPSHOT', marketId=1)]
        self.assertTrue(md.start_state_line(good, 10)['holds'])
        empty = good[:3] + [frame(4, type='CANDLE_HISTORY', marketId=1, interval='1m', candles=[])] + good[3:]
        self.assertEqual(md.start_state_line(empty, 10)['text'], 'empty series sent without the history')
        handshake = [frame(0, type='TICKERS', tickers=[])] + good
        self.assertEqual(md.start_state_line(handshake, 10)['text'], 'empty series sent without the history')
        no_error = good[:2] + good[3:]
        self.assertEqual(md.start_state_line(no_error, 10)['text'], 'history unavailable was not reported at the start')
        stale = good[:3]
        self.assertEqual(md.start_state_line(stale, 10)['text'], 'no fresh initial state when the trade path started')
        self.assertTrue(md.start_state_line(good[:3], None)['inconclusive'])

    def test_metric_sums_every_series(self):
        self.assertEqual(md.metric({'a{x="1"}': 1.0, 'a{x="2"}': 2.0, 'ab': 9.0}, 'a'), 3.0)
        self.assertIsNone(md.metric({}, 'a'))


class KindsTest(unittest.TestCase):
    def test_the_drill_kinds_stage_the_test_build_their_defines_name(self):
        import test_mk_manifests
        import release_cut
        builder = test_mk_manifests.CutManifestBuilderTest('test_every_s17_kind_builds_validates_and_passes_the_checker')
        builder.setUp()
        self.addCleanup(builder.tearDown)
        for kind, spec in core_contracts.GATEWAY_KINDS.items():
            if not spec.get('marketdata_defines'):
                continue
            with self.subTest(kind=kind):
                _, m = builder.built(kind)
                entry = m['artifacts']['marketdata_nc']
                self.assertEqual(entry['defines'], spec['marketdata_defines'])
                self.assertIsNone(m['artifacts']['marketdata'])
                self.assertEqual(m['slot_artifacts']['md0'], 'marketdata_nc')
                self.assertEqual(release_cut.check(m, builder.world.m, 'rig', old_pins=builder.world.pins).items, [])
                refused = release_cut.check(m, builder.world.m, 'product', old_pins=builder.world.pins).items
                self.assertTrue(any(r == 'K3' for r, _ in refused), refused)
        # a test build whose tree carries another define is refused
        _, m = builder.built('cps-mdnc-epoch')
        tree = Path(m['artifacts']['marketdata_nc']['path']).parent.parent
        (tree / 'CMakeCache.txt').write_text('CMAKE_CXX_FLAGS:STRING=-DMD_NC_NO_EPOCH_CHECK -DMD_NC_COMMIT_SPLIT\n')
        found = release_cut.check(m, builder.world.m, 'rig', old_pins=builder.world.pins).items
        self.assertTrue(any('is not the defines' in t for _, t in found), found)
        # and one of another gateway commit
        other = tree / 'bin/oe-marketdata'
        other.write_bytes(b'ELF oe-marketdata ' + b'9' * 40)
        bad = copy.deepcopy(m)
        import hashlib
        bad['artifacts']['marketdata_nc']['sha256'] = hashlib.sha256(other.read_bytes()).hexdigest()
        found = release_cut.check(bad, builder.world.m, 'rig', old_pins=builder.world.pins).items
        self.assertTrue(any('is not a build of the cut\'s gateway' in t for _, t in found), found)

    def test_a_test_build_needs_its_defines(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        m = marketdata_manifest(temp.name, kind='cps-mdtc')
        m['artifacts']['marketdata_nc'] = dict(m['artifacts']['marketdata'], defines=['MD_TC_COMMIT_PAUSE'])
        m['artifacts']['marketdata'] = None
        m['slot_artifacts']['md0'] = 'marketdata_nc'
        core_contracts.validate_marketdata_artifacts(m)
        m['artifacts']['marketdata_nc']['defines'] = ['MD_NC_OTHER']
        with self.assertRaisesRegex(Violation, 'defines is a non-empty list'):
            core_contracts.validate_marketdata_artifacts(m)
        m['artifacts']['marketdata_nc']['defines'] = ['MD_TC_COMMIT_PAUSE']
        m['artifacts']['marketdata'] = dict(m['artifacts']['marketdata_nc'])
        with self.assertRaisesRegex(Violation, 'the product build carries no defines'):
            core_contracts.validate_marketdata_artifacts(m)


class EnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_order_and_the_test_build_settings(self):
        f = marketdata_fixture(self.dir)
        plain = f.marketdata_env('md0')
        self.assertNotIn('MDTC_COMMIT_PAUSE_MS', plain)
        f.marketdata_archive_order = [2, 0, 1]
        f.marketdata_env_overrides = {'MDTC_COMMIT_PAUSE_MS': 4000, 'MDTC_COMMIT_PAUSE_SKIP': 0}
        env = f.marketdata_env('md0')
        archives = plain['MD_ME_JOURNAL_ARCHIVES'].split(',')
        self.assertEqual(env['MD_ME_JOURNAL_ARCHIVES'].split(','), [archives[2], archives[0], archives[1]])
        self.assertEqual((env['MDTC_COMMIT_PAUSE_MS'], env['MDTC_COMMIT_PAUSE_SKIP']), ('4000', '0'))
        f.marketdata_archive_order = [0, 0, 1]
        with self.assertRaisesRegex(Violation, 'names each ME member once'):
            f.marketdata_env('md0')
        f.marketdata_archive_order = None
        f.marketdata_env_overrides = {'MD_EGRESS_STALE_MS': 1}
        with self.assertRaisesRegex(Violation, 'a drill overrides only'):
            f.marketdata_env('md0')


if __name__ == '__main__':
    unittest.main()
