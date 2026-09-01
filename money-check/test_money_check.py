#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the live-money guardrail's invariant logic.

money_check.py is the thing that decides whether the ledger is sound, and until now
nothing checked the checker. These tests exercise the pure functions only -- no Redis,
no OMS, no AeDump -- so they run anywhere with the stdlib, matching money_check's own
zero-dependency rule.

    python3 -m unittest discover -s tools/money-check

The cases are drawn from failures this stack has actually had: a hold that outlives its
order (2026-07-25, $9.15M of maker collateral frozen), a deposit that has to be
subtracted from an apparent conservation breach (2026-08-03), and the fixed-point
arithmetic that must never go through a float.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from money_check import (  # noqa: E402
    SCALE,
    check_ae_internal,
    check_conservation,
    check_locked,
    check_nonnegative,
    expected_locked_for_user,
    fmt_fixed,
    parse_asset_map,
    parse_fixed,
    parse_ledger_log,
    parse_user_arg,
)

# asset_map is symbol -> id (that is the direction asset_name() reads).
ASSETS = {"USD": 0, "BTC": 1}
MARKETS = {1: (1, 0)}  # BTC-USD: base BTC(1), quote USD(0)


def bal(**kw):
    """balances dict: {(userId, assetId): {"available": int, "locked": int}}"""
    return {k: {"available": v[0], "locked": v[1]} for k, v in kw.items()}


class FixedPoint(unittest.TestCase):
    def test_parses_eight_decimal_places(self):
        self.assertEqual(parse_fixed("99182.00000000"), 99182 * SCALE)
        self.assertEqual(parse_fixed("1.87453054"), 187453054)

    def test_whole_numbers_and_missing_fraction(self):
        self.assertEqual(parse_fixed("7"), 7 * SCALE)
        self.assertEqual(parse_fixed("0.5"), SCALE // 2)

    def test_empty_and_none_are_zero(self):
        self.assertEqual(parse_fixed(None), 0)
        self.assertEqual(parse_fixed(""), 0)
        self.assertEqual(parse_fixed("   "), 0)

    def test_negative(self):
        self.assertEqual(parse_fixed("-1.5"), -(3 * SCALE // 2))

    def test_extra_precision_truncates_rather_than_rounds(self):
        # A ninth decimal place must not be allowed to round a balance upward.
        self.assertEqual(parse_fixed("0.000000019"), 1)

    def test_round_trip(self):
        for s in ("0.00000000", "1.87453054", "-12.30000000", "100000.00000000"):
            self.assertEqual(fmt_fixed(parse_fixed(s)), s)


class ExpectedLocked(unittest.TestCase):
    """The collateral rule: a BUY locks quote, a SELL locks base."""

    def test_buy_locks_price_times_remaining_in_quote(self):
        orders = [{"marketId": 1, "side": "BUY", "status": "NEW",
                   "price": "90000.00000000", "remainingQty": "0.00100000"}]
        exp, n_open, n_unpriced = expected_locked_for_user(orders, MARKETS)
        self.assertEqual(exp, {0: 90 * SCALE})  # 90000 * 0.001 = 90 USD
        self.assertEqual((n_open, n_unpriced), (1, 0))

    def test_sell_locks_base_units_and_ignores_price(self):
        orders = [{"marketId": 1, "side": "SELL", "status": "NEW",
                   "price": "90000.00000000", "remainingQty": "0.25000000"}]
        exp, _, _ = expected_locked_for_user(orders, MARKETS)
        self.assertEqual(exp, {1: SCALE // 4})

    def test_terminal_orders_lock_nothing(self):
        for status in ("FILLED", "CANCELED", "CANCELLED", "REJECTED", "EXPIRED", "DONE"):
            orders = [{"marketId": 1, "side": "BUY", "status": status,
                       "price": "90000.00000000", "remainingQty": "0.00100000"}]
            exp, n_open, _ = expected_locked_for_user(orders, MARKETS)
            self.assertEqual(exp, {}, "%s must not hold collateral" % status)
            self.assertEqual(n_open, 0)

    def test_fully_filled_order_locks_nothing(self):
        orders = [{"marketId": 1, "side": "BUY", "status": "PARTIALLY_FILLED",
                   "price": "90000.00000000", "remainingQty": "0"}]
        exp, n_open, _ = expected_locked_for_user(orders, MARKETS)
        self.assertEqual((exp, n_open), ({}, 0))

    def test_unpriced_buy_is_reported_not_guessed(self):
        # A market BUY has no price, so no quote hold can be derived from qty alone.
        # It must be surfaced as unpriced rather than silently contributing zero.
        orders = [{"marketId": 1, "side": "BUY", "status": "NEW",
                   "price": "0", "remainingQty": "0.00100000"}]
        exp, n_open, n_unpriced = expected_locked_for_user(orders, MARKETS)
        self.assertEqual(exp, {})
        self.assertEqual((n_open, n_unpriced), (1, 1))

    def test_unknown_market_is_skipped_without_crashing(self):
        orders = [{"marketId": 99, "side": "BUY", "status": "NEW",
                   "price": "1.00000000", "remainingQty": "1.00000000"}]
        exp, n_open, _ = expected_locked_for_user(orders, MARKETS)
        self.assertEqual((exp, n_open), ({}, 1))

    def test_two_orders_accumulate(self):
        orders = [
            {"marketId": 1, "side": "BUY", "status": "NEW",
             "price": "90000.00000000", "remainingQty": "0.00100000"},
            {"marketId": 1, "side": "SELL", "status": "NEW",
             "price": "95000.00000000", "remainingQty": "0.50000000"},
        ]
        exp, n_open, _ = expected_locked_for_user(orders, MARKETS)
        self.assertEqual(exp, {0: 90 * SCALE, 1: SCALE // 2})
        self.assertEqual(n_open, 2)


class Conservation(unittest.TestCase):
    """Trading moves value inside an asset; only deposits and withdrawals change its total."""

    def test_passes_when_totals_match_deposits(self):
        balances = bal(**{})
        balances = {(1, 0): {"available": 60 * SCALE, "locked": 0},
                    (2, 0): {"available": 40 * SCALE, "locked": 0}}
        r = check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 0)
        self.assertEqual(r["status"], "PASS")

    def test_locked_counts_toward_the_total(self):
        # Collateral has not left the venue; it must not look like a shortfall.
        balances = {(1, 0): {"available": 40 * SCALE, "locked": 60 * SCALE}}
        r = check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 0)
        self.assertEqual(r["status"], "PASS")

    def test_fails_when_value_appears_from_nowhere(self):
        # The failure that matters: matching that creates money.
        balances = {(1, 0): {"available": 101 * SCALE, "locked": 0}}
        r = check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 0)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["gap"], SCALE)
        self.assertEqual(r["drifts"][0]["asset"], "USD")

    def test_fails_when_value_disappears(self):
        balances = {(1, 0): {"available": 99 * SCALE, "locked": 0}}
        r = check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 0)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["gap"], -SCALE)

    def test_withdrawals_are_subtracted(self):
        balances = {(1, 0): {"available": 70 * SCALE, "locked": 0}}
        r = check_conservation(balances, {0: 100 * SCALE}, {0: 30 * SCALE}, True, ASSETS, 0)
        self.assertEqual(r["status"], "PASS")

    def test_indeterminate_when_the_log_misses_genesis(self):
        # Without the clean-slate seeding we cannot assert an absolute total, and a
        # guess here would be a false breach on a healthy venue.
        balances = {(1, 0): {"available": 5 * SCALE, "locked": 0}}
        r = check_conservation(balances, {0: 100 * SCALE}, {}, False, ASSETS, 0)
        self.assertEqual(r["status"], "INDETERMINATE")
        self.assertEqual(r["drifts"], [])

    def test_tolerance_absorbs_a_sub_tick_gap(self):
        balances = {(1, 0): {"available": 100 * SCALE + 1, "locked": 0}}
        self.assertEqual(check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 1)["status"], "PASS")
        self.assertEqual(check_conservation(balances, {0: 100 * SCALE}, {}, True, ASSETS, 0)["status"], "FAIL")


class NonNegativity(unittest.TestCase):
    def test_passes_on_clean_balances(self):
        balances = {(1, 0): {"available": SCALE, "locked": 0}}
        self.assertEqual(check_nonnegative(balances, ASSETS)["status"], "PASS")

    def test_catches_negative_available(self):
        balances = {(1, 0): {"available": -1, "locked": 0}}
        r = check_nonnegative(balances, ASSETS)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["field"], "available")

    def test_catches_negative_locked(self):
        # An over-release drives locked below zero; it must not be written off as noise.
        balances = {(1, 0): {"available": SCALE, "locked": -5}}
        r = check_nonnegative(balances, ASSETS)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["field"], "locked")


class LockedVsHolds(unittest.TestCase):
    def test_passes_when_locked_matches_open_orders(self):
        balances = {(1, 0): {"available": 0, "locked": 90 * SCALE}}
        r = check_locked(balances, {(1, 0): 90 * SCALE}, ASSETS, 0, True)
        self.assertEqual(r["status"], "PASS")

    def test_catches_a_hold_that_outlived_its_order(self):
        # 2026-07-25: holds accumulated with no open order behind them and $9.15M of
        # maker collateral stayed frozen while every component reported healthy.
        balances = {(1, 0): {"available": 0, "locked": 90 * SCALE}}
        r = check_locked(balances, {}, ASSETS, 0, True)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["gap"], 90 * SCALE)
        self.assertEqual(r["drifts"][0]["userId"], 1)

    def test_catches_collateral_that_was_never_taken(self):
        balances = {(1, 0): {"available": 90 * SCALE, "locked": 0}}
        r = check_locked(balances, {(1, 0): 90 * SCALE}, ASSETS, 0, True)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["gap"], -90 * SCALE)

    def test_skips_rather_than_passes_when_the_oms_is_unreachable(self):
        # A check that cannot see its authority must not report green.
        r = check_locked({}, {}, ASSETS, 0, False)
        self.assertEqual(r["status"], "SKIP")


class AeInternal(unittest.TestCase):
    def test_returns_none_when_not_in_ae_mode(self):
        self.assertIsNone(check_ae_internal({}, None, ASSETS, 0))

    def test_passes_when_hold_entries_sum_to_locked(self):
        balances = {(1, 1): {"available": 0, "locked": SCALE}}
        self.assertEqual(check_ae_internal(balances, {(1, 1): SCALE}, ASSETS, 0)["status"], "PASS")

    def test_catches_a_locked_balance_with_no_hold_behind_it(self):
        balances = {(1, 1): {"available": 0, "locked": SCALE}}
        r = check_ae_internal(balances, {}, ASSETS, 0)
        self.assertEqual(r["status"], "FAIL")
        self.assertEqual(r["drifts"][0]["gap"], SCALE)


class LedgerLog(unittest.TestCase):
    """The right-hand side of conservation is recovered from the simulator's log."""

    def _log(self, text):
        fh = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_parses_a_real_top_up_line(self):
        # Verbatim from the demo box, 2026-08-03. Chasing this line explained a
        # 1.87453054 BTC apparent conservation breach that was not a breach.
        path = self._log(
            "2026/08/03 23:47:24 [accounts] bot 900009: deposited 1.87453054 of asset 1 "
            "(had 13.12546946, target 15.00000000)\n")
        deposits, withdrawals, genesis, meta = parse_ledger_log([path])
        self.assertEqual(deposits, {1: 187453054})
        self.assertEqual(withdrawals, {})
        self.assertEqual(meta["assets_seen"], [1])

    def test_genesis_is_only_covered_when_the_first_deposit_started_from_zero(self):
        mid = self._log("bot 1: deposited 5.00000000 of asset 0 (had 10.00000000, target 15.00000000)\n")
        _, _, genesis, meta = parse_ledger_log([mid])
        self.assertFalse(genesis)
        self.assertEqual(meta["first_had_nonzero"], [0])

        clean = self._log("bot 1: deposited 15.00000000 of asset 0 (had 0, target 15.00000000)\n")
        _, _, genesis, _ = parse_ledger_log([clean])
        self.assertTrue(genesis)

    def test_deposits_accumulate_per_asset(self):
        path = self._log(
            "deposited 1.00000000 of asset 0 (had 0, target 1)\n"
            "deposited 2.50000000 of asset 0 (had 1, target 3.5)\n"
            "deposited 0.00000001 of asset 1 (had 0, target 1)\n")
        deposits, _, _, _ = parse_ledger_log([path])
        self.assertEqual(deposits, {0: 350000000, 1: 1})

    def test_withdrawals_are_collected_separately(self):
        path = self._log(
            "deposited 10.00000000 of asset 0 (had 0, target 10)\n"
            "bot 1: withdrew 4.00000000 of asset 0\n")
        deposits, withdrawals, _, _ = parse_ledger_log([path])
        self.assertEqual(deposits, {0: 10 * SCALE})
        self.assertEqual(withdrawals, {0: 4 * SCALE})

    def test_missing_file_is_not_an_error(self):
        deposits, _, genesis, meta = parse_ledger_log(["/nonexistent/sim.log"])
        self.assertEqual(deposits, {})
        self.assertFalse(genesis)
        self.assertEqual(meta["files"], [])

    def test_unrelated_lines_are_ignored(self):
        path = self._log(
            "2026/08/03 23:47:24 [run] source=binance BTC-USD=102642.01 placed=9722841\n"
            "deposited 1.00000000 of asset 0 (had 0, target 1)\n")
        deposits, _, _, meta = parse_ledger_log([path])
        self.assertEqual(deposits, {0: SCALE})
        self.assertEqual(meta["lines"], 2)

    def test_rotated_logs_are_read_oldest_first(self):
        # A glob like --sim-log "sim.log*" sorts the LIVE file ahead of its
        # archives ("sim.log" < "sim.log.1", and "sim.log.10" < "sim.log.2"),
        # i.e. newest first. Genesis coverage keys on the FIRST deposit line
        # per asset, so the parser must order files chronologically itself --
        # otherwise a rotated soak reports conservation INDETERMINATE forever
        # while the sweep still exits 0 (green), and a wipe+rotation can even
        # read as a false breach (archived deposits counted, balances wiped).
        oldest = self._log(
            "bot 1: deposited 15.00000000 of asset 0 (had 0, target 15.00000000)\n")
        newest = self._log(
            "bot 1: deposited 5.00000000 of asset 0 (had 15.00000000, target 20.00000000)\n")
        # mtime is the chronological source; pin it so the test is deterministic.
        os.utime(oldest, (1_700_000_000, 1_700_000_000))
        os.utime(newest, (1_700_000_100, 1_700_000_100))
        # Pass newest first -- the order a sorted glob yields.
        deposits, _, genesis, meta = parse_ledger_log([newest, oldest])
        self.assertEqual(deposits, {0: 20 * SCALE})
        self.assertTrue(genesis)
        self.assertEqual(meta["files"], [oldest, newest])

    def test_rotation_index_breaks_mtime_ties_oldest_first(self):
        # mtimes can tie (coarse filesystem granularity, rapid successive
        # rotations), and the caller passes a lexicographically sorted glob --
        # a stable sort on mtime alone would then keep that newest-first
        # order. Ties must resolve by rotation index instead: larger ".N" is
        # older, and the live file ("sim.log", no suffix) is newest.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        paths = {}
        for name, text in [
            ("sim.log.10",
             "bot 1: deposited 15.00000000 of asset 0 (had 0, target 15.00000000)\n"),
            ("sim.log.2",
             "bot 1: deposited 5.00000000 of asset 0 (had 15.00000000, target 20.00000000)\n"),
            ("sim.log",
             "bot 1: deposited 1.00000000 of asset 0 (had 20.00000000, target 21.00000000)\n"),
        ]:
            p = os.path.join(d, name)
            with open(p, "w") as fh:
                fh.write(text)
            paths[name] = p
        for p in paths.values():
            os.utime(p, (1_700_000_000, 1_700_000_000))  # identical mtimes
        # Lexicographic order, as handed over by sorted(glob.glob(...)).
        deposits, _, genesis, meta = parse_ledger_log(sorted(paths.values()))
        self.assertEqual(meta["files"],
                         [paths["sim.log.10"], paths["sim.log.2"], paths["sim.log"]])
        self.assertEqual(deposits, {0: 21 * SCALE})
        self.assertTrue(genesis)


class ArgParsing(unittest.TestCase):
    def test_user_ranges_and_singles(self):
        self.assertEqual(sorted(parse_user_arg("900000-900002,900999")),
                         [900000, 900001, 900002, 900999])

    def test_asset_map_is_symbol_equals_id(self):
        self.assertEqual(parse_asset_map("USD=0,BTC=1"), {"USD": 0, "BTC": 1})


if __name__ == "__main__":
    unittest.main()
