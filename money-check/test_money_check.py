#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the live-money guardrail's invariant logic.

money_check.py is the thing that decides whether the ledger is sound, and until now
nothing checked the checker. These tests exercise the pure functions only -- no Redis,
no OMS, no CoreDump -- so they run anywhere with the stdlib, matching money_check's own
zero-dependency rule.

    python3 -m unittest discover -s tools/money-check

The cases are drawn from failures this stack has actually had: a hold that outlives its
order (2026-07-25, $9.15M of maker collateral frozen), a deposit that has to be
subtracted from an apparent conservation breach (2026-08-03), and the fixed-point
arithmetic that must never go through a float.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core_expected  # noqa: E402
from money_check import (  # noqa: E402
    SCALE,
    build_arg_parser,
    check_core_internal,
    check_conservation,
    check_locked,
    check_nonnegative,
    expected_locked_for_user,
    fmt_fixed,
    parse_asset_map,
    parse_fixed,
    parse_ledger_log,
    parse_user_arg,
    main,
    retired_refusal,
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


class CoreInternal(unittest.TestCase):
    def test_returns_none_when_not_in_core_mode(self):
        self.assertIsNone(check_core_internal({}, None, ASSETS, 0))

    def test_passes_when_hold_entries_sum_to_locked(self):
        balances = {(1, 1): {"available": 0, "locked": SCALE}}
        self.assertEqual(check_core_internal(balances, {(1, 1): SCALE}, ASSETS, 0)["status"], "PASS")

    def test_catches_a_locked_balance_with_no_hold_behind_it(self):
        balances = {(1, 1): {"available": 0, "locked": SCALE}}
        r = check_core_internal(balances, {}, ASSETS, 0)
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

    def test_admin_timestamp_archives_with_equal_mtimes(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        paths = {}
        for name, amount, had in [
            ("sim.log.20260908-120000", 15, 0),
            ("sim.log.20260908-130000", 5, 15),
            ("sim.log", 1, 20),
        ]:
            path = os.path.join(d, name)
            with open(path, "w") as fh:
                fh.write(f"bot 1: deposited {amount}.00000000 of asset 0 (had {had}.00000000, target 21.00000000)\n")
            os.utime(path, (1_700_000_000, 1_700_000_000))
            paths[name] = path

        deposits, _, genesis, meta = parse_ledger_log(sorted(paths.values()))
        self.assertEqual(meta["files"], [
            paths["sim.log.20260908-120000"],
            paths["sim.log.20260908-130000"],
            paths["sim.log"],
        ])
        self.assertEqual(deposits, {0: 21 * SCALE})
        self.assertTrue(genesis)


class ArgParsing(unittest.TestCase):
    def test_user_ranges_and_singles(self):
        self.assertEqual(sorted(parse_user_arg("900000-900002,900999")),
                         [900000, 900001, 900002, 900999])

    def test_asset_map_is_symbol_equals_id(self):
        self.assertEqual(parse_asset_map("USD=0,BTC=1"), {"USD": 0, "BTC": 1})


class RetiredFlags(unittest.TestCase):
    """The flags and the --store value retired by the rename to core are refused naming the new ones."""

    REFUSED = [
        (["--ae-dump-cmd", "x"], "the flag --ae-dump-cmd is retired; it is now --cut"),
        (["--ae-dump-cmd=x"], "the flag --ae-dump-cmd is retired; it is now --cut"),
        (["--store", "core", "--core-dump-cmd", "x"], "the flag --core-dump-cmd is retired; it is now --cut"),
        (["--ae-timeout", "5"], "the flag --ae-timeout is retired; it is now --core-timeout"),
        (["--store", "core", "--ae-timeout=5"], "the flag --ae-timeout is retired; it is now --core-timeout"),
        (["--store", "ae"], "--store ae is retired; it is now --store core"),
        (["--store=ae"], "--store ae is retired; it is now --store core"),
    ]

    def test_retired_flags_and_value_are_refused(self):
        for argv, text in self.REFUSED:
            with self.subTest(argv=argv):
                self.assertIn(text, retired_refusal(argv))

    def test_main_exits_64_before_anything_runs(self):
        import contextlib
        import io
        for argv, text in self.REFUSED:
            err = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(err):
                self.assertEqual(main(argv), 64)
            self.assertIn(text, err.getvalue())

    def test_negative_control_new_names_parse(self):
        argv = ["--store", "core", "--cut", "cut.json", "--core-timeout", "5"]
        self.assertIsNone(retired_refusal(argv))
        args = build_arg_parser().parse_args(argv)
        self.assertEqual((args.store, args.cut, args.core_timeout), ("core", "cut.json", 5))


class CoreProgramsFromTheCut(unittest.TestCase):
    """--store core runs CoreDump (tools.core-dump) and the order snapshot reader (harness.core_probe on
    artifacts.core-cluster.jar) from the cut's bytes, re-hashed; no cut, a missing entry or other bytes refuse to run."""

    def setUp(self):
        import hashlib
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.files = {}
        for name in ("core-bridge.jar", "CoreProbe.jar", "core-cluster.jar"):
            path = os.path.join(self.dir, name)
            with open(path, "wb") as fh:
                fh.write(name.encode())
            self.files[name] = {"path": path, "sha256": hashlib.sha256(name.encode()).hexdigest()}
        self.doc = {"cut_id": "dev-cut-1",
                    "tools": {"core-dump": dict(self.files["core-bridge.jar"], main=core_expected.CORE_DUMP_MAIN)},
                    "harness": {"core_probe": self.files["CoreProbe.jar"]},
                    "artifacts": {"core-cluster.jar": self.files["core-cluster.jar"]}}

    def tearDown(self):
        self.tmp.cleanup()

    def cut(self, doc):
        path = os.path.join(self.dir, "cut.json")
        with open(path, "w") as fh:
            json.dump(doc, fh)
        return path

    def test_the_programs_are_the_cut_jars(self):
        dump, probe = core_expected.cut_programs(self.cut(self.doc), java=("java",))
        self.assertEqual(dump, ["java", "-cp", self.files["core-bridge.jar"]["path"], core_expected.CORE_DUMP_MAIN])
        self.assertEqual(probe, ["java", "-cp", f'{self.files["CoreProbe.jar"]["path"]}:{self.files["core-cluster.jar"]["path"]}',
                                 "CoreProbe", "order-dump"])
        dump, _ = core_expected.cut_programs(self.cut(self.doc))
        self.assertEqual(dump[:2], ["java", "--add-opens"])

    def test_an_artifact_root_keeps_the_names_and_the_digests(self):
        other = os.path.join(self.dir, "box")
        os.mkdir(other)
        for name in self.files:
            shutil.copyfile(self.files[name]["path"], os.path.join(other, name))
        dump, _ = core_expected.cut_programs(self.cut(self.doc), other, java=("java",))
        self.assertEqual(dump[2], os.path.join(other, "core-bridge.jar"))
        with open(os.path.join(other, "core-bridge.jar"), "ab") as fh:
            fh.write(b"x")
        with self.assertRaisesRegex(core_expected.OperationalError, "hashes to .* the cut pins"):
            core_expected.cut_programs(self.cut(self.doc), other)

    def test_no_cut_no_entry_or_other_bytes_refuse(self):
        E = core_expected.OperationalError
        with self.assertRaisesRegex(E, "needs --cut MANIFEST"):
            core_expected.cut_programs(None)
        with self.assertRaisesRegex(E, "not a readable cut manifest"):
            core_expected.cut_programs(os.path.join(self.dir, "missing.json"))
        for key, sub, text in (("tools", "core-dump", "names no tools.core-dump jar"),
                               ("harness", "core_probe", "names no harness.core_probe jar"),
                               ("artifacts", "core-cluster.jar", "names no artifacts.core-cluster.jar")):
            doc = json.loads(json.dumps(self.doc))
            del doc[key][sub]
            with self.assertRaisesRegex(E, text):
                core_expected.cut_programs(self.cut(doc))
        doc = json.loads(json.dumps(self.doc))
        doc["tools"]["core-dump"]["main"] = "x"
        with self.assertRaisesRegex(E, "main is 'x'"):
            core_expected.cut_programs(self.cut(doc))

    def test_key_files_must_be_private(self):
        path = os.path.join(self.dir, "admin.key")
        with open(path, "w") as fh:
            fh.write("12:ADMIN:00ff\n")
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(core_expected.OperationalError, "readable by others"):
            core_expected.read_key(path, "--admin-key-file")
        os.chmod(path, 0o600)
        self.assertEqual(core_expected.read_key(path, "--admin-key-file"), "12:ADMIN:00ff")


# --------------------------------------------------------------------------- core expected side over dump fixtures

M = 10 ** 8


def dump_doc(balances, holds, consume=10, trade=5):
    return {"balances": [{"userId": u, "assetId": a, "available": av, "locked": lk} for u, a, av, lk in balances],
            "holds": [{"orderId": o, "userId": u, "assetId": a, "remaining": r} for o, u, a, r in holds],
            "consumePosition": consume, "lastAppliedTradeId": trade}


def order(oid, user, side, price, qty, filled=0, status="NEW", typ="LIMIT", hold_amount=None):
    hold_asset = 0 if side == "BUY" else 1
    if hold_amount is None:
        hold_amount = price * qty // M if side == "BUY" else qty
    return {"order": oid, "user": user, "market": 1, "status": status, "side": side, "type": typ, "tif": "GTC",
            "price": price, "quantity": qty, "filled": filled, "remaining": qty - filled, "stop_price": 0,
            "hold_asset": hold_asset, "hold_amount": hold_amount, "budget": 0}


class Proc:
    def __init__(self, rc, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


class FakeCore:
    """A scripted core behind the two programs: ``states`` is a list of (dump doc, orders) the reads walk through (one
    state per read of each program); ``dump_rc`` overrides CoreDump's exit code."""

    def __init__(self, states, dump_rc=0, timeout=False, by_read=False):
        self.states, self.dump_rc, self.timeout, self.dumps, self.orders = states, dump_rc, timeout, 0, 0
        self.by_read = by_read   # True: the state is a function of the read count over both programs (a moving core)

    def state(self, own):
        i = self.dumps + self.orders if self.by_read else own
        return self.states[min(i, len(self.states) - 1)]

    def run(self, argv, **kw):
        if self.timeout:
            import subprocess
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        if argv[-1] == "order-dump":
            st = self.state(self.orders)
            self.orders += 1
            return Proc(0, json.dumps({"verb": "order-dump", "pages": 1, "count": len(st[1]), "orders": st[1]}) + "\n")
        st = self.state(self.dumps)
        self.dumps += 1
        if self.dump_rc:
            return Proc(self.dump_rc, "", "CoreDump: snapshot incomplete after 30000ms")
        return Proc(0, json.dumps(st[0]))


ENV = {"common": {}, "dump": {}, "probe": {}}
CLEAN = (dump_doc([(1, 0, 900 * M, 100 * M), (2, 1, 5 * M, 5 * M)], [(11, 1, 0, 100 * M), (12, 2, 1, 5 * M)]),
         [order(11, 1, "BUY", 10 * M, 10 * M), order(12, 2, "SELL", 20 * M, 5 * M)])
FUNDING = lambda: ({0: 1000 * M, 1: 10 * M}, {}, None)


def sweep(core, **kw):
    reader = core_expected.CoreReader(["java", "CoreDump"], ["java", "CoreProbe", "order-dump"], ENV, 5, run=core.run)
    logs = []
    kw.setdefault("sleep", lambda s: None)
    result, code = core_expected.sweep(reader, kw.pop("funding", FUNDING), log=logs.append, **kw)
    return result, code, logs


def guard_clean_is_not_unreachable(code):
    """The guard: an unreachable core is never clean."""
    if code == 0:
        raise AssertionError("unreachable core reported as clean")


def guard_timeout_is_operational(code):
    if code == 3:
        raise AssertionError("CoreDump timeout reported as UNSTABLE")


def guard_one_instant(core_consistent_each_instant, code):
    if core_consistent_each_instant and code == 2:
        raise AssertionError("mismatch reported across two instants")


class CoreExpectedSide(unittest.TestCase):
    def test_clean_state_is_green(self):
        result, code, _ = sweep(FakeCore([CLEAN]))
        self.assertEqual(code, 0, json.dumps(result["checks"]))
        self.assertEqual(result["status"], "OK")
        self.assertIn("not the fixture oracle", result["statement"])
        self.assertEqual({c["name"]: c["status"] for c in result["checks"]},
                         {"conservation": "PASS", "locked_vs_holds": "PASS", "holds_live": "PASS", "order_holds": "PASS",
                          "non_negativity": "PASS", "core_counters": "INDETERMINATE"})

    def test_a_hold_on_an_order_that_is_not_live_is_a_residual_hold(self):
        d, orders = CLEAN
        dead = [dict(orders[0], status="CANCELLED", remaining=0), orders[1]]
        result, code, _ = sweep(FakeCore([(d, dead)]))
        self.assertEqual(code, 2)
        texts = [core_expected.residual_text(r) for r in result["residual_holds"]]
        self.assertEqual(texts, [f"residual hold: user 1 asset 0 {100 * M}"])
        print("\ncore expected side, residual hold:", texts[0], "exit", code)

    def test_a_hold_of_a_vanished_order_and_a_live_order_without_hold(self):
        d, orders = CLEAN
        result, code, _ = sweep(FakeCore([(d, orders[1:] + [order(13, 1, "BUY", 1 * M, 1 * M)])]))
        self.assertEqual(code, 2)
        names = {c["name"]: c for c in result["checks"]}
        self.assertEqual(names["holds_live"]["drifts"][0]["orderId"], 11)
        self.assertEqual(names["order_holds"]["drifts"][0]["reason"], "live order without a hold")

    def test_a_live_hold_that_differs_from_the_recomputation(self):
        d = dump_doc([(1, 0, 900 * M, 101 * M), (2, 1, 5 * M, 5 * M)], [(11, 1, 0, 101 * M), (12, 2, 1, 5 * M)])
        result, code, _ = sweep(FakeCore([(d, CLEAN[1])]), funding=lambda: ({0: 1001 * M, 1: 10 * M}, {}, None))
        self.assertEqual(code, 2)
        names = {c["name"]: c["status"] for c in result["checks"]}
        self.assertEqual(names["order_holds"], "FAIL")
        self.assertEqual(names["conservation"], "PASS")

    def test_a_partly_filled_buy_is_bounded_by_its_price_improvement(self):
        # BUY 10 @ 10, 4 filled at 9: the core holds 100 - 36 = 64 > 10 x 6 = 60 (price improvement held to the end)
        o = order(11, 1, "BUY", 10 * M, 10 * M, filled=4 * M, status="PARTIALLY_FILLED")
        d = dump_doc([(1, 0, 900 * M, 64 * M), (1, 1, 4 * M, 0)], [(11, 1, 0, 64 * M)])
        result, code, _ = sweep(FakeCore([(d, [o])]), funding=lambda: ({0: 964 * M, 1: 4 * M}, {}, None))
        self.assertEqual(code, 0, json.dumps(result["checks"]))
        d2 = dump_doc([(1, 0, 900 * M, 59 * M), (1, 1, 4 * M, 0)], [(11, 1, 0, 59 * M)])
        _, code, _ = sweep(FakeCore([(d2, [o])]), funding=lambda: ({0: 959 * M, 1: 4 * M}, {}, None))
        self.assertEqual(code, 2)   # below price x remaining: under-collateralized

    def test_conservation_against_the_money_history(self):
        _, code, _ = sweep(FakeCore([CLEAN]), funding=lambda: ({0: 1000 * M, 1: 10 * M}, {0: 1 * M}, None))
        self.assertEqual(code, 2)

    def test_a_money_history_behind_the_core_is_not_judged(self):
        counters = lambda: {"m0": {"core_pending_commands": 0, "core_release_backlog": 0, "core_journal_seq": 9}}
        result, code, _ = sweep(FakeCore([CLEAN]), funding=lambda: ({0: 1 * M}, {}, 7), counters_source=counters)
        names = {c["name"]: c for c in result["checks"]}
        self.assertEqual((code, names["conservation"]["status"]), (0, "INDETERMINATE"))
        self.assertIn("journal 7 of 9", names["conservation"]["reason"])
        self.assertEqual(names["core_counters"]["status"], "PASS")
        _, code, _ = sweep(FakeCore([CLEAN]), funding=lambda: ({0: 1 * M}, {}, 9), counters_source=counters)
        self.assertEqual(code, 2)     # at the head the gap is judged

    def test_zero_hold_users(self):
        result, code, _ = sweep(FakeCore([CLEAN]), zero_users=[(2, 2)])
        self.assertEqual(code, 2)
        self.assertEqual([core_expected.residual_text(r) for r in result["residual_holds"]],
                         [f"residual hold: user 2 asset 1 {5 * M}"])

    def test_live_traffic_is_unstable_then_stable(self):
        moving = [(dump_doc([(1, 0, 900 * M - i, 100 * M)], [(11, 1, 0, 100 * M)]), CLEAN[1][:1]) for i in range(5)]
        still = [(dump_doc([(1, 0, 900 * M, 100 * M)], [(11, 1, 0, 100 * M)]), CLEAN[1][:1])]
        result, code, logs = sweep(FakeCore(moving + still * 10), funding=lambda: ({0: 1000 * M}, {}, None), retries=5)
        unstable = [l for l in logs if l.startswith("UNSTABLE")]
        self.assertGreaterEqual(len(unstable), 2, logs)
        self.assertEqual((code, result["status"]), (0, "OK"))
        print("\ncore expected side, live traffic:", len(unstable), "UNSTABLE attempts, then", result["status"])

    def test_unstable_to_the_end_exits_3(self):
        moving = [(dump_doc([(1, 0, i, 0)], []), []) for i in range(100)]
        result, code, logs = sweep(FakeCore(moving), funding=lambda: ({}, {}, None), retries=3)
        self.assertEqual((code, result["status"], len(logs)), (3, "UNSTABLE", 3))

    def test_coredump_exit_3_is_an_operational_error_never_unstable(self):
        with self.assertRaisesRegex(core_expected.OperationalError, "^CoreDump timeout"):
            sweep(FakeCore([CLEAN], dump_rc=3))
        with self.assertRaisesRegex(core_expected.OperationalError, "^CoreDump timeout"):
            sweep(FakeCore([CLEAN], timeout=True))

    def test_main_maps_an_unreachable_core_to_1(self):
        import contextlib
        import io
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        keys = []
        for name in ("tool", "admin"):
            p = os.path.join(tmp.name, name)
            with open(p, "w") as fh:
                fh.write("1:TOOL:00\n")
            os.chmod(p, 0o600)
            keys.append(p)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["--store", "core", "--tool-key-file", keys[0], "--admin-key-file", keys[1], "--cut",
                         os.path.join(tmp.name, "missing.json")])
        self.assertEqual(code, 1)
        guard_clean_is_not_unreachable(code)
        self.assertIn("operational error", err.getvalue())

    def test_oms_flags_are_refused_with_the_core_store(self):
        import contextlib
        import io
        for argv in (["--store", "core", "--oms-url", "http://127.0.0.1:9"], ["--store=core", "--sim-log", "x"]):
            err = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(err):
                self.assertEqual(main(argv), 64)
            self.assertIn("has no meaning with --store core", err.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main(["--store", "nope"]), 64)   # a usage error is 64, never 2

    def test_a_read_killed_at_the_bound_leaves_no_driver_directory(self):
        import subprocess
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pidfile = os.path.join(tmp.name, "pid")
        script = ("import os,time; os.makedirs('/dev/shm/aeron-aedump-%d' % os.getpid()); "
                  f"open({pidfile!r}, 'w').write(str(os.getpid())); time.sleep(30)")
        with self.assertRaises(subprocess.TimeoutExpired):
            core_expected.run_child([sys.executable, "-c", script], timeout=2)
        with open(pidfile) as fh:
            pid = fh.read()
        self.assertFalse(os.path.exists(f"/dev/shm/aeron-aedump-{pid}"))

    # ---- the three controls: each switches a rule off in a test copy and must fail with its text

    def test_control_stability_reduced_to_the_markers(self):
        # Every instant is consistent (state a, then state b: order 12 cancelled, its hold released), the content
        # moves between the third and the fourth read while the markers stay equal: the reduced check judges the dump of
        # one instant against the orders of another.
        a = CLEAN
        b = (dump_doc([(1, 0, 900 * M, 100 * M), (2, 1, 10 * M, 0)], [(11, 1, 0, 100 * M)]),
             [order(11, 1, "BUY", 10 * M, 10 * M), order(12, 2, "SELL", 20 * M, 5 * M, status="CANCELLED")])
        states = [a, a, a] + [b] * 20
        _, code, _ = sweep(FakeCore(states, by_read=True))
        self.assertEqual(code, 0)
        guard_one_instant(True, code)   # the product check: content stability, no mismatch
        _, reduced, _ = sweep(FakeCore(states, by_read=True), stable=core_expected.markers_stable)
        with self.assertRaises(AssertionError) as caught:
            guard_one_instant(True, reduced)
        self.assertEqual(str(caught.exception), "mismatch reported across two instants")
        print("\nCONTROL stability reduced to the markers ->", caught.exception)

    def test_control_unreachable_mapped_to_clean(self):
        def sweep_copy():
            try:
                sweep(FakeCore([CLEAN], timeout=True))
            except core_expected.OperationalError:
                return 0    # the planted mistake: an unreachable core read as clean
            return 1
        with self.assertRaises(AssertionError) as caught:
            guard_clean_is_not_unreachable(sweep_copy())
        self.assertEqual(str(caught.exception), "unreachable core reported as clean")
        print("\nCONTROL unreachable mapped to clean ->", caught.exception)

    def test_control_coredump_exit_3_passed_through(self):
        def sweep_copy():
            core = FakeCore([CLEAN], dump_rc=3)
            p = core.run(["java", "CoreDump"])
            return p.returncode     # the planted mistake: CoreDump's own exit code passed through
        with self.assertRaises(AssertionError) as caught:
            guard_timeout_is_operational(sweep_copy())
        self.assertEqual(str(caught.exception), "CoreDump timeout reported as UNSTABLE")
        print("\nCONTROL CoreDump exit 3 passed through ->", caught.exception)


if __name__ == "__main__":
    unittest.main()
