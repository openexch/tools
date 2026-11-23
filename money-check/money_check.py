#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""money_check.py -- the live-money guardrail for the Open Exchange cutover soak.

Reconciles the money ledger against three invariants that must hold at all times.
It is READ-ONLY: it never issues a write to Redis, the core, or the OMS.

  INVARIANT 1 -- per-asset conservation (deposit-aware)
      For every asset:  Sigma_users (available + locked)  ==  Sigma deposits - Sigma withdrawals
      The simulator re-seeds bots toward a target every ~3 min, so the right-hand
      side grows over time. We recover it by parsing the "deposited ..." lines out
      of the sim log (see --sim-log). Trading only moves value *within* an asset
      (base seller->buyer, quote buyer->seller) so it never changes an asset's total;
      only deposits/withdrawals do. If the log does not reach genesis we cannot assert
      an absolute total, so the check reports INDETERMINATE rather than a false breach.

  INVARIANT 2 -- locked == sum of open-order holds
      The AUTHORITATIVE expected locked comes from the OMS open-orders API, never from
      the Redis holds:{u} hash (that hash is write-only and leaks on settle -- a trap).
        BUY  order locks the QUOTE asset:  price * remainingQty        (residual quote hold)
        SELL order locks the BASE  asset:  remainingQty                (base units)
      Amend caveat: after an amend the OMS's stored holdAmount nets filled qty; the OMS
      does not expose holdAmount on the order, so we use price*remainingQty. For an order
      with fills at a price other than its limit, that residual can differ from the core's
      netted hold by a rounding tick -- treated as explainable drift, not a hard breach.

  INVARIANT 3 -- non-negativity
      No available < 0 and no locked < 0, ever.

Stores:
  --store redis (default)  read Redis db0 directly (bal:{userId} hashes); the expected side is the v0.5 OMS.
  --store core             the core expected side (core_expected.py): the ledger from CoreDump and the expected holds
                           from the core's own order snapshot, both run from the release cut's jars (--cut MANIFEST,
                           re-hashed against it); funding from the money history. No OMS. The OMS and sim-log flags are
                           refused with this store (exit 64).

Exit codes:  0 = all green (--store core: every check judged and passed)   2 = an invariant was violated
             1 = operational error (core unreachable, a missing setting, CoreDump timeout: CoreDump's own exit 3 is
             mapped here, never to 3)   3 = UNSTABLE: the core's content kept moving through every stable-read attempt
             (--store core)   4 = INDETERMINATE: nothing violated, and at least one check could not be judged, so the
             sweep is not green (--store core)
             64 = a retired flag or value (--ae-dump-cmd, --core-dump-cmd, --ae-timeout, --store ae), a flag that has no
                  meaning with --store core, or any other usage error: the line names it.
"""

import argparse
import glob
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core_expected  # noqa: E402

SCALE = 10 ** 8  # all amounts are 8dp fixed-point int64

# Default asset symbol -> assetId map. This mirrors the engine's MarketConfig as
# carried by the market-sim DefaultMarkets table (USD is asset 0; base ids 1..5).
# Override with --asset-map "USD=0,BTC=1,..." if a deployment renumbers assets.
DEFAULT_ASSET_MAP = {"USD": 0, "BTC": 1, "ETH": 2, "SOL": 3, "XRP": 4, "DOGE": 5}

TERMINAL_STATUSES = {"FILLED", "CANCELED", "CANCELLED", "REJECTED", "EXPIRED", "DONE"}


# --------------------------------------------------------------------------- #
# fixed-point helpers
# --------------------------------------------------------------------------- #
def parse_fixed(s):
    """Parse a decimal string ("99182.00000000") into an 8dp int. Ints pass through."""
    if s is None:
        return 0
    s = str(s).strip()
    if s == "":
        return 0
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    if "." in s:
        whole, frac = s.split(".", 1)
    else:
        whole, frac = s, ""
    frac = (frac + "0" * 8)[:8]
    val = int(whole or "0") * SCALE + int(frac or "0")
    return -val if neg else val


def fmt_fixed(v):
    """Render an 8dp int as a signed decimal string for human reports."""
    neg = v < 0
    v = abs(v)
    s = f"{v // SCALE}.{v % SCALE:08d}"
    return ("-" if neg else "") + s


# --------------------------------------------------------------------------- #
# minimal, zero-dependency Redis (RESP) client
#   Uses only the stdlib. If the `redis` package happens to be installed we use
#   it instead, but nothing here requires a pip install.
# --------------------------------------------------------------------------- #
class RedisError(Exception):
    pass


class _RespClient:
    """Just enough RESP to SELECT, SCAN and HGETALL, read-only."""

    def __init__(self, host, port, db, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.f = self.sock.makefile("rb")
        self._command(b"SELECT", str(db).encode())

    def _command(self, *args):
        out = [b"*%d\r\n" % len(args)]
        for a in args:
            if isinstance(a, str):
                a = a.encode()
            out.append(b"$%d\r\n%s\r\n" % (len(a), a))
        self.sock.sendall(b"".join(out))
        return self._read_reply()

    def _read_reply(self):
        line = self.f.readline()
        if not line:
            raise RedisError("connection closed by redis")
        t, body = line[:1], line[1:-2]
        if t == b"+":
            return body.decode()
        if t == b"-":
            raise RedisError(body.decode())
        if t == b":":
            return int(body)
        if t == b"$":
            n = int(body)
            if n == -1:
                return None
            data = self.f.read(n)
            self.f.read(2)  # trailing CRLF
            return data
        if t == b"*":
            n = int(body)
            if n == -1:
                return None
            return [self._read_reply() for _ in range(n)]
        raise RedisError(f"unexpected RESP type {t!r}")

    def scan_keys(self, match):
        cursor = b"0"
        first = True
        keys = []
        while first or cursor != b"0":
            first = False
            cursor, batch = self._command(b"SCAN", cursor, b"MATCH", match, b"COUNT", b"1000")
            keys.extend(k.decode() for k in batch)
        return keys

    def hgetall(self, key):
        flat = self._command(b"HGETALL", key)
        out = {}
        for i in range(0, len(flat), 2):
            out[flat[i].decode()] = flat[i + 1].decode()
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class _PkgClient:
    """Adapter over the `redis` package, if present."""

    def __init__(self, host, port, db, timeout=5.0):
        import redis  # type: ignore
        self.r = redis.Redis(host=host, port=port, db=db, socket_timeout=timeout,
                             decode_responses=True)

    def scan_keys(self, match):
        return list(self.r.scan_iter(match=match, count=1000))

    def hgetall(self, key):
        return self.r.hgetall(key)

    def close(self):
        try:
            self.r.close()
        except Exception:
            pass


def make_redis(host, port, db, timeout=5.0):
    try:
        import redis  # noqa: F401
        return _PkgClient(host, port, db, timeout)
    except Exception:
        return _RespClient(host, port, db, timeout)


# --------------------------------------------------------------------------- #
# stores -- both yield the same shape:
#   balances : { (userId:int, assetId:int) : {"available": int, "locked": int} }
#   holds    : { (userId:int, assetId:int) : int }   (core only; None for redis)
#   position : { "consumePosition": int|None, "lastAppliedTradeId": int|None }
# --------------------------------------------------------------------------- #
def load_redis_store(host, port, db):
    r = make_redis(host, port, db)
    try:
        balances = {}
        for key in r.scan_keys("bal:*"):
            try:
                uid = int(key.split(":", 1)[1])
            except ValueError:
                continue
            h = r.hgetall(key)
            per_asset = defaultdict(lambda: {"available": 0, "locked": 0})
            for field, val in h.items():
                if ":" not in field:
                    continue
                kind, asset = field.split(":", 1)
                try:
                    asset = int(asset)
                    v = int(val)
                except ValueError:
                    continue
                if kind == "avail":
                    per_asset[asset]["available"] = v
                elif kind == "locked":
                    per_asset[asset]["locked"] = v
            for asset, rec in per_asset.items():
                balances[(uid, asset)] = rec
        return {"balances": balances, "holds": None,
                "position": {"consumePosition": None, "lastAppliedTradeId": None}}
    finally:
        r.close()


# --------------------------------------------------------------------------- #
# sim.log deposit/withdrawal parser (invariant 1's right-hand side)
# --------------------------------------------------------------------------- #
DEPOSIT_RE = re.compile(
    r"deposited\s+(-?\d+(?:\.\d+)?)\s+of\s+asset\s+(\d+)\s+\(had\s+(-?\d+(?:\.\d+)?)")
WITHDRAW_RE = re.compile(
    r"(?:withdrew|withdrawn)\s+(-?\d+(?:\.\d+)?)\s+of\s+asset\s+(\d+)")
ROTATION_SUFFIX_RE = re.compile(r"\.(\d+)$")
TIMESTAMP_ROTATION_SUFFIX_RE = re.compile(r"\.(\d{8}-\d{6})$")


def _chronological_key(path):
    """Oldest-first sort key for rotated logs: mtime, then rotation index.

    mtimes can tie (coarse filesystem granularity, rapid successive
    rotations), and the caller hands over a lexicographically sorted glob,
    so a stable sort on mtime alone would silently keep that newest-first
    order. Larger ".N" suffixes are older archives, so they sort before
    smaller ones and before the live file (no suffix). The path itself is
    only a final tie-break to keep the ordering total and independent of
    input order.
    """
    timestamp = TIMESTAMP_ROTATION_SUFFIX_RE.search(path)
    if timestamp:
        return (os.path.getmtime(path), 0, timestamp.group(1), path)

    numeric = ROTATION_SUFFIX_RE.search(path)
    if numeric:
        return (os.path.getmtime(path), 1, -int(numeric.group(1)), path)

    return (os.path.getmtime(path), 2, 0, path)


def parse_ledger_log(paths):
    """Sum deposits/withdrawals per asset from the sim log(s).

    Returns (deposits, withdrawals, genesis_covered, meta).
      genesis_covered is True only if, for every asset seen, the FIRST deposit line
      had "had 0" -- i.e. the log reaches the clean-slate seeding. When False we
      cannot assert an absolute total and invariant 1 becomes INDETERMINATE.
    """
    deposits = defaultdict(int)
    withdrawals = defaultdict(int)
    first_had = {}
    lines_seen = 0
    files_used = []
    # Consume the logs oldest first: genesis coverage keys on the FIRST deposit
    # line per asset, so rotated logs must be read chronologically. Sorting the
    # paths alphabetically is newest-first under the usual "sim.log, sim.log.1,
    # ..." rotation names (the live file sorts ahead of its archives, and
    # "sim.log.10" before "sim.log.2"); modification time is naming-scheme
    # independent, with the rotation index as a deterministic tie-break.
    existing = [p for p in paths if os.path.exists(p)]
    existing.sort(key=_chronological_key)
    for path in existing:
        files_used.append(path)
        with open(path, "r", errors="replace") as fh:
            for ln in fh:
                lines_seen += 1
                m = DEPOSIT_RE.search(ln)
                if m:
                    amt = parse_fixed(m.group(1))
                    asset = int(m.group(2))
                    deposits[asset] += amt
                    if asset not in first_had:
                        first_had[asset] = parse_fixed(m.group(3))
                    continue
                w = WITHDRAW_RE.search(ln)
                if w:
                    withdrawals[int(w.group(2))] += parse_fixed(w.group(1))
    genesis_covered = bool(first_had) and all(v == 0 for v in first_had.values())
    meta = {"files": files_used, "lines": lines_seen,
            "assets_seen": sorted(first_had.keys()),
            "first_had_nonzero": [a for a, v in first_had.items() if v != 0]}
    return dict(deposits), dict(withdrawals), genesis_covered, meta


# --------------------------------------------------------------------------- #
# OMS open orders -> authoritative expected locked (invariant 2)
# --------------------------------------------------------------------------- #
def parse_extra_deposits(path, asset_map=None):
    """Sum manual deposits (ts/user/asset/amount) from a FILE into per-asset totals.

    Accepts JSON (a list of objects with keys ts/user/asset/amount, or an object
    keyed by asset) or whitespace/comma-delimited lines. Asset may be a numeric
    id or a symbol resolvable through asset_map.
    """
    asset_map = asset_map or {}
    totals = defaultdict(int)
    if not path:
        return {}
    with open(os.path.expanduser(path), "r", errors="replace") as fh:
        raw = fh.read().strip()
    if not raw:
        return {}
    # JSON first
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        data = None
    records = []
    if isinstance(data, list):
        for row in data:
            records.append((row.get("asset"), row.get("amount")))
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, dict):
                records.append((k, v.get("amount")))
            else:
                records.append((k, v))
    else:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = [p.strip() for p in ln.replace(",", " ").split()]
            if len(parts) < 4:
                continue
            # ts user asset amount
            records.append((parts[2], parts[3]))
    for asset, amt in records:
        if asset is None or amt is None:
            continue
        s = str(asset).strip()
        if s.isdigit():
            aid = int(s)
        else:
            aid = asset_map.get(s)
            if aid is None:
                continue
        totals[aid] += parse_fixed(amt)
    return dict(totals)


def http_get_json(url, bearer, timeout):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_markets(base_url, asset_map, timeout, bearer_user):
    """marketId -> (base_assetId, quote_assetId), resolved via the asset symbol map."""
    data = http_get_json(base_url.rstrip("/") + "/api/v1/markets", f"dev:{bearer_user}", timeout)
    out = {}
    unknown = set()
    for m in data:
        b = asset_map.get(m["baseAsset"])
        q = asset_map.get(m["quoteAsset"])
        if b is None:
            unknown.add(m["baseAsset"])
        if q is None:
            unknown.add(m["quoteAsset"])
        out[int(m["marketId"])] = (b, q)
    if unknown:
        raise RuntimeError(f"OMS markets reference asset symbols not in the asset map: "
                          f"{sorted(unknown)} -- pass --asset-map to define them")
    return out


def expected_locked_for_user(orders, markets):
    """Per-asset expected locked from one user's open orders. Returns (per_asset, n_open, n_unpriced)."""
    exp = defaultdict(int)
    n_open = 0
    n_unpriced = 0
    for o in orders:
        rem = parse_fixed(o.get("remainingQty", "0"))
        status = str(o.get("status", "")).upper()
        if rem <= 0 or status in TERMINAL_STATUSES:
            continue
        n_open += 1
        base, quote = markets.get(int(o["marketId"]), (None, None))
        if base is None or quote is None:
            continue
        if o.get("side") == "BUY":
            price = parse_fixed(o.get("price", "0"))
            if price <= 0:
                n_unpriced += 1  # market/unpriced BUY: cannot derive a quote hold from qty alone
                continue
            exp[quote] += price * rem // SCALE
        else:  # SELL locks base units
            exp[base] += rem
    return dict(exp), n_open, n_unpriced


def collect_oms_expected(base_url, user_ids, markets, timeout):
    """Query the OMS per user; return ((uid,asset)->expected_locked, stats)."""
    expected = {}
    stats = {"users_queried": 0, "users_error": 0, "open_orders": 0, "unpriced": 0}
    for uid in user_ids:
        try:
            orders = http_get_json(base_url.rstrip("/") + "/api/v1/orders",
                                    f"dev:{uid}", timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout):
            stats["users_error"] += 1
            continue
        stats["users_queried"] += 1
        per_asset, n_open, n_unpriced = expected_locked_for_user(orders, markets)
        stats["open_orders"] += n_open
        stats["unpriced"] += n_unpriced
        for asset, amt in per_asset.items():
            expected[(uid, asset)] = expected.get((uid, asset), 0) + amt
    return expected, stats


# --------------------------------------------------------------------------- #
# the three checks -- each returns a result dict
# --------------------------------------------------------------------------- #
def asset_name(asset_map, asset_id):
    for sym, aid in asset_map.items():
        if aid == asset_id:
            return sym
    return f"#{asset_id}"


def check_conservation(balances, deposits, withdrawals, genesis_covered, asset_map, tol):
    per_asset = defaultdict(int)
    for (uid, asset), rec in balances.items():
        per_asset[asset] += rec["available"] + rec["locked"]
    drifts = []
    assets = sorted(set(per_asset) | set(deposits) | set(withdrawals))
    for a in assets:
        actual = per_asset.get(a, 0)
        expected = deposits.get(a, 0) - withdrawals.get(a, 0)
        gap = actual - expected
        if abs(gap) > tol:
            drifts.append({"scope": "asset", "userId": None, "assetId": a,
                          "asset": asset_name(asset_map, a),
                          "expected": expected, "actual": actual, "gap": gap})
    if not genesis_covered:
        return {"name": "conservation", "status": "INDETERMINATE",
                "reason": "sim log does not reach genesis (had!=0 on first deposit); "
                          "cannot assert an absolute per-asset total",
                "drifts": []}
    return {"name": "conservation", "status": "PASS" if not drifts else "FAIL",
            "drifts": drifts}


def check_locked(balances, expected, asset_map, tol, have_oms):
    if not have_oms:
        return {"name": "locked_vs_holds", "status": "SKIP",
                "reason": "OMS unreachable; cannot compute authoritative expected locked",
                "drifts": []}
    drifts = []
    keys = set(k for k, rec in balances.items() if rec["locked"] != 0) | set(expected.keys())
    for (uid, asset) in keys:
        actual = balances.get((uid, asset), {"locked": 0})["locked"]
        exp = expected.get((uid, asset), 0)
        gap = actual - exp
        if abs(gap) > tol:
            drifts.append({"scope": "user", "userId": uid, "assetId": asset,
                          "asset": asset_name(asset_map, asset),
                          "expected": exp, "actual": actual, "gap": gap})
    return {"name": "locked_vs_holds", "status": "PASS" if not drifts else "FAIL",
            "drifts": drifts}


def check_nonnegative(balances, asset_map):
    drifts = []
    for (uid, asset), rec in balances.items():
        for kind in ("available", "locked"):
            if rec[kind] < 0:
                drifts.append({"scope": "user", "userId": uid, "assetId": asset,
                              "asset": asset_name(asset_map, asset),
                              "field": kind, "expected": 0, "actual": rec[kind],
                              "gap": rec[kind]})
    return {"name": "non_negativity", "status": "PASS" if not drifts else "FAIL",
            "drifts": drifts}


def check_core_internal(balances, holds, asset_map, tol):
    """Core-mode bonus: the core's own hold entries must sum to its own locked balances."""
    if holds is None:
        return None
    drifts = []
    keys = set(k for k, rec in balances.items() if rec["locked"] != 0) | set(holds.keys())
    for (uid, asset) in keys:
        actual = balances.get((uid, asset), {"locked": 0})["locked"]
        hsum = holds.get((uid, asset), 0)
        gap = actual - hsum
        if abs(gap) > tol:
            drifts.append({"scope": "user", "userId": uid, "assetId": asset,
                          "asset": asset_name(asset_map, asset),
                          "expected": hsum, "actual": actual, "gap": gap})
    return {"name": "core_holds_vs_locked", "status": "PASS" if not drifts else "FAIL",
            "drifts": drifts}


# --------------------------------------------------------------------------- #
# one sweep
# --------------------------------------------------------------------------- #
def run_sweep(args, asset_map):
    t0 = time.time()
    result = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "checks": [], "error": None}

    # 1. load the store
    store = load_redis_store(args.redis_host, args.redis_port, args.redis_db)
    balances = store["balances"]
    result["position"] = store["position"]

    # 2. deposits from the sim log
    log_paths = []
    for p in args.sim_log:
        log_paths.extend(sorted(glob.glob(os.path.expanduser(p))) or [os.path.expanduser(p)])
    deposits, withdrawals, genesis_covered, log_meta = parse_ledger_log(log_paths)
    if args.extra_deposits:
        extra = parse_extra_deposits(args.extra_deposits, asset_map)
        for a, amt in extra.items():
            deposits[a] = deposits.get(a, 0) + amt
    result["log_meta"] = log_meta

    # 3. OMS expected locked
    user_ids = sorted(set(uid for (uid, _a) in balances.keys()))
    if args.users:
        user_ids = parse_user_arg(args.users)
    have_oms = True
    oms_stats = {}
    expected = {}
    try:
        bearer_user = 1
        if user_ids:
            sim = [u for u in user_ids if 900001 <= u <= 900999]
            if sim:
                bearer_user = sim[0]
            elif 1 in user_ids:
                bearer_user = 1
            else:
                bearer_user = user_ids[0]
        markets = load_markets(args.oms_url, asset_map, args.http_timeout, bearer_user)
        expected, oms_stats = collect_oms_expected(args.oms_url, user_ids, markets, args.http_timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout, RuntimeError) as e:
        have_oms = False
        oms_stats = {"error": str(e)}
    result["oms_stats"] = oms_stats

    # 4. checks
    result["checks"].append(check_conservation(balances, deposits, withdrawals,
                                              genesis_covered, asset_map, args.tolerance))
    result["checks"].append(check_locked(balances, expected, asset_map, args.tolerance, have_oms))
    result["checks"].append(check_nonnegative(balances, asset_map))
    core_internal = check_core_internal(balances, store["holds"], asset_map, args.tolerance)
    if core_internal is not None:
        result["checks"].append(core_internal)

    result["accounts"] = len(set(uid for (uid, _a) in balances.keys()))
    result["balance_rows"] = len(balances)
    result["duration_ms"] = int((time.time() - t0) * 1000)
    result["violated"] = any(c["status"] == "FAIL" for c in result["checks"])
    result["indeterminate"] = any(c["status"] in ("INDETERMINATE", "SKIP") for c in result["checks"])
    return result


def parse_user_arg(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return out


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def print_human(result, verbose):
    tag = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "SKIP",
           "INDETERMINATE": "INDET"}
    print(f"[{result['ts']}] store sweep: {result['accounts']} accounts, "
          f"{result['balance_rows']} balance rows, {result['duration_ms']}ms")
    pos = result.get("position", {})
    if pos.get("consumePosition") is not None:
        print(f"   core position: consume={pos['consumePosition']} "
              f"lastAppliedTradeId={pos['lastAppliedTradeId']}")
    for c in result["checks"]:
        line = f"   {tag.get(c['status'], c['status']):<5} {c['name']}"
        if c.get("reason"):
            line += f"  ({c['reason']})"
        n = len(c.get("drifts", []))
        if n:
            line += f"  [{n} drift(s)]"
        print(line)
        for d in c.get("drifts", [])[: (10 ** 9 if verbose else 20)]:
            who = f"user={d['userId']}" if d.get("userId") is not None else "GLOBAL"
            print(f"        DRIFT {who} asset={d['asset']}({d['assetId']}) "
                  f"expected={d['expected']} actual={d['actual']} "
                  f"gap={d['gap']:+d} (={fmt_fixed(d['gap'])})")
    oms = result.get("oms_stats", {})
    if oms.get("error"):
        print(f"   OMS: UNREACHABLE ({oms['error'][:160]})")
    elif oms:
        print(f"   OMS: {oms.get('users_queried', 0)} users, {oms.get('open_orders', 0)} open orders"
              + (f", {oms['users_error']} query errors" if oms.get("users_error") else "")
              + (f", {oms['unpriced']} unpriced" if oms.get("unpriced") else ""))


def status_line(result, sweep_no, rolling):
    checks = " ".join(f"{c['name'][:4]}={c['status'][0]}" for c in result["checks"])
    state = "FAIL" if result["violated"] else ("INDET" if result["indeterminate"] else "OK")
    return (f"[{result['ts']}] sweep#{sweep_no} {state:<5} {checks} "
            f"acct={result['accounts']} {result['duration_ms']}ms "
            f"violations={rolling}")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def build_arg_parser():
    p = _Parser(description="Live-money guardrail for the Open Exchange cutover soak.")
    p.add_argument("--store", choices=["redis", "core"], default="redis",
                  help="ledger source: redis (default) or core (via CoreDump)")
    p.add_argument("--oms-url", default="http://localhost:8080",
                  help="OMS base URL for the open-orders API (default %(default)s)")
    p.add_argument("--sim-log", action="append",
                  default=None, help="sim log path(s)/glob(s) for deposits "
                                     "(default ~/.local/log/cluster/sim.log)")
    p.add_argument("--redis-host", default="127.0.0.1")
    p.add_argument("--redis-port", type=int, default=6379)
    p.add_argument("--redis-db", type=int, default=0)
    p.add_argument("--cut", default=None, metavar="MANIFEST",
                  help="release cut manifest; --store core runs CoreDump (tools.core-dump) and the order snapshot reader "
                       "(harness.core_probe on artifacts.core-cluster.jar) from its jars (required)")
    p.add_argument("--artifact-root", default=None, metavar="DIR",
                  help="core: the directory the cut's jars were copied to (file names and sha256 stay the cut's)")
    p.add_argument("--core-timeout", type=int, default=40,
                  help="seconds to wait for each core read (CoreDump's own deadline is 30s)")
    p.add_argument("--core-addresses", default=None, help="core: the members' hosts, comma list in member order")
    p.add_argument("--core-port-base", type=int, default=None, help="core: the cluster port base")
    p.add_argument("--core-port-stride", type=int, default=100, help="core: the port stride per member (default 100)")
    p.add_argument("--local-host", default=None, help="core: this machine's address the core replies to")
    p.add_argument("--driver-mode", choices=["embedded", "external"], default=None,
                  help="core: the media driver of the two reads (required): embedded or external (with --aeron-dir)")
    p.add_argument("--aeron-dir", default=None, help="core: the external aeronmd's directory (external mode only)")
    p.add_argument("--tool-key-file", default=None, help="core: TOOL credential file for CoreDump (mode 600)")
    p.add_argument("--admin-key-file", default=None, help="core: ADMIN credential file for the order snapshot (mode 600)")
    p.add_argument("--money-history-dsn", default=None,
                  help="core: PostgreSQL connection string of the money history database (the funding source)")
    p.add_argument("--funding-file", default=None,
                  help="core: per-asset deposits and withdrawals written from the money history, instead of the DSN")
    p.add_argument("--psql", default="psql", help="core: the psql program (default psql)")
    p.add_argument("--java", default="java", help="core: the java program the two reads run with (default java)")
    p.add_argument("--jvm-opt", action="append", default=None,
                  help="core: a JVM option of the two reads, repeatable; replaces the default --add-opens set")
    p.add_argument("--core-metrics", default=None,
                  help="core: comma list of member /metrics URLs (required): checks core_pending_commands and "
                       "core_release_backlog, and reads the money journal head conservation is judged at")
    p.add_argument("--zero-hold-users", default=None,
                  help="core: users that must hold nothing at all, e.g. 900000-900999 (the simulator's own)")
    p.add_argument("--stable-retries", type=int, default=int(os.environ.get("MONEY_CHECK_STABLE_RETRIES", 5)),
                  help="core: stable-read attempts before UNSTABLE (default 5, MONEY_CHECK_STABLE_RETRIES)")
    p.add_argument("--stable-wait-ms", type=int, default=int(os.environ.get("MONEY_CHECK_STABLE_WAIT_MS", 1000)),
                  help="core: wait between attempts (default 1000, MONEY_CHECK_STABLE_WAIT_MS)")
    p.add_argument("--asset-map", default=None,
                  help='override symbol->id map, e.g. "USD=0,BTC=1,ETH=2,SOL=3,XRP=4,DOGE=5"')
    p.add_argument("--users", default=None,
                  help="restrict OMS reconciliation to these users, e.g. 900000-900999,900999")
    p.add_argument("--tolerance", type=int, default=0,
                  help="per-row absolute gap (8dp int) tolerated before flagging (default 0)")
    p.add_argument("--http-timeout", type=float, default=5.0)
    p.add_argument("--loop", type=int, default=None, metavar="SECONDS",
                  help="run continuously, one sweep every SECONDS; Ctrl-C to stop")
    p.add_argument("--max-sweeps", type=int, default=None,
                  help="stop after N sweeps (for bounded soak runs)")
    p.add_argument("--json", action="store_true", help="emit one JSON object per sweep")
    p.add_argument("--verbose", action="store_true", help="print every drift, not the first 20")
    p.add_argument("--extra-deposits", default=None,
                  help="FILE of manual deposits (ts user asset amount) to add to the sim-log ledger")
    return p


def parse_asset_map(spec):
    if not spec:
        return dict(DEFAULT_ASSET_MAP)
    out = {}
    for part in spec.split(","):
        sym, aid = part.split("=")
        out[sym.strip()] = int(aid)
    return out


# The flags and values retired by the rename of the engine to core, old to new. A command line that still uses one was
# written for the old names: it is refused naming the new one before anything runs (no alias, no fallback).
RETIRED_FLAGS = {"--ae-dump-cmd": "--cut", "--core-dump-cmd": "--cut", "--ae-timeout": "--core-timeout"}
RETIRED_STORE = {"ae": "core"}


def retired_refusal(argv):
    """The refusal line for the first retired flag (or ``--store`` value) in ``argv``, or None when there is none."""
    for i, arg in enumerate(argv):
        name, eq, value = arg.partition("=")
        if name in RETIRED_FLAGS:
            return (f"money_check: refused: the flag {name} is retired; it is now {RETIRED_FLAGS[name]} "
                    "(rename the flag; the old name is never read)")
        if name == "--store":
            value = value if eq else (argv[i + 1] if i + 1 < len(argv) else None)
            if value in RETIRED_STORE:
                return (f"money_check: refused: --store {value} is retired; it is now --store {RETIRED_STORE[value]} "
                        "(rename the value; the old one is never read)")
    return None


# Flags of the OMS and sim-log expected side: refused with --store core, whose expected side and funding come from the core
CORE_REFUSED = ("--oms-url", "--sim-log", "--extra-deposits", "--users", "--asset-map", "--loop", "--max-sweeps",
                "--redis-host", "--redis-port", "--redis-db", "--tolerance", "--http-timeout")


def core_refusal(argv):
    """The refusal line for a flag that has no meaning with --store core, or None."""
    if not any(a == "--store=core" or (a == "--store" and i + 1 < len(argv) and argv[i + 1] == "core")
               for i, a in enumerate(argv)):
        return None
    for arg in argv:
        name = arg.split("=", 1)[0]
        if name in CORE_REFUSED:
            return (f"money_check: refused: {name} has no meaning with --store core: the expected side and the funding "
                    "come from the core and its money history")
    return None


def core_env(args, tool_key, admin_key):
    """The environment of the two reads: the core's address in each program's own names, the driver mode, the key."""
    stride = args.core_port_stride
    if args.core_port_base is None:
        raise core_expected.OperationalError("--store core needs --core-port-base")
    for flag, value in (("--core-addresses", args.core_addresses), ("--local-host", args.local_host),
                        ("--driver-mode", args.driver_mode)):
        if not value:
            raise core_expected.OperationalError(f"--store core needs {flag}")
    if (args.driver_mode == "external") != bool(args.aeron_dir):
        raise core_expected.OperationalError("--aeron-dir is required with --driver-mode external and refused with embedded")
    common = {"AERON_DIR": args.aeron_dir} if args.aeron_dir else {}
    dump = {"COREDUMP_DRIVER_MODE": args.driver_mode, "CORE_AUTH_CREDENTIAL": tool_key,
            "BRIDGE_CORE_CLUSTER_ADDRESSES": args.core_addresses, "BRIDGE_CORE_PORT_BASE": str(args.core_port_base),
            "BRIDGE_LOCAL_HOST": args.local_host}
    probe = {"CORE_PROBE_DRIVER_MODE": args.driver_mode, "CORE_AUTH_CREDENTIAL": admin_key,
             "CORE_ADDRESSES": args.core_addresses, "CORE_PORT_BASE": str(args.core_port_base),
             "CLUSTER_PORT_STRIDE": str(stride), "CORE_LOCAL_HOST": args.local_host}
    return {"common": common, "dump": dump, "probe": probe}


def print_core(result):
    print(f"[{result['ts']}] core sweep: {result['status']}")
    print(f"   {result['statement']}")
    for a in result.get("attempts", []):
        if not a["stable"]:
            print(f"   UNSTABLE attempt {a['attempt']}: {core_expected.UNSTABLE_TEXT}")
    if result.get("position"):
        print(f"   core position: consume={result['position']['consumePosition']} "
              f"lastAppliedTradeId={result['position']['lastAppliedTradeId']}; {result.get('accounts')} accounts, "
              f"{result.get('live_orders')} live orders, {result.get('hold_entries')} holds")
    for c in result.get("checks", []):
        line = f"   {c['status']:<13} {c['name']}"
        if c.get("reason"):
            line += f"  ({c['reason']})"
        print(line)
        for d in c.get("drifts", [])[:50]:
            print(f"        {json.dumps(d, sort_keys=True)}")
    for d in result.get("residual_holds", []):
        print(f"   {core_expected.residual_text(d)}")


def core_main(args):
    """--store core: one sweep with the core's own expected side. Exit 0 green, 2 violated, 3 unstable, 4 indeterminate
    (a check was not judged), 1 operational."""
    try:
        urls = [u.strip() for u in (args.core_metrics or "").split(",") if u.strip()]
        if not urls:
            raise core_expected.OperationalError("--store core needs --core-metrics: without the members' /metrics the "
                                                 "core counters and the money journal head are not read")
        tool_key = core_expected.read_key(args.tool_key_file, "--tool-key-file")
        admin_key = core_expected.read_key(args.admin_key_file, "--admin-key-file")
        java = [args.java, *(core_expected.JVM_FLAGS if args.jvm_opt is None else args.jvm_opt)]
        dump_argv, probe_argv = core_expected.cut_programs(args.cut, args.artifact_root, java)
        env = core_env(args, tool_key, admin_key)
        if bool(args.money_history_dsn) == bool(args.funding_file):
            raise core_expected.OperationalError("--store core needs exactly one funding source: --money-history-dsn or "
                                                 "--funding-file")
        if args.money_history_dsn:
            funding = lambda: core_expected.funding_from_history(args.money_history_dsn, args.psql)
        else:
            funding = lambda: core_expected.funding_from_file(args.funding_file)
        counters = lambda: core_expected.core_counters(urls)
        zero = [tuple(r) for r in ranges_of(args.zero_hold_users)] if args.zero_hold_users else ()
        reader = core_expected.CoreReader(dump_argv, probe_argv, env, args.core_timeout)
        result, code = core_expected.sweep(reader, funding, zero, counters, args.stable_retries, args.stable_wait_ms,
                                           log=lambda m: print(m, file=sys.stderr))
    except core_expected.OperationalError as e:
        print(f"money_check: operational error: {e}", file=sys.stderr)
        if args.json:
            print(json.dumps({"mode": "core", "status": "ERROR", "error": str(e), "statement": core_expected.STATEMENT}))
        return 1
    if args.json:
        print(json.dumps(result), flush=True)
    else:
        print_core(result)
    return code


def ranges_of(spec):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


class _Parser(argparse.ArgumentParser):
    """A usage error exits 64 (EX_USAGE), never 2: 2 means an invariant was violated."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"money_check: usage: {message}", file=sys.stderr)
        sys.exit(64)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    refusal = retired_refusal(argv) or core_refusal(argv)
    if refusal is not None:
        print(refusal, file=sys.stderr)
        return 64
    try:
        args = build_arg_parser().parse_args(argv)
    except SystemExit as e:
        return e.code
    if args.store == "core":
        return core_main(args)
    if args.sim_log is None:
        args.sim_log = ["~/.local/log/cluster/sim.log"]
    asset_map = parse_asset_map(args.asset_map)

    rolling = 0
    sweep_no = 0
    ever_violated = False
    try:
        while True:
            sweep_no += 1
            try:
                result = run_sweep(args, asset_map)
            except Exception as e:  # operational error: report, don't crash a soak loop
                if args.loop is None:
                    print(f"money_check: operational error: {e}", file=sys.stderr)
                    return 1
                print(f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] sweep#{sweep_no} ERROR {e}",
                      file=sys.stderr)
                time.sleep(args.loop)
                continue

            if result["violated"]:
                rolling += 1
                ever_violated = True

            if args.json:
                print(json.dumps(result), flush=True)
            elif args.loop is not None:
                print(status_line(result, sweep_no, rolling), flush=True)
                if result["violated"] or result["indeterminate"]:
                    print_human(result, args.verbose)
            else:
                print_human(result, args.verbose)

            if args.loop is None:
                return 2 if result["violated"] else 0
            if args.max_sweeps is not None and sweep_no >= args.max_sweeps:
                break
            time.sleep(args.loop)
    except KeyboardInterrupt:
        print(f"\nmoney_check: stopped after {sweep_no} sweep(s), "
              f"{rolling} with violations.", file=sys.stderr)
    return 2 if ever_violated else 0


if __name__ == "__main__":
    sys.exit(main())
