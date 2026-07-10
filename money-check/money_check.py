#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""money_check.py -- the live-money guardrail for the Open Exchange cutover soak.

Reconciles the money ledger against three invariants that must hold at all times.
It is READ-ONLY: it never issues a write to Redis, the AE, or the OMS.

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
      with fills at a price other than its limit, that residual can differ from the AE's
      netted hold by a rounding tick -- treated as explainable drift, not a hard breach.

  INVARIANT 3 -- non-negativity
      No available < 0 and no locked < 0, ever.

Stores:
  --store redis (default)  read Redis db0 directly (bal:{userId} hashes).
  --store ae               shell out to the AeDump CLI and read its JSON snapshot.

Exit codes:  0 = all green   2 = an invariant was violated   1 = operational error.
"""

import argparse
import glob
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
#   holds    : { (userId:int, assetId:int) : int }   (AE only; None for redis)
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


def load_ae_store(dump_cmd, timeout):
    try:
        proc = subprocess.run(dump_cmd, shell=True, capture_output=True,
                             timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"AeDump timed out after {timeout}s (cmd: {dump_cmd})")
    if proc.returncode == 3:
        raise RuntimeError("AeDump reported its own 30s snapshot timeout (exit 3) -- "
                          "is the AE cluster up and has a leader?")
    if proc.returncode != 0:
        raise RuntimeError(f"AeDump exited {proc.returncode}: {proc.stderr.strip()[:400]}")
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"AeDump stdout was not JSON: {e}; first 200 chars: {proc.stdout[:200]!r}")
    balances = {}
    for b in doc.get("balances", []):
        balances[(int(b["userId"]), int(b["assetId"]))] = {
            "available": int(b["available"]), "locked": int(b["locked"])}
    holds = defaultdict(int)
    for h in doc.get("holds", []):
        holds[(int(h["userId"]), int(h["assetId"]))] += int(h["remaining"])
    return {"balances": balances, "holds": dict(holds),
            "position": {"consumePosition": doc.get("consumePosition"),
                        "lastAppliedTradeId": doc.get("lastAppliedTradeId")}}


# --------------------------------------------------------------------------- #
# sim.log deposit/withdrawal parser (invariant 1's right-hand side)
# --------------------------------------------------------------------------- #
DEPOSIT_RE = re.compile(
    r"deposited\s+(-?\d+(?:\.\d+)?)\s+of\s+asset\s+(\d+)\s+\(had\s+(-?\d+(?:\.\d+)?)")
WITHDRAW_RE = re.compile(
    r"(?:withdrew|withdrawn)\s+(-?\d+(?:\.\d+)?)\s+of\s+asset\s+(\d+)")


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
    for path in paths:
        if not os.path.exists(path):
            continue
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


def check_ae_internal(balances, holds, asset_map, tol):
    """AE-mode bonus: the AE's own hold entries must sum to its own locked balances."""
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
    return {"name": "ae_holds_vs_locked", "status": "PASS" if not drifts else "FAIL",
            "drifts": drifts}


# --------------------------------------------------------------------------- #
# one sweep
# --------------------------------------------------------------------------- #
def run_sweep(args, asset_map):
    t0 = time.time()
    result = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "checks": [], "error": None}

    # 1. load the store
    if args.store == "redis":
        store = load_redis_store(args.redis_host, args.redis_port, args.redis_db)
    else:
        store = load_ae_store(args.ae_dump_cmd, args.ae_timeout)
    balances = store["balances"]
    result["position"] = store["position"]

    # 2. deposits from the sim log
    log_paths = []
    for p in args.sim_log:
        log_paths.extend(sorted(glob.glob(os.path.expanduser(p))) or [os.path.expanduser(p)])
    deposits, withdrawals, genesis_covered, log_meta = parse_ledger_log(log_paths)
    result["log_meta"] = log_meta

    # 3. OMS expected locked
    user_ids = sorted(set(uid for (uid, _a) in balances.keys()))
    if args.users:
        user_ids = parse_user_arg(args.users)
    have_oms = True
    oms_stats = {}
    expected = {}
    try:
        bearer_user = user_ids[0] if user_ids else 900001
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
    ae_internal = check_ae_internal(balances, store["holds"], asset_map, args.tolerance)
    if ae_internal is not None:
        result["checks"].append(ae_internal)

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
        print(f"   AE position: consume={pos['consumePosition']} "
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
    p = argparse.ArgumentParser(description="Live-money guardrail for the Open Exchange cutover soak.")
    p.add_argument("--store", choices=["redis", "ae"], default="redis",
                  help="ledger source: redis (default) or ae (via AeDump)")
    p.add_argument("--oms-url", default="http://localhost:8080",
                  help="OMS base URL for the open-orders API (default %(default)s)")
    p.add_argument("--sim-log", action="append",
                  default=None, help="sim log path(s)/glob(s) for deposits "
                                     "(default ~/.local/log/cluster/sim.log)")
    p.add_argument("--redis-host", default="127.0.0.1")
    p.add_argument("--redis-port", type=int, default=6379)
    p.add_argument("--redis-db", type=int, default=0)
    p.add_argument("--ae-dump-cmd",
                  default="java -jar assets-bridge/target/assets-bridge.jar dump",
                  help="command that prints the AeDump JSON snapshot (--store ae)")
    p.add_argument("--ae-timeout", type=int, default=40,
                  help="seconds to wait for AeDump (its own timeout is 30s)")
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
    p.add_argument("--verbose", action="store_true", help="print every drift row, not just the first 20")
    return p


def parse_asset_map(spec):
    if not spec:
        return dict(DEFAULT_ASSET_MAP)
    out = {}
    for part in spec.split(","):
        sym, aid = part.split("=")
        out[sym.strip()] = int(aid)
    return out


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
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
