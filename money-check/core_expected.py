# SPDX-License-Identifier: Apache-2.0
"""The core expected side of money-check: the ledger and the expected holds both come from the core, so the check runs
with no OMS.

Two read-only reads, each its own process, each started from the release cut's own bytes (sha256 checked):

  ledger   CoreDump (the cut's tools.core-dump jar, a TOOL key): balances, per-order holds, the feed markers.
  orders   CoreProbe ``order-dump`` (the cut's harness core_probe jar on the cut's core-cluster.jar, an ADMIN key): the
           core's own order snapshot for every user (RequestOrderSnapshot, userId 0), every page.

Stability is defined by content, not by a marker: the tool reads dump, orders, dump, orders and judges only when both
dumps are equal and both order snapshots are equal (the markers consumePosition and lastAppliedTradeId move with the
ME feed and not with a create, a cancel, an amend or a deposit, so they cannot stand for the content). Otherwise the
attempt is UNSTABLE and the tool waits and reads again, up to its retries; it never reports a mismatch from two
different instants.

The invariants, each exact for every user:
  conservation     per asset, the sum of available + locked equals deposits - withdrawals of the core's own money
                   history (the money projector's money_journal, read over a PostgreSQL connection, or a funding file
                   written from it)
  locked_vs_holds  locked equals the sum of the core's hold entries per user and asset
  holds_live       every hold belongs to a live order of the same user and hold asset (else: a residual hold)
  order_holds      every live order has a hold, and it equals the value recomputed from the order's fields:
                   SELL remaining quantity; BUY of a priced type with nothing filled price x remaining (floored, as the
                   core's FixedPoint.multiply); BUY with fills: between price x remaining and the order's hold amount
                   (a fill below the limit leaves the price improvement held until the order ends, so only the floor is
                   exact); a price-less BUY (market, stop loss, trailing stop) its own hold amount less nothing it
                   cannot see: judged as "at most the hold amount"
  zero_holds       the named users (the simulator's own) hold nothing at all
  non_negativity   no available and no locked below zero
  core_counters    core_pending_commands and core_release_backlog are 0 on every member (when --core-metrics is given)

This compares the core with itself and with the tool's recomputation. It is weaker than the fixture oracle, which
anchors on the client's own request log, and it is exact only at a quiesce point.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
import urllib.request

STATEMENT = ("money-check compares the core with itself and with its own recomputation of each hold; it is not the "
             "fixture oracle (which anchors on the client's request log) and it is exact only at a quiesce point")
SCALE = 10 ** 8
TERMINAL = {"FILLED", "CANCELED", "CANCELLED", "REJECTED", "EXPIRED"}
PRICED = {"LIMIT", "LIMIT_MAKER", "ICEBERG", "STOP_LIMIT"}
CORE_DUMP_TOOL = "core-dump"
CORE_DUMP_MAIN = "com.openexchange.core.bridge.CoreDump"
PROBE_KEY = "core_probe"
PROBE_MAIN = "CoreProbe"
CORE_JAR = "core-cluster.jar"
TIMEOUT_TEXT = "CoreDump timeout"
SETTINGS = {"MONEY_CHECK_STABLE_RETRIES": 5, "MONEY_CHECK_STABLE_WAIT_MS": 1000}
# The JVM options every Aeron client on Java 21 needs (Agrona's buffers and Aeron's channels reach into the JDK)
JVM_FLAGS = ["--add-opens", "java.base/jdk.internal.misc=ALL-UNNAMED", "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED",
             "--add-opens", "java.base/java.nio=ALL-UNNAMED"]


class OperationalError(RuntimeError):
    """Exit 1: the core could not be read (never clean, never broken)."""


# --------------------------------------------------------------------------- the cut's bytes

def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def cut_file(cut, what, entry, artifact_root):
    """The local path of one cut entry, re-hashed against the cut. ``artifact_root`` (the directory the files were
    copied to, e.g. on the box) replaces the build machine's directory; the file name and the sha256 stay the cut's."""
    if not isinstance(entry, dict) or not entry.get("path") or not entry.get("sha256"):
        raise OperationalError(f"the cut {cut.get('cut_id')} names no {what} (path and sha256)")
    path = os.path.join(artifact_root, os.path.basename(entry["path"])) if artifact_root else entry["path"]
    try:
        digest = _sha(path)
    except OSError as e:
        raise OperationalError(f"{what}: {path} is not readable: {e}")
    if digest != entry["sha256"]:
        raise OperationalError(f"{what}: {path} hashes to {digest}, the cut pins {entry['sha256']}")
    return path


def cut_programs(cut_path, artifact_root=None, java=("java", *JVM_FLAGS)):
    """(CoreDump argv, CoreProbe argv) from the release cut manifest; anything missing refuses (exit 1)."""
    if not cut_path:
        raise OperationalError("--store core needs --cut MANIFEST: CoreDump and the order snapshot reader run from the "
                               "release cut's jars, never from a default path")
    try:
        with open(cut_path) as fh:
            cut = json.load(fh)
    except (OSError, ValueError) as e:
        raise OperationalError(f"--cut {cut_path}: not a readable cut manifest: {e}")
    if not isinstance(cut, dict):
        raise OperationalError(f"--cut {cut_path}: not a cut manifest")
    dump = (cut.get("tools") or {}).get(CORE_DUMP_TOOL)
    if isinstance(dump, dict) and dump.get("main") not in (None, CORE_DUMP_MAIN):
        raise OperationalError(f"--cut {cut_path}: tools.{CORE_DUMP_TOOL}.main is {dump.get('main')!r}, not {CORE_DUMP_MAIN}")
    dump_jar = cut_file(cut, f"tools.{CORE_DUMP_TOOL} jar", dump, artifact_root)
    probe_jar = cut_file(cut, f"harness.{PROBE_KEY} jar", (cut.get("harness") or {}).get(PROBE_KEY), artifact_root)
    core_jar = cut_file(cut, f"artifacts.{CORE_JAR}", (cut.get("artifacts") or {}).get(CORE_JAR), artifact_root)
    return ([*java, "-cp", dump_jar, CORE_DUMP_MAIN],
            [*java, "-cp", f"{probe_jar}:{core_jar}", PROBE_MAIN, "order-dump"])


def read_key(path, what):
    """One credential file (keyId:CLASS:secretHex), readable by its owner only."""
    if not path:
        raise OperationalError(f"--store core needs {what}")
    try:
        st = os.stat(path)
        with open(path) as fh:
            value = fh.read().strip()
    except OSError as e:
        raise OperationalError(f"{what} {path}: {e}")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise OperationalError(f"{what} {path} is readable by others (mode {oct(st.st_mode & 0o777)}); chmod 600 it")
    if value.count(":") != 2:
        raise OperationalError(f"{what} {path} does not hold keyId:CLASS:secretHex")
    return value


# --------------------------------------------------------------------------- the two reads

# The embedded driver directories of the two read programs, by the child's pid (CoreDump, CoreProbe)
CHILD_DRIVER_DIRS = ("/dev/shm/aeron-aedump-{pid}", "/dev/shm/core-probe-{pid}")


def run_child(argv, capture_output=True, text=True, timeout=None, env=None):
    """subprocess.run for one read program. A program killed at the bound cannot delete its own embedded driver
    directory, so this removes the one its pid names (it never touches another process's directory)."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text, env=env)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        for pattern in CHILD_DRIVER_DIRS:
            shutil.rmtree(pattern.format(pid=proc.pid), ignore_errors=True)
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


class CoreReader:
    """Runs the two reads. ``run`` is run_child (a test passes a fake)."""

    def __init__(self, dump_argv, probe_argv, env, timeout, run=run_child):
        self.dump_argv, self.probe_argv, self.env, self.timeout, self.run = dump_argv, probe_argv, env, timeout, run

    def _proc(self, argv, extra):
        env = dict(os.environ)
        env.update(self.env["common"])
        env.update(extra)
        try:
            return self.run(argv, capture_output=True, text=True, timeout=self.timeout, env=env)
        except subprocess.TimeoutExpired:
            return None

    def dump(self):
        p = self._proc(self.dump_argv, self.env["dump"])
        if p is None:
            raise OperationalError(f"{TIMEOUT_TEXT}: no answer within --core-timeout {self.timeout} s")
        if p.returncode == 3:
            # CoreDump's own exit 3 is its 30 s snapshot deadline: an operational error here, never UNSTABLE
            raise OperationalError(f"{TIMEOUT_TEXT}: CoreDump exit 3 (no complete snapshot before its deadline: is there "
                                   f"a core leader?) {p.stderr.strip()[-300:]}")
        if p.returncode != 0:
            raise OperationalError(f"CoreDump exited {p.returncode}: {p.stderr.strip()[:400]}")
        try:
            doc = json.loads(p.stdout)
        except ValueError as e:
            raise OperationalError(f"CoreDump stdout was not JSON: {e}")
        return {"balances": sorted((int(b["userId"]), int(b["assetId"]), int(b["available"]), int(b["locked"]))
                                   for b in doc.get("balances", [])),
                "holds": sorted((int(h["orderId"]), int(h["userId"]), int(h["assetId"]), int(h["remaining"]))
                                for h in doc.get("holds", [])),
                "markers": {"consumePosition": doc.get("consumePosition"),
                            "lastAppliedTradeId": doc.get("lastAppliedTradeId")}}

    def orders(self):
        p = self._proc(self.probe_argv, self.env["probe"])
        if p is None:
            raise OperationalError(f"order snapshot timeout: no answer within --core-timeout {self.timeout} s")
        if p.returncode == 3:
            raise OperationalError("order snapshot timeout: the reader got no answer before its deadline")
        if p.returncode != 0:
            raise OperationalError(f"order snapshot reader exited {p.returncode}: {(p.stderr or p.stdout).strip()[-400:]}")
        lines = [l for l in p.stdout.splitlines() if l.startswith("{")]
        try:
            doc = json.loads(lines[-1])
        except (IndexError, ValueError) as e:
            raise OperationalError(f"order snapshot answer was not JSON: {e}")
        if doc.get("outcome") in ("REFUSED", "UNKNOWN") or "orders" not in doc:
            raise OperationalError(f"order snapshot refused: {json.dumps(doc)[:300]}")
        return sorted((json.dumps(o, sort_keys=True) for o in doc["orders"]))


def content_stable(d1, o1, d2, o2):
    """Both dumps equal and both order snapshots equal: the content, never the markers."""
    return d1["balances"] == d2["balances"] and d1["holds"] == d2["holds"] and o1 == o2


def markers_stable(d1, o1, d2, o2):
    """The reduced check (a control only): the CoreDump markers alone."""
    return d1["markers"] == d2["markers"]


def stable_read(reader, retries, wait_ms, sleep=time.sleep, stable=content_stable, log=None):
    """(dump, orders, attempts) of the first stable attempt, or (None, None, attempts) after ``retries`` attempts."""
    attempts = []
    for n in range(1, retries + 1):
        d1, o1 = reader.dump(), reader.orders()
        d2, o2 = reader.dump(), reader.orders()
        ok = stable(d1, o1, d2, o2)
        attempts.append({"attempt": n, "stable": ok, "markers": [d1["markers"], d2["markers"]]})
        if ok:
            return d2, o2, attempts
        if log:
            log(f"UNSTABLE: the dump or the order snapshot changed between two reads (attempt {n} of {retries})")
        if n < retries:
            sleep(wait_ms / 1000)
    return None, None, attempts


# --------------------------------------------------------------------------- funding source

def funding_from_history(dsn, psql="psql", run=subprocess.run, timeout=30):
    """Per-asset (deposits, withdrawals) from the money projector's money_journal (movement 2 deposit, 3 withdraw)."""
    sql = ("SELECT asset_id, movement_type, COALESCE(sum(amount), 0) FROM money_journal "
           "WHERE movement_type IN (2, 3) GROUP BY 1, 2 ORDER BY 1, 2")
    try:
        p = run([psql, dsn, "-X", "-q", "-A", "-t", "-F", ",", "-v", "ON_ERROR_STOP=1", "-c", sql],
                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise OperationalError(f"money history unreadable: {e}")
    if p.returncode != 0:
        raise OperationalError(f"money history unreadable: {p.stderr.strip()[-300:]}")
    dep, wd = {}, {}
    for line in p.stdout.split():
        asset, kind, amount = line.split(",")
        (dep if kind == "2" else wd)[int(asset)] = int(amount)
    head = run([psql, dsn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c",
                "SELECT COALESCE(max(journal_seq), 0) FROM money_journal"], capture_output=True, text=True, timeout=timeout)
    if head.returncode != 0:
        raise OperationalError(f"money history unreadable: {head.stderr.strip()[-300:]}")
    return dep, wd, int(head.stdout.strip() or 0)


def funding_from_file(path):
    """{"<asset>": {"deposits": n, "withdrawals": n}} written from the money history."""
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        raise OperationalError(f"--funding-file {path}: {e}")
    return ({int(a): int(v.get("deposits", 0)) for a, v in doc.items()},
            {int(a): int(v.get("withdrawals", 0)) for a, v in doc.items()}, None)


def core_counters(urls, timeout=5):
    """{member url: {core_pending_commands, core_release_backlog}} from each member's /metrics."""
    out = {}
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                text = r.read().decode()
        except OSError as e:
            raise OperationalError(f"core metrics unreadable: {url}: {e}")
        vals = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("core_pending_commands", "core_release_backlog", "core_journal_seq"):
                vals[parts[0]] = float(parts[1])
        out[url] = vals
    return out


# --------------------------------------------------------------------------- the invariants

def floor_quote(price, qty):
    return price * qty // SCALE


def recompute(order):
    """(kind, low, high) of a live order's expected hold: exact when low == high."""
    side, typ = order["side"], order["type"]
    remaining, filled = int(order["remaining"]), int(order["filled"])
    if side == "SELL":
        return "exact", remaining, remaining
    if typ in PRICED:
        floor = floor_quote(int(order["price"]), remaining)
        if filled == 0:
            return "exact", floor, floor
        return "bounded", floor, int(order["hold_amount"])
    return "bounded", 0, int(order["hold_amount"])


def _drift(name, **kw):
    return dict({"check": name}, **kw)


def in_ranges(user, ranges):
    return any(lo <= user <= hi for lo, hi in ranges)


def judge(dump, orders, funding, zero_users=(), counters=None):
    """The checks over one stable pair; each check is {name, status, drifts}."""
    checks = []
    bal = {(u, a): (av, lk) for u, a, av, lk in dump["balances"]}
    holds = {}
    for oid, u, a, rem in dump["holds"]:
        holds.setdefault(oid, []).append((u, a, rem))
    live = {}
    for raw in orders:
        o = json.loads(raw)
        if str(o["status"]).upper() not in TERMINAL:
            live[int(o["order"])] = o

    # conservation
    core_head = max((v.get("core_journal_seq", -1) for v in (counters or {}).values()), default=None)
    history_head = funding[2] if funding is not None else None
    if funding is None:
        checks.append({"name": "conservation", "status": "INDETERMINATE", "reason": "no funding source", "drifts": []})
    elif history_head is not None and core_head is not None and history_head < core_head:
        checks.append({"name": "conservation", "status": "INDETERMINATE", "drifts": [],
                       "reason": f"the money history is behind the core: journal {history_head} of {core_head}"})
    else:
        dep, wd = funding[0], funding[1]
        per = {}
        for (u, a), (av, lk) in bal.items():
            per[a] = per.get(a, 0) + av + lk
        drifts = []
        for a in sorted(set(per) | set(dep) | set(wd)):
            exp = dep.get(a, 0) - wd.get(a, 0)
            if per.get(a, 0) != exp:
                drifts.append(_drift("conservation", userId=None, assetId=a, expected=exp, actual=per.get(a, 0),
                                     gap=per.get(a, 0) - exp))
        checks.append({"name": "conservation", "status": "FAIL" if drifts else "PASS", "drifts": drifts})

    # locked equals the sum of holds
    sums = {}
    for oid, rows in holds.items():
        for u, a, rem in rows:
            sums[(u, a)] = sums.get((u, a), 0) + rem
    drifts = []
    for key in sorted(set(sums) | {k for k, v in bal.items() if v[1] != 0}):
        locked = bal.get(key, (0, 0))[1]
        if locked != sums.get(key, 0):
            drifts.append(_drift("locked_vs_holds", userId=key[0], assetId=key[1], expected=sums.get(key, 0), actual=locked,
                                 gap=locked - sums.get(key, 0)))
    checks.append({"name": "locked_vs_holds", "status": "FAIL" if drifts else "PASS", "drifts": drifts})

    # every hold belongs to a live order
    drifts = []
    for oid in sorted(holds):
        for u, a, rem in holds[oid]:
            o = live.get(oid)
            if o is None or int(o["user"]) != u or int(o["hold_asset"]) != a:
                drifts.append(_drift("holds_live", orderId=oid, userId=u, assetId=a, actual=rem, expected=0, gap=rem,
                                     reason="no live order" if o is None else "order of another user or hold asset"))
    checks.append({"name": "holds_live", "status": "FAIL" if drifts else "PASS", "drifts": drifts})

    # every live order's hold equals the recomputed value
    drifts, bounded = [], 0
    for oid in sorted(live):
        o = live[oid]
        have = sum(rem for u, a, rem in holds.get(oid, []))
        if oid not in holds:
            drifts.append(_drift("order_holds", orderId=oid, userId=int(o["user"]), assetId=int(o["hold_asset"]),
                                 expected="a hold", actual=0, gap=0, reason="live order without a hold"))
            continue
        kind, low, high = recompute(o)
        bounded += kind == "bounded"
        if not low <= have <= high:
            drifts.append(_drift("order_holds", orderId=oid, userId=int(o["user"]), assetId=int(o["hold_asset"]),
                                 expected=low if kind == "exact" else [low, high], actual=have,
                                 gap=have - low if have < low else have - high, reason=kind))
    checks.append({"name": "order_holds", "status": "FAIL" if drifts else "PASS", "drifts": drifts,
                   "bounded_orders": bounded})

    # the simulator's own users hold nothing
    if zero_users:
        drifts = [_drift("zero_holds", orderId=oid, userId=u, assetId=a, actual=rem, expected=0, gap=rem)
                  for oid in sorted(holds) for u, a, rem in holds[oid] if in_ranges(u, zero_users) and rem]
        checks.append({"name": "zero_holds", "status": "FAIL" if drifts else "PASS", "drifts": drifts})

    drifts = [_drift("non_negativity", userId=u, assetId=a, field=f, expected=0, actual=v, gap=v)
              for (u, a), (av, lk) in sorted(bal.items()) for f, v in (("available", av), ("locked", lk)) if v < 0]
    checks.append({"name": "non_negativity", "status": "FAIL" if drifts else "PASS", "drifts": drifts})

    if counters is None:
        checks.append({"name": "core_counters", "status": "INDETERMINATE",
                       "reason": "no --core-metrics: core_pending_commands and core_release_backlog not read", "drifts": []})
    else:
        drifts = [_drift("core_counters", member=url, field=k, expected=0, actual=v, gap=v)
                  for url, vals in sorted(counters.items()) for k, v in sorted(vals.items())
                  if k != "core_journal_seq" and v != 0]
        missing = [url for url, vals in counters.items()
                   if not {"core_pending_commands", "core_release_backlog"} <= set(vals)]
        status = "FAIL" if drifts else "INDETERMINATE" if missing else "PASS"
        checks.append({"name": "core_counters", "status": status, "drifts": drifts,
                       **({"reason": "counter missing on " + ", ".join(missing)} if missing else {})})
    residual = [d for c in checks if c["name"] in ("holds_live", "zero_holds") for d in c["drifts"]]
    return checks, residual, len(live)


def residual_text(d):
    return f"residual hold: user {d['userId']} asset {d['assetId']} {d['actual']}"


def sweep(reader, funding_source, zero_users=(), counters_source=None, retries=5, wait_ms=1000, sleep=time.sleep,
          stable=content_stable, log=None):
    """One core-mode sweep: the result document and its exit code (0 green, 2 violated, 3 unstable to the end)."""
    t0 = time.time()
    dump, orders, attempts = stable_read(reader, retries, wait_ms, sleep, stable, log)
    result = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "mode": "core", "statement": STATEMENT, "attempts": attempts}
    if dump is None:
        result.update(status="UNSTABLE", checks=[], violated=False, indeterminate=True,
                      duration_ms=int((time.time() - t0) * 1000))
        return result, 3
    funding = funding_source() if funding_source else None
    counters = counters_source() if counters_source else None
    checks, residual, n_live = judge(dump, orders, funding, zero_users, counters)
    violated = any(c["status"] == "FAIL" for c in checks)
    result.update(status="VIOLATED" if violated else "OK", checks=checks, residual_holds=residual, position=dump["markers"],
                  live_orders=n_live, hold_entries=len(dump["holds"]), balance_rows=len(dump["balances"]),
                  accounts=len({b[0] for b in dump["balances"]}), violated=violated,
                  indeterminate=any(c["status"] == "INDETERMINATE" for c in checks),
                  duration_ms=int((time.time() - t0) * 1000))
    return result, 2 if violated else 0
