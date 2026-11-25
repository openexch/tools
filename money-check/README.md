# money-check

Read-only money invariant checker. `money_check.py` reconciles the ledger against three invariants and exits non-zero when one breaks. It only issues `SCAN`, `HGETALL` and `GET` to Redis, `GET` to the OMS and, in core mode, runs a read-only snapshot command. It never writes.

It reads the ledger from either store behind one interface:

- `--store redis` (default): Redis `db0` directly (`bal:{userId}` hashes), the v0.5 stack.
- `--store core`: the core expected side, no OMS (section below).

With `--store redis` the expected-hold side comes from the v0.5 OMS open-orders API, so that store needs a running v0.5 OMS.

Python 3, standard library only. It speaks RESP over a socket with a small built-in client and uses the `redis` package instead if it is importable.

## The three invariants

1. Per-asset conservation, deposit-aware. For every asset:

   ```
   sum over users (available + locked)  ==  sum of deposits - sum of withdrawals
   ```

   Trading only moves value within an asset, so only deposits and withdrawals change an asset total. The right-hand side is summed from the `deposited ... of asset N` lines in the simulator log (`--sim-log`, default `~/.local/log/cluster/sim.log`, rotated logs read oldest first), plus any manual deposits in `--extra-deposits`. If the log does not reach the clean-slate genesis (the first deposit per asset shows `had 0.00000000`), the check reports INDETERMINATE rather than a false breach.

2. `locked` equals the sum of open-order holds. The expected `locked` per (user, asset) comes from the OMS open-orders API (`GET /api/v1/orders`, `Authorization: Bearer dev:<userId>`):

   ```
   BUY  locks the quote asset:  price x remainingQty
   SELL locks the base asset:   remainingQty
   ```

3. Non-negativity. No `available < 0` and no `locked < 0`.

Amounts are 8-decimal fixed-point `int64` throughout.

## Two traps the tool avoids

`holds:{u}` in Redis is not a source of truth. Entries are added when a hold is placed and are not reliably removed on settle, so the hash accumulates stale holds. The tool never reconciles against it; it uses the OMS open-orders API as the expected side and `bal:{u}` or the core snapshot as the actual side.

BUY holds after a partial fill at a better price. The OMS does not expose an order's stored hold amount, so the tool computes `price x remainingQty`. When a BUY fills partly below its limit, the core's residual hold is `originalHold - sum(fillPrice x fillQty)`, which is larger than the computed value by the price improvement. That drift is always positive (over-collateralized), bounded by `sum((limitPrice - fillPrice) x filledQty)`, and zero for unfilled orders. A negative locked gap (under-collateralized) is never explained by this and is a real finding.

## The core expected side (`--store core`)

Both sides come from the core, each read by its own process started from the release cut's bytes (re-hashed against the
cut manifest; `--artifact-root DIR` names the directory the jars were copied to, their names and digests stay the cut's):

- the ledger: `CoreDump` (the cut's `tools.core-dump` jar) with a TOOL key: balances, per-order holds, the feed markers;
- the expected holds: the core's own order snapshot for every user, read with an ADMIN key by `CoreProbe order-dump` (the
  cut's `harness.core_probe` jar on its `core-cluster.jar`).

Stability is defined by content: the tool reads dump, orders, funding, dump, orders, funding and judges only when both
dumps, both order snapshots and both funding reads are equal (the funding source is read inside the window, so a deposit
next to the reads is never judged against a dump of another instant). Otherwise the attempt is UNSTABLE and it reads
again after `--stable-wait-ms` (default 1000, `MONEY_CHECK_STABLE_WAIT_MS`), up to `--stable-retries` attempts (default
5, `MONEY_CHECK_STABLE_RETRIES`). It never reports a mismatch from two instants.

The invariants, exact for every user: conservation per asset against the core's own deposits and withdrawals (the money
history, `--money-history-dsn`, or `--funding-file` written from it; the money history is judged only when it is at the
core's money journal head, `core_journal_seq` of `--core-metrics`: behind the head, or with no head read, conservation
is INDETERMINATE; a funding file carries no journal position, the caller answers for its instant); locked equals the sum of holds; every hold belongs to a live order (else a
`residual hold: user <u> asset <a> <amount>`); every live order's hold equals the value recomputed from its fields (SELL
remaining; an unfilled priced BUY price x remaining; a partly filled BUY at least price x remaining and at most its hold
amount, since a fill below the limit keeps the price improvement held until the order ends); `--zero-hold-users` hold
nothing; non-negativity; `core_pending_commands` and `core_release_backlog` are 0 on every member (`--core-metrics`).

This compares the core with itself and with the tool's own recomputation; it is not the fixture oracle, and it is exact only
at a quiesce point. The output says so.

```bash
python3 money_check.py --store core --cut /abs/cut-manifest.json --artifact-root /opt/oe/tools \
    --core-addresses 10.0.0.1,10.0.0.2,10.0.0.3 --core-port-base 9300 --local-host 10.0.0.9 \
    --driver-mode external --aeron-dir /dev/shm/aeron \
    --tool-key-file ~/.oe/tool.key --admin-key-file ~/.oe/admin.key \
    --money-history-dsn "host=127.0.0.1 dbname=oe_money user=obs" \
    --core-metrics http://10.0.0.1:9306/metrics,http://10.0.0.2:9306/metrics,http://10.0.0.3:9306/metrics \
    --zero-hold-users 900000-900999 --json
```

Required with `--store core`: `--cut`, `--core-addresses`, `--core-port-base`, `--local-host`, `--driver-mode` (`embedded`,
or `external` with `--aeron-dir`; the two reads get `COREDUMP_DRIVER_MODE` and `CORE_PROBE_DRIVER_MODE`), the two key
files (`keyId:CLASS:secretHex`, mode 600: a key file readable by others is refused), exactly one funding source, and
`--core-metrics` (every member's `/metrics`).
Optional: `--core-port-stride` (100), `--core-timeout` (40 s per read), `--java` and `--jvm-opt` (default: the three
`--add-opens` options Aeron needs on Java 21), `--psql`. The OMS and sim-log flags are refused with exit 64.

Exit codes in this mode: `0` green (status `OK`: every check was judged and passed), `2` an invariant was violated
(`VIOLATED`), `3` UNSTABLE through every attempt, `4` INDETERMINATE (nothing violated, and at least one check could not
be judged: the money history behind the core's journal head, a counter missing on a member; the check's reason says
which), `1` operational error (a missing setting, the core unreachable, `CoreDump timeout`: CoreDump's own exit 3 is
mapped to 1, never to 3). Only `0` is green; `--zero-hold-users` is the one check that exists only when its flag is given
(the observation verdict requires it in each quiesce document when `OBS_ZERO_HOLD_USERS` is set).

## Usage (`--store redis`)

```bash
# one sweep: Redis store, OMS at http://localhost:8080, default sim log
python3 money_check.py

# one JSON object per sweep
python3 money_check.py --json

# continuous: one sweep every 60 s
python3 money_check.py --loop 60

# unit tests
python3 -m unittest test_money_check
```

Flags: `--store {redis,core}`, `--oms-url`, `--sim-log` (repeatable, globs allowed), `--extra-deposits FILE` (lines `ts user asset amount`), `--redis-host`, `--redis-port`, `--redis-db`, `--cut` (the release cut manifest; required with `--store core`, no default), `--core-timeout` (default 40 s), `--asset-map "USD=0,BTC=1,..."`, `--users 900000-900999`, `--tolerance N` (per-row 8-dp gap tolerated, default 0), `--http-timeout` (default 5 s), `--loop SECONDS`, `--max-sweeps N`, `--json`, `--verbose`.

Default asset map, matching the market-sim `DefaultMarkets` table: `USD=0, BTC=1, ETH=2, SOL=3, XRP=4, DOGE=5`. Override with `--asset-map` if a deployment numbers assets differently.

Exit codes (`--store redis`): `0` all green, `2` an invariant was violated, `1` operational error (store or OMS unreachable), `64` a usage error: a retired flag or value (`--ae-dump-cmd`, `--ae-timeout`, `--store ae`, `--core-dump-cmd`: use `--cut`), a flag that has no meaning with `--store core`, or any other bad argument. With `--loop` the process runs until Ctrl-C or `--max-sweeps` and exits `2` if any sweep violated.

## Reading results on a live stack

A sweep is not atomic across the store and the OMS, and the simulator keeps trading, so invariant 2 can show explainable transient drift: the BUY-hold caveat above (persistent, small, positive) and read-time skew on the most active markets for the moment between the balance read and that user's OMS read. Conservation and non-negativity should be green; a one-off conservation gap from an in-flight settle clears on the next sweep.

Never benign: a negative locked gap, drift on the same (user, asset) that grows or persists across sweeps, a conservation gap that does not clear, or any non-negativity failure.

For a clean point-in-time check, pause the simulator (`POST /control {"pause":true}` on market-sim) and run one sweep.

## CoreDump

`CoreDump` is `com.openexchange.core.bridge.CoreDump` in the `core` repo. It needs `COREDUMP_DRIVER_MODE` (`embedded`: its
own driver in `/dev/shm/aeron-aedump-<pid>`, deleted on exit; `external`: the aeronmd at `AERON_DIR`), the core's address
(`BRIDGE_CORE_CLUSTER_ADDRESSES`, `BRIDGE_CORE_PORT_BASE`, `BRIDGE_LOCAL_HOST`) and a TOOL credential in
`CORE_AUTH_CREDENTIAL`; money-check sets all of them from its flags. It prints one JSON document and exits `0`, `1` when the
start is refused, or `3` when its 30 s snapshot deadline passes:

```json
{
  "balances": [{"userId": 900001, "assetId": 0, "available": 900, "locked": 100}],
  "holds":    [{"orderId": 111, "userId": 900001, "assetId": 0, "remaining": 100}],
  "consumePosition": 88231,
  "lastAppliedTradeId": 45012
}
```

The snapshot requests do not change core state.
