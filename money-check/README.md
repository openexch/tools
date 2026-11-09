# money-check

Read-only money invariant checker. `money_check.py` reconciles the ledger against three invariants and exits non-zero when one breaks. It only issues `SCAN`, `HGETALL` and `GET` to Redis, `GET` to the OMS and, in Assets Engine mode, runs a read-only snapshot command. It never writes.

It reads the ledger from either store behind one interface:

- `--store redis` (default): Redis `db0` directly (`bal:{userId}` hashes), the v0.5 stack.
- `--store ae`: runs the `AeDump` command from the `assets` repo and reads its JSON snapshot.

The expected-hold side always comes from the v0.5 OMS open-orders API, so the tool needs a running v0.5 OMS.

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

`holds:{u}` in Redis is not a source of truth. Entries are added when a hold is placed and are not reliably removed on settle, so the hash accumulates stale holds. The tool never reconciles against it; it uses the OMS open-orders API as the expected side and `bal:{u}` or the AE snapshot as the actual side.

BUY holds after a partial fill at a better price. The OMS does not expose an order's stored hold amount, so the tool computes `price x remainingQty`. When a BUY fills partly below its limit, the AE's residual hold is `originalHold - sum(fillPrice x fillQty)`, which is larger than the computed value by the price improvement. That drift is always positive (over-collateralized), bounded by `sum((limitPrice - fillPrice) x filledQty)`, and zero for unfilled orders. A negative locked gap (under-collateralized) is never explained by this and is a real finding.

## Usage

```bash
# one sweep: Redis store, OMS at http://localhost:8080, default sim log
python3 money_check.py

# one JSON object per sweep
python3 money_check.py --json

# continuous: one sweep every 60 s
python3 money_check.py --loop 60

# against the Assets Engine (build the assets-bridge jar in the assets repo first)
AE_AUTH_CREDENTIAL=<ADMIN or TOOL credential> python3 money_check.py --store ae \
    --ae-dump-cmd "java -jar /path/to/assets/assets-bridge/target/assets-bridge.jar dump"

# unit tests
python3 -m unittest test_money_check
```

Flags: `--store {redis,ae}`, `--oms-url`, `--sim-log` (repeatable, globs allowed), `--extra-deposits FILE` (lines `ts user asset amount`), `--redis-host`, `--redis-port`, `--redis-db`, `--ae-dump-cmd` (default `java -jar assets-bridge/target/assets-bridge.jar dump`, relative to the working directory), `--ae-timeout` (default 40 s), `--asset-map "USD=0,BTC=1,..."`, `--users 900000-900999`, `--tolerance N` (per-row 8-dp gap tolerated, default 0), `--http-timeout` (default 5 s), `--loop SECONDS`, `--max-sweeps N`, `--json`, `--verbose`.

Default asset map, matching the market-sim `DefaultMarkets` table: `USD=0, BTC=1, ETH=2, SOL=3, XRP=4, DOGE=5`. Override with `--asset-map` if a deployment numbers assets differently.

Exit codes: `0` all green, `2` an invariant was violated, `1` operational error (store or OMS unreachable, AeDump timeout). With `--loop` the process runs until Ctrl-C or `--max-sweeps` and exits `2` if any sweep violated.

## Reading results on a live stack

A sweep is not atomic across the store and the OMS, and the simulator keeps trading, so invariant 2 can show explainable transient drift: the BUY-hold caveat above (persistent, small, positive) and read-time skew on the most active markets for the moment between the balance read and that user's OMS read. Conservation and non-negativity should be green; a one-off conservation gap from an in-flight settle clears on the next sweep.

Never benign: a negative locked gap, drift on the same (user, asset) that grows or persists across sweeps, a conservation gap that does not clear, or any non-negativity failure.

For a clean point-in-time check, pause the simulator (`POST /control {"pause":true}` on market-sim) and run one sweep per store. `--store ae` adds the `ae_holds_vs_locked` check (the AE's own hold entries must sum to its own `locked`) and reports `consumePosition` and `lastAppliedTradeId`.

## AeDump

`AeDump` is `com.openexchange.assets.bridge.AeDump` in the `assets` repo, run as `java -jar assets-bridge.jar dump`. It connects an `AeronCluster` client with the credential from `AE_AUTH_CREDENTIAL` (or `-Dassets.auth.credential`), requests balance, hold and feed-position snapshots, prints one JSON document and exits `0`, or `3` when the 30 s snapshot deadline passes:

```json
{
  "balances": [{"userId": 900001, "assetId": 0, "available": 900, "locked": 100}],
  "holds":    [{"orderId": 111, "userId": 900001, "assetId": 0, "remaining": 100}],
  "consumePosition": 88231,
  "lastAppliedTradeId": 45012
}
```

The snapshot requests do not change AE state.
