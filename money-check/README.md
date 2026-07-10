# money-check

The live-money guardrail for the Open Exchange **cutover soak**. `money_check.py` reconciles
the money ledger against three invariants and exits non-zero the moment one breaks. It is
**read-only** end to end: it issues `SCAN`/`HGETALL`/`GET` to Redis, `GET` to the OMS, and (in
AE mode) shells to a read-only snapshot CLI. It never writes.

It reads the ledger from either store behind one interface, so you run the *same* checks against
the Redis projection today and the Assets Engine during and after cutover:

- `--store redis` (default) reads Redis `db0` directly (`bal:{userId}` hashes).
- `--store ae` shells to the **AeDump** CLI (in the `assets` repo) and reads its JSON snapshot.

Python 3, standard library only. No `pip install` needed: it speaks RESP over a socket with a
tiny built-in client, and will transparently use the `redis` package instead if it happens to be
importable.

## The three invariants

**1. Per-asset conservation (deposit-aware).** For every asset:

```
Σ_users (available + locked)  ==  Σ deposits − Σ withdrawals
```

Trading only moves value *within* an asset (base seller→buyer, quote buyer→seller), so it never
changes an asset's global total. Only deposits and withdrawals do. The simulator re-seeds bots
toward a target roughly every 3 minutes, so the right-hand side grows over time; we recover it by
summing the `deposited … of asset N` lines out of the sim log (`--sim-log`, default
`~/.local/log/cluster/sim.log`). If the log does not reach the clean-slate genesis (detected by
`had 0.00000000` on the first deposit per asset), an absolute total cannot be asserted and the
check reports **INDETERMINATE** rather than a false breach.

**2. `locked` == Σ open-order holds.** The **authoritative** expected `locked` per (user, asset)
is derived from the **OMS open-orders API** (`GET /api/v1/orders`, header
`Authorization: Bearer dev:<userId>`):

```
BUY  order locks the QUOTE asset (USD):  price × remainingQty
SELL order locks the BASE  asset:        remainingQty
```

**3. Non-negativity.** No `available < 0` and no `locked < 0`, ever.

Amounts are 8-decimal fixed-point `int64` throughout.

## Two traps this tool exists to avoid

### `holds:{u}` is a trap — never reconcile against it
Redis has a `holds:{u}` hash, but it is **write-only and leaks on settle**: entries are added
when a hold is placed and are not reliably removed when an order settles, so it accumulates stale
holds (you will see `holds:{u}` populated for users the OMS reports as having *zero* open orders).
Reconciling `locked` against `holds:{u}` would hide real breaches behind stale noise. This tool
**only** uses the OMS open-orders API as the authoritative expected-hold side, and `bal:{u}` /
the AE balance snapshot as the actual `locked`.

### The amend / fill-netting caveat on BUY holds
The OMS does **not** expose the order's stored `holdAmount`, so the tool computes the BUY hold as
`price × remainingQty`. When a BUY order **partially fills at a better price than its limit** (a
taker buy matched against cheaper resting asks), the AE's residual hold is
`originalHold − Σ(fillPrice × fillQty)`, which is **larger** than `price × remainingQty` by the
price improvement on the filled quantity. Result: for partially-filled BUY orders the actual
`locked` is legitimately a hair **higher** than the computed expectation. This drift is:

- always **positive** (actual ≥ expected — *over*-collateralized, the safe direction);
- bounded by `Σ (limitPrice − fillPrice) × filledQty`, typically sub-cent per order;
- exactly **zero** for any order with `filledQty == 0`.

A **negative** locked gap (actual < expected — *under*-collateralized) is the dangerous direction
and is never explained by this caveat; treat it as a real finding.

## Usage

```bash
# one green/red sweep (default: redis store, OMS at :8080, sim log at the default path)
python3 money_check.py

# machine-readable, one JSON object to stdout
python3 money_check.py --json

# continuous soak: one status line per sweep, every 60s, rolling violation count
python3 money_check.py --loop 60

# against the Assets Engine (needs the AeDump jar built — see the assets repo)
python3 money_check.py --store ae \
    --ae-dump-cmd "java -jar /path/assets-bridge/target/assets-bridge.jar dump"
```

Key flags: `--store {redis,ae}`, `--oms-url`, `--sim-log` (repeatable / globs),
`--redis-host/-port/-db`, `--ae-dump-cmd`, `--ae-timeout`, `--asset-map "USD=0,BTC=1,…"`,
`--users 900000-900999`, `--tolerance N` (per-row 8dp int gap tolerated), `--loop SECONDS`,
`--max-sweeps N`, `--json`, `--verbose`.

Default asset map (mirrors the engine's `MarketConfig` as carried by the market-sim
`DefaultMarkets` table): `USD=0, BTC=1, ETH=2, SOL=3, XRP=4, DOGE=5`. Override with `--asset-map`
if a deployment renumbers assets.

**Exit codes:** `0` all green · `2` an invariant was violated · `1` operational error
(store/OMS unreachable in a way that prevents the check, AeDump timeout, etc.). In `--loop` mode
the process runs until `Ctrl-C` (or `--max-sweeps`) and then exits `2` if *any* sweep violated.

## Reading the output on a live, actively-trading stack

A single sweep is not atomic across the store and the OMS, and the sim never stops trading, so on
a live stack expect **explainable transient drift** on invariant 2 (`locked`):

- the fill/amend caveat above (persistent but tiny, always positive), plus
- read-time skew on the fastest markets (DOGE), which can reach a few dollars on the most active
  traders for the fraction of a second between the balance snapshot and that user's OMS read.

Invariants 1 (conservation) and 3 (non-negativity) should be **green** essentially always; a
one-off tiny conservation gap is an in-flight settle caught mid-projection and clears on the next
sweep. Watch for the things that are **never** benign: any **negative** locked gap, a **growing**
or **sustained** drift on the same (user, asset) across sweeps, a conservation gap that does not
clear, or any non-negativity failure.

## Cutover-soak recipe

The gate for promoting the Assets Engine to the money source of record:

1. **Baseline (Redis).** `python3 money_check.py --store redis --loop 60` for the soak window.
   Expect conservation and non-negativity green throughout; locked drift only ever positive and
   bounded as described. Any negative or sustained/growing drift halts the cutover.
2. **Point-in-time authoritative check.** For a clean green with no read-skew noise, **quiesce
   the sim** (pause new orders so holds stop churning) and run a single `--store redis` sweep and
   a single `--store ae` sweep; both must be fully green and agree.
3. **Cross-store agreement.** With the AE live alongside Redis, run `--store ae` — it adds the
   `ae_holds_vs_locked` internal check (the AE's own hold entries must sum to its own `locked`)
   on top of the three invariants, and reports `consumePosition` / `lastAppliedTradeId` so you can
   confirm the AE has consumed up to the expected ME journal position before you cut over.
4. **Hold the gate open through the soak** with `--loop` + `--json` piped to your alerting; a
   non-zero final exit or any negative/sustained drift fails the gate.

## AeDump (the `--store ae` backend)

`AeDump` lives in the `assets` repo (`com.openexchange.assets.bridge.AeDump`, dispatched by
`assets-bridge` as `java -jar assets-bridge.jar dump`). It connects an `AeronCluster` client,
sends `RequestBalanceSnapshot` + `RequestHoldSnapshot` + `QueryFeedPosition`, collects the
streamed `BalanceUpdate` / `HoldSnapshotEntry` up to the matching `*End` messages, and prints one
JSON document then exits `0` (exit `3` on a 30 s snapshot timeout):

```json
{
  "balances": [{"userId": 900001, "assetId": 0, "available": 900, "locked": 100}],
  "holds":    [{"orderId": 111,    "userId": 900001, "assetId": 0, "remaining": 100}],
  "consumePosition": 88231,
  "lastAppliedTradeId": 45012
}
```

All snapshot requests are read-only and deterministic no-ops on AE state.
