# market-sim

Agent-based market simulator and synthetic demo health check for the Open
Exchange stack. Drives the real user path (OMS REST, `/api/v1`) with
maker/taker/noise agents anchored to a pluggable reference price: live
Binance returns when reachable, a GBM random walk when not. Doubles as the
demo canary: it continuously proves that orders flow, fills happen, market
data moves, and the browser-facing CORS surface works.

## Modes

```bash
go build -o market-sim .

# Fund the bot population (idempotent shortfall deposits; safe on every boot)
./market-sim -mode=seed

# One-shot end-to-end check: create far-from-touch -> NEW -> cancel -> CANCELLED
./market-sim -mode=once

# Continuous simulation + health server
./market-sim -mode=run -source=auto -global-ops=60
```

In deployment the admin gateway runs the sim as the managed service `sim`
(pinned to the spare cores, `DependsOn: oms, market`).

## Health surface (:8090)

- `GET /health` — 200/503 plus per-check JSON. Critical checks: OMS
  reachable, market data fresh, a real fill within 5 minutes, the canary
  order round-trip (create → NEW → cancel → CANCELLED on bot 900999), and
  the **CORS canary**: a browser-style preflight + GET asserting
  `Access-Control-Allow-Origin` echoes the demo UI origin, against BOTH the
  local OMS and the public edge (`-oms-public-url`). This is the check that
  catches the regression class that once broke the demo for a day.
- `GET /metrics` — Prometheus text (`sim_healthy`, `sim_check{name}`,
  order/fill/reject counters, canary round-trip, feed staleness).
- `POST /control` — `{"pause":true|false}` (suspend agents before ad-hoc
  load tests) and `{"source":"auto"|"binance"|"gbm"}`.

## Known server-side issues the sim works around

- PUT amend silently loses orders (oms#67): cancel+repost only.
- Open-order accounting drift (oms#65): OPEN_ORDER_LIMIT triggers an
  immediate reconcile + placement hold-off.
- The OMS REST server closes every connection (oms#66): keep-alives off.

## Key design points

- **Returns, not price levels.** Reference sources emit log-returns; a
  per-market anchor price (seeded inside the engine band) integrates them.
  Live BTC can sit outside the engine's 50k-150k band, and source failover
  must not jump the price.
- **Real order lifecycle.** Agents place, amend, and cancel through the
  frozen OMS v1 API with per-bot dev tokens (`Bearer dev:<userId>`,
  override `-auth-template`). Money is 8-dp decimal strings end-to-end
  (`oms.Money`); Snowflake ids stay strings.
- **Fixed bot population**: userIds 900001+ (10 per market by default),
  canary bot 900999. Disjoint from the dev/test user ranges.
- **Engine constraints are config** (`config.go`): band + tick per market
  mirror `MarketConfig` (not yet API-discoverable, match#64).

## Packages

| Package | Purpose |
|---|---|
| `oms` | Typed client for the frozen OMS v1 REST API + fixed-point `Money` |
| `dist` | Order-flow distributions (ported from `tools/binance-replay`) |
| `refprice` | Reference-price sources: Binance WS, GBM fallback, failover router |
| `accounts` | Idempotent bot funding |
