# market-sim

Agent-based market simulator and synthetic demo health check for the Open
Exchange stack. Drives the real user path (OMS REST, `/api/v1`) with
maker/taker/noise agents anchored to a pluggable reference price: live
Binance returns when reachable, a GBM random walk when not. Doubles as the
demo canary: it continuously proves that orders flow, fills happen, market
data moves, and the browser-facing CORS surface works.

Status: Phase 0 (scaffold). `run` mode lands in Phase 1.

## Modes

```bash
go build -o market-sim .

# Fund the bot population (idempotent shortfall deposits; safe on every boot)
./market-sim -mode=seed

# One-shot end-to-end check: create far-from-touch -> NEW -> cancel -> CANCELLED
./market-sim -mode=once

# Continuous simulation + health server (Phase 1+)
./market-sim
```

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
