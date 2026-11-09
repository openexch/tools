# market-sim

Agent-based market simulator and synthetic health check for the v0.5 Open Exchange stack. It drives the real user path, the OMS REST API under `/api/v1`, with maker, taker, noise and depth agents anchored to a reference price: live Binance returns when reachable, a GBM random walk when not. It doubles as the demo canary: it keeps checking that orders flow, fills happen, market data moves, settlement runs and the browser-facing CORS surface works.

v1 has no user-facing gateway yet, so market-sim does not drive a v1 stack.

## Build and run

```bash
go build -o market-sim .
go test ./...

# Fund the bot population (shortfall deposits only, safe to repeat)
./market-sim -mode=seed

# One-shot check: create a far-from-touch order, expect NEW, cancel, expect CANCELLED
./market-sim -mode=once

# Continuous simulation plus the health server
./market-sim -mode=run -source=auto -global-ops=60
```

## Configuration

Flags win over environment variables. Defaults are from `main.go` and `config.go`.

| Flag | Env | Default |
|---|---|---|
| `-oms-url` | `OMS_URL` | `http://127.0.0.1:8080` |
| `-market-ws-url` | `MARKET_WS_URL` | `ws://127.0.0.1:8081/ws` |
| `-auth-template` | `SIM_AUTH_TEMPLATE` | `dev:%d` (sent as `Bearer dev:<userId>`) |
| `-source` | `SIM_SOURCE` | `auto` (`auto`, `binance`, `gbm`) |
| `-binance-url` | `SIM_BINANCE_URL` | `wss://stream.binance.com:9443/ws` |
| `-health-addr` | `SIM_HEALTH_ADDR` | `127.0.0.1:8090` (empty disables) |
| `-cors-origin` | `SIM_CORS_ORIGIN` | origin the CORS canary asserts |
| `-oms-public-url` | `SIM_PUBLIC_OMS_URL` | public OMS edge probed by the CORS canary (empty: local only) |
| `-edge-ws-url` | `SIM_EDGE_WS_URL` | public market-data WebSocket to watch (empty: check fails as not configured) |
| `-bridge-health-url` | `SIM_BRIDGE_HEALTH_URL` | `http://127.0.0.1:9600/health` |
| `-anchor-file` | `SIM_ANCHOR_FILE` | `anchors.json` (reference-price persistence, empty disables) |
| `-markets` | | all markets in `DefaultMarkets` |
| `-bot-base`, `-bots-per-market` | | `900001`, `10` |
| `-global-ops` | | `100` OMS operations per second across all markets |

## Health surface

- `GET /health`: 200 or 503 plus per-check JSON. Critical checks: `oms_reachable`, `market_data_fresh`, `fills_recent` (a fill within 5 minutes), `book_depth`, `canary_order_roundtrip` (create, NEW, cancel, CANCELLED on bot 900999), `edge_feed_fresh`, `settlement_flowing` (the bridge `/health` must not report halted) and the `cors_*` checks (a browser-style preflight and GET asserting `Access-Control-Allow-Origin` against the local OMS and the public edge). A critical check not refreshed within 2 minutes fails closed.
- `GET /metrics`: Prometheus text (`sim_healthy`, `sim_check{name,critical}`, `sim_orders_placed_total`, `sim_fills_total`, `sim_errors_total` and more).
- `POST /control`: `{"pause":true|false}` suspends or resumes agents (for example before an ad-hoc load test); `{"source":"auto"|"binance"|"gbm"}` switches the reference source.

## Design points

- Returns, not price levels. Reference sources emit log-returns; a per-market anchor price, started inside the engine band, integrates them. Live prices can sit outside the band, and a source failover must not jump the price.
- Agents place and cancel. They never amend; a reprice is cancel then re-place.
- Money is an 8-decimal fixed-point string end to end (`oms.Money`); order ids stay strings.
- Bot population: user ids from 900001 (10 per market by default) and the canary bot 900999, disjoint from dev and test user ranges. The stabilizer agent (900900 and up) is disabled by default in `config.go`.
- Engine constraints are configuration. Band and tick per market live in `DefaultMarkets` in `config.go` because the API does not expose them; an off-tick or out-of-band order is rejected by the engine.

## Packages

| Package | Purpose |
|---|---|
| `oms` | Typed client for the OMS v1 REST API and the fixed-point `Money` type |
| `agents` | Maker, taker, noise, depth and stabilizer agents, rate limiting, scheduling |
| `dist` | Order-flow distributions |
| `refprice` | Reference-price sources: Binance WebSocket, GBM fallback, failover router |
| `feed` | Market-data WebSocket reader and local book |
| `health` | Health registry, canary, CORS probe, HTTP server |
| `accounts` | Idempotent bot funding |
