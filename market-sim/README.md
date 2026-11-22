# market-sim

Agent-based market simulator and synthetic health check for Open Exchange. It drives the real user path: the gateway REST API under `/api/v2` (`oe-gateway`), with maker, taker, noise and depth agents anchored to a reference price (live Binance returns when reachable, a GBM random walk when not). It follows the bots' orders on the user stream (`oe-stream`, `/ws/v2`) and doubles as the demo canary: it keeps checking that orders flow, fills happen, market data moves, settlement runs and the browser-facing CORS surface works.

## Build and run

```bash
go build -o market-sim .
go test ./...
./market-sim -version     # market-sim source <commit>: the tools commit the binary was linked with (unknown here)

# Fund the bot population (shortfall deposits only, safe to repeat; needs the gateway's treasury lane)
./market-sim -mode=seed -gateway-url=http://127.0.0.1:8080 -api-keys-file=/path/sim-keys -faucet-max=0:10000,1:5

# One-shot check: create a far-from-touch order, expect NEW, cancel, expect CANCELLED
./market-sim -mode=once -gateway-url=http://127.0.0.1:8080 -api-keys-file=/path/sim-keys

# Continuous simulation plus the health server
./market-sim -mode=run -gateway-url=http://127.0.0.1:8080 -stream-url=ws://127.0.0.1:8081/ws/v2 \
  -api-keys-file=/path/sim-keys -faucet-max=0:10000,1:5 -keyed-stats-file=/path/keyed.json
```

The release binary is the linux/arm64 cross-build of `runtime-e2e/arm64_sibling.py go-build`: pure Go, built twice from `git archive <commit>` and refused unless the two builds are byte-equal, with the commit linked in as `main.sourceSha`. A setting the simulator cannot run with (no `-stream-url` in run mode, a bad `-faucet-max`, missing API keys, no markets) is refused before anything is sent, with exit 78 and the key's name.

Gateway side: `GATEWAY_AUTH_MODES` and `STREAM_AUTH_MODES` include `api-key`, with the same keys in `GATEWAY_API_KEYS_FILE`. Seeding needs the treasury lane (`GATEWAY_TREASURY_CREDENTIAL` and `GATEWAY_ALLOW_TREASURY_LANE=1`).

## Auth and idempotency

- **One API key per bot user**, the canary included. Keys come from `-api-keys-file`, in the gateway's `GATEWAY_API_KEYS_FILE` format: one `key:userId` per line, `#` for comments. A user listed twice, or a bot user without a key, is refused at start.
- **Headers only.** Keys are sent as `X-API-Key`, never in a URL.
- **Dev auth.** `-dev-auth` sends `Authorization: Bearer dev:<userId>` instead. Only a gateway with `dev` in its auth modes and `GATEWAY_ALLOW_DEV_AUTH=1` accepts it.
- **One key per logical request.** Every create, amend and deposit (and every single cancel with `-keyed-cancels`) gets a fresh UUID `Idempotency-Key`.
- **Retries reuse that key.** A resend after a transport error, a 504, or a 503/429 `CORE_UNAVAILABLE`, `OVERLOADED` or `RATE_LIMITED` with `keyFinal:false` reuses the key. A keyed resend never starts later than `-retry-max-elapsed` after the first send (default: half of the gateway's `idempotencyWindowMs`); with no window known, a keyed request is never resent.
- **Unknown deposits are not funded twice.** A deposit whose outcome stayed unknown is remembered; the next seeding pass resends it with its own key before it reads the balance, and drops it once it is decided or past the window.

## Keyed request counters

The sim counts keyed requests per user, the count a per-user request cap over one window refuses on (retries are counted separately):

- the most a user sent inside any one window (sliding),
- per-window p50, p99 and max (tumbling),
- stored versus not-stored outcomes.

The window is `-keyed-window`; 0 means the gateway's `idempotencyWindowMs`. Every `-keyed-stats-interval` the counters are logged as a `[keyed]` line and written to `-keyed-stats-file` as JSON.

## Configuration

Flags win over environment variables. `./market-sim -h` lists every flag with its default.

| Flag | Env | Default |
|---|---|---|
| `-gateway-url` | `GATEWAY_URL` | `http://127.0.0.1:8080` (requests go to `<url>/api/v2/...`) |
| `-stream-url` | `SIM_STREAM_URL` | none; required in run mode unless `-user-stream=false` |
| `-api-keys-file` | `SIM_API_KEYS_FILE` | none |
| `-dev-auth` | `SIM_DEV_AUTH=1` | off |
| `-faucet-max` | `SIM_FAUCET_MAX` | none; per-request deposit cap as `assetId:amount,...` (the gateway's `GATEWAY_FAUCET_MAX_AMOUNT`) |
| `-keyed-stats-file` | `SIM_KEYED_STATS_FILE` | none (stats line only) |
| `-keyed-window`, `-keyed-stats-interval`, `-keyed-windows-kept` | | `0`, `30s`, `64` |
| `-keyed-cancels` | | off |
| `-retry-attempts`, `-retry-backoff`, `-retry-max-backoff`, `-retry-max-elapsed` | | `4`, `200ms`, `2s`, `0` |
| `-http-timeout` | | `10s` per attempt |
| `-boot-wait` | | `2m` for `/api/v2/status` to read ready |
| `-market-ws-url` | `MARKET_WS_URL` | `ws://127.0.0.1:8081/ws` |
| `-source` | `SIM_SOURCE` | `auto` (`auto`, `binance`, `gbm`) |
| `-binance-url` | `SIM_BINANCE_URL` | `wss://stream.binance.com:9443/ws` |
| `-health-addr` | `SIM_HEALTH_ADDR` | `127.0.0.1:8090` (empty disables) |
| `-cors-origin` | `SIM_CORS_ORIGIN` | origin the CORS canary asserts |
| `-public-url` | `SIM_PUBLIC_URL` | public gateway edge probed by the CORS canary (empty: local only) |
| `-edge-ws-url` | `SIM_EDGE_WS_URL` | public market-data WebSocket to watch (empty: check disabled) |
| `-bridge-health-url` | `SIM_BRIDGE_HEALTH_URL` | `http://127.0.0.1:9600/health` |
| `-anchor-file` | `SIM_ANCHOR_FILE` | `anchors.json` (reference-price persistence, empty disables) |
| `-markets` | | all markets in `DefaultMarkets` |
| `-bot-base`, `-bots-per-market`, `-canary-bot` | | `900001`, `10`, `900999` |
| `-global-ops` | | `100` gateway operations per second across all markets |

## Health surface

- `GET /health`: 200 or 503 plus per-check JSON. Critical checks: `gateway_ready` (`/api/v2/status` reads ready), `market_data_fresh`, `fills_recent` (a fill within 5 minutes), `book_depth`, `canary_order_roundtrip` (create, NEW, cancel, CANCELLED on the canary bot), `edge_feed_fresh`, `settlement_flowing` (the bridge `/health` must not report halted) and the `cors_*` checks (a browser-style preflight and GET asserting `Access-Control-Allow-Origin` against the local gateway and the public edge). A critical check not refreshed within 2 minutes fails closed.
- `GET /metrics`: Prometheus text (`sim_healthy`, `sim_check{name,critical}`, `sim_orders_placed_total`, `sim_fills_total`, `sim_errors_total` and more).
- `POST /control`: `{"pause":true|false}` suspends or resumes agents; `{"source":"auto"|"binance"|"gbm"}` switches the reference source.

## Design points

- Returns, not price levels. Reference sources emit log-returns; a per-market anchor price, started inside the engine band, integrates them. Live prices can sit outside the band, and a source failover must not jump the price.
- Agents place and cancel. They never amend; a reprice is cancel then re-place.
- Money is an 8-decimal fixed-point string end to end (`oms.Money`); order ids stay strings.
- Rejects arrive as 4xx/503 error bodies; an error carrying a core `reason` is turned back into a reject. The engine's own decision arrives later on the stream.
- The sim sends no `clientOrderId`. The maker's orphan sweep cancels any order on its market it does not track, which is safe only because each bot user belongs to the sim alone.
- The user stream delivers only live `order` frames to the agents. The rows of an orders snapshot (sent on subscribe and after a `resync`) move only the resume position; after a resync an agent learns its open orders from its periodic reconcile read (`GET /api/v2/orders`).
- At start the sim refuses to run if a configured market id, symbol or tick differs from `GET /api/v2/markets`. Band and tick per market live in `DefaultMarkets` in `config.go`.
- Bot population: user ids from 900001 (10 per market by default) and the canary bot 900999, disjoint from dev and test user ranges. The stabilizer agent (900900 and up) is disabled by default in `config.go`.

## Packages

| Package | Purpose |
|---|---|
| `oms` | Typed client for the gateway v2 REST API and user stream, API keys, idempotency keys and keyed counters, the fixed-point `Money` type |
| `agents` | Maker, taker, noise, depth and stabilizer agents, rate limiting, scheduling |
| `dist` | Order-flow distributions |
| `refprice` | Reference-price sources: Binance WebSocket, GBM fallback, failover router |
| `feed` | Market-data WebSocket reader and local book |
| `health` | Health registry, canary, CORS probe, HTTP server |
| `accounts` | Idempotent bot funding |
