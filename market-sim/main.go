// market-sim: agent-based market simulator and synthetic demo health check
// for the Open Exchange stack. Drives the real user path (the gateway REST
// API, /api/v2) with maker, taker and noise agents anchored to a pluggable
// reference price (live Binance returns or a GBM fallback). Every bot user
// authenticates with its own API key and every create, amend, keyed cancel
// and deposit carries its own Idempotency-Key. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openexch/tools/market-sim/accounts"
	"github.com/openexch/tools/market-sim/oms"
)

func main() {
	cfg := DefaultConfig()
	mode := flag.String("mode", "run", "run | seed | once (seed: fund bots and exit; once: single order round-trip check)")
	flag.StringVar(&cfg.GatewayURL, "gateway-url", envOr("GATEWAY_URL", cfg.GatewayURL), "oe-gateway REST base URL (scheme://host:port; requests go to <url>/api/v2/...)")
	flag.StringVar(&cfg.StreamURL, "stream-url", envOr("SIM_STREAM_URL", ""), "oe-stream user stream URL, e.g. ws://127.0.0.1:8081/ws/v2 (required in run mode unless -user-stream=false)")
	userStream := flag.Bool("user-stream", true, "follow maker and depth bots on the user stream (false: reconcile passes only)")
	flag.StringVar(&cfg.MarketWSURL, "market-ws-url", envOr("MARKET_WS_URL", cfg.MarketWSURL), "match-gateway market-data WebSocket URL")
	keysFile := flag.String("api-keys-file", envOr("SIM_API_KEYS_FILE", ""), "API keys file, one `key:userId` per line ('#' comments; the gateway's GATEWAY_API_KEYS_FILE format, so one file can serve both). Exactly one key per bot user, the canary included. Keys are sent as X-API-Key, never in a URL")
	devAuth := flag.Bool("dev-auth", envOr("SIM_DEV_AUTH", "") == "1", "send `Authorization: Bearer dev:<userId>` instead of API keys; only a gateway with dev in GATEWAY_AUTH_MODES and GATEWAY_ALLOW_DEV_AUTH=1 accepts it")
	flag.BoolVar(&cfg.KeyedCancels, "keyed-cancels", false, "send an Idempotency-Key on single cancels (each then takes a request-table entry of the user)")
	bootWait := flag.Duration("boot-wait", 2*time.Minute, "how long to wait at start for the gateway's /status to read ready")
	flag.IntVar(&cfg.Retry.Attempts, "retry-attempts", 4, "sends per logical request, the first included")
	flag.DurationVar(&cfg.Retry.Backoff, "retry-backoff", 200*time.Millisecond, "first resend wait when the answer has no Retry-After (doubles per resend)")
	flag.DurationVar(&cfg.Retry.MaxBackoff, "retry-max-backoff", 2*time.Second, "cap of the doubled resend wait")
	flag.DurationVar(&cfg.Retry.MaxElapsed, "retry-max-elapsed", 0, "latest start of a keyed resend after the first send (0 = half the gateway's idempotencyWindowMs)")
	flag.DurationVar(&cfg.HTTPTimeout, "http-timeout", 10*time.Second, "per-attempt HTTP timeout (a timeout is an unknown outcome: resent with the same key)")
	flag.DurationVar(&cfg.KeyedWindow, "keyed-window", 0, "window of the per-user keyed request counters (0 = the gateway's idempotencyWindowMs, the request-table TTL)")
	flag.StringVar(&cfg.KeyedStatsFile, "keyed-stats-file", envOr("SIM_KEYED_STATS_FILE", ""), "JSON file the keyed request counters are written to (empty: stats line in the log only)")
	flag.DurationVar(&cfg.KeyedStatsEvery, "keyed-stats-interval", 30*time.Second, "how often the keyed stats line is logged and the file rewritten")
	flag.IntVar(&cfg.KeyedWindowsKept, "keyed-windows-kept", 64, "closed windows kept in the stats file")
	faucetMax := flag.String("faucet-max", envOr("SIM_FAUCET_MAX", ""), "per-request deposit cap as assetId:amount,... (the gateway's GATEWAY_FAUCET_MAX_AMOUNT); a larger shortfall is sent as several deposits")
	markets := flag.String("markets", "", "comma-separated market symbols to simulate (default: all)")
	flag.Int64Var(&cfg.BotBase, "bot-base", cfg.BotBase, "first bot userId (population is contiguous)")
	flag.IntVar(&cfg.BotsPerMarket, "bots-per-market", cfg.BotsPerMarket, "bots per market")
	flag.Int64Var(&cfg.CanaryBot, "canary-bot", cfg.CanaryBot, "userId of the canary bot")
	source := flag.String("source", envOr("SIM_SOURCE", "auto"), "reference price source: auto | binance | gbm")
	binanceURL := flag.String("binance-url", envOr("SIM_BINANCE_URL", "wss://stream.binance.com:9443/ws"), "Binance WS base URL")
	globalOps := flag.Float64("global-ops", 100, "global gateway operations/sec cap across all markets")
	healthAddr := flag.String("health-addr", envOr("SIM_HEALTH_ADDR", "127.0.0.1:8090"), "health/metrics/control listen address (empty = disabled)")
	corsOrigin := flag.String("cors-origin", envOr("SIM_CORS_ORIGIN", "https://trade.openexch.io"), "browser origin asserted by the CORS canary")
	publicURL := flag.String("public-url", envOr("SIM_PUBLIC_URL", ""), "public gateway edge probed by the CORS canary (empty = local only)")
	edgeWS := flag.String("edge-ws-url", envOr("SIM_EDGE_WS_URL", ""), "public market-data WS to watch (the edge relay viewer path; empty = check disabled)")
	bridgeHealth := flag.String("bridge-health-url", envOr("SIM_BRIDGE_HEALTH_URL", "http://127.0.0.1:9600/health"), "settlement bridge health endpoint; a HALTED bridge stops all money settlement and leaks holds (empty = check disabled)")
	anchorFile := flag.String("anchor-file", envOr("SIM_ANCHOR_FILE", "anchors.json"), "reference-price persistence file (empty = disabled)")
	version := flag.Bool("version", false, "print the tools commit this binary was built from and exit")
	flag.Parse()
	if *version {
		printVersion()
		return
	}
	cfg.SelectMarkets(*markets)

	if len(cfg.Markets) == 0 {
		refuseConfig("-markets", "no markets selected")
	}
	if !*userStream {
		cfg.StreamURL = ""
	} else if *mode == "run" && cfg.StreamURL == "" {
		refuseConfig("SIM_STREAM_URL", "-stream-url is required in run mode (or -user-stream=false to run on reconcile passes only)")
	}
	var err error
	if cfg.FaucetMax, err = parseFaucetMax(*faucetMax); err != nil {
		refuseConfig("SIM_FAUCET_MAX", "-faucet-max: %v", err)
	}
	creds, err := loadCredentials(*keysFile, *devAuth, cfg.Users())
	if err != nil {
		refuseConfig("SIM_API_KEYS_FILE", "%v", err)
	}

	client := oms.NewClient(cfg.GatewayURL, creds)
	client.HTTP.Timeout = cfg.HTTPTimeout
	client.Retry = cfg.Retry
	client.KeyedCancels = cfg.KeyedCancels
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// /status first: it gives the idempotency window the keyed resends and
	// the counters are bounded by.
	if err := awaitReady(ctx, client, *bootWait); err != nil {
		log.Fatalf("gateway %s: %v", cfg.GatewayURL, err)
	}
	window := cfg.KeyedWindow
	if window <= 0 {
		window = client.IdempotencyWindow()
	}
	if window <= 0 {
		log.Fatal("the gateway's /status gave no idempotencyWindowMs: set -keyed-window")
	}
	client.Keyed = oms.NewKeyedCounter(window, cfg.KeyedWindowsKept)
	log.Printf("[main] gateway %s auth=%s idempotencyWindow=%s keyedWindow=%s keyedCancels=%v",
		cfg.GatewayURL, creds.Mode(), client.IdempotencyWindow(), window, cfg.KeyedCancels)
	statsDone := keyedStats(ctx, client.Keyed, cfg.KeyedStatsFile, cfg.KeyedStatsEvery)
	defer statsDone()

	if *mode != "seed" {
		if err := checkMarkets(ctx, &cfg, client); err != nil {
			log.Fatalf("markets: %v", err)
		}
	}

	switch *mode {
	case "seed":
		if err := seed(ctx, &cfg, client); err != nil {
			statsDone()
			log.Fatalf("seed failed: %v", err)
		}
	case "once":
		if err := onceCheck(ctx, &cfg, client); err != nil {
			statsDone()
			log.Fatalf("once check FAILED: %v", err)
		}
		log.Print("once check OK")
	case "run":
		hOpts := HealthOpts{Addr: *healthAddr, CORSOrigin: *corsOrigin, PublicURL: *publicURL, EdgeWSURL: *edgeWS, BridgeHealthURL: *bridgeHealth}
		if err := run(ctx, &cfg, client, *source, *binanceURL, *globalOps, hOpts, *anchorFile); err != nil {
			statsDone()
			log.Fatalf("run failed: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// awaitReady polls /api/v2/status until ready (a gateway that is still
// registering its core session reads not ready), for at most wait.
func awaitReady(ctx context.Context, client *oms.Client, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := client.Health(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return fmt.Errorf("not ready after %s: %w", wait, err)
		}
		log.Printf("[main] waiting for the gateway: %v", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// loadCredentials picks exactly one auth scheme. With a keys file every bot
// user the run drives must have a key; a missing one is refused here, not
// found later as 401s.
func loadCredentials(keysFile string, dev bool, users []int64) (oms.Credentials, error) {
	switch {
	case keysFile != "" && dev:
		return nil, errors.New("give -api-keys-file or -dev-auth, not both")
	case dev:
		return oms.DevAuth{}, nil
	case keysFile == "":
		return nil, errors.New("-api-keys-file is required (or -dev-auth for a dev gateway)")
	}
	keys, err := oms.LoadAPIKeys(keysFile)
	if err != nil {
		return nil, fmt.Errorf("-api-keys-file: %w", err)
	}
	if missing := keys.Missing(users); len(missing) > 0 {
		return nil, fmt.Errorf("-api-keys-file %s has no key for bot user(s) %v", keysFile, missing)
	}
	return keys, nil
}

// parseFaucetMax reads assetId:amount,... ("" = no caps).
func parseFaucetMax(s string) (map[int]oms.Money, error) {
	out := map[int]oms.Money{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		id, amount, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			return nil, fmt.Errorf("%q: expected assetId:amount", part)
		}
		asset, err := strconv.Atoi(id)
		if err != nil || asset < 0 {
			return nil, fmt.Errorf("%q: assetId must be a non-negative integer", part)
		}
		m, err := oms.ParseMoney(amount)
		if err != nil || m <= 0 {
			return nil, fmt.Errorf("%q: amount must be a positive decimal", part)
		}
		if _, dup := out[asset]; dup {
			return nil, fmt.Errorf("asset %d listed twice", asset)
		}
		out[asset] = m
	}
	return out, nil
}

// keyedStats logs the keyed request counters every interval and rewrites
// the JSON file; the returned func writes a last snapshot once.
func keyedStats(ctx context.Context, k *oms.KeyedCounter, file string, every time.Duration) func() {
	emit := func() {
		s := k.Snapshot()
		log.Printf("[keyed] %s", s.Line())
		if file != "" {
			if err := s.WriteFile(file); err != nil {
				log.Printf("[keyed] write %s: %v", file, err)
			}
		}
	}
	stop := make(chan struct{})
	finished := make(chan struct{})
	if every > 0 {
		go func() {
			defer close(finished)
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stop:
					return
				case <-t.C:
					emit()
				}
			}
		}()
	} else {
		close(finished)
	}
	done := false
	return func() {
		if done {
			return
		}
		done = true
		close(stop)
		<-finished
		emit()
	}
}

// checkMarkets compares the configured markets with the core's config
// (GET /api/v2/markets): a configured market the core does not list, another
// symbol or another tick is refused, because every order would be rejected
// or priced on the wrong grid. A band outside the core's min/max price is
// logged.
func checkMarkets(ctx context.Context, cfg *Config, client *oms.Client) error {
	got, err := client.Markets(ctx)
	if err != nil {
		return err
	}
	byID := map[int]oms.MarketInfo{}
	for _, m := range got {
		byID[int(m.MarketID)] = m
	}
	var problems []string
	for _, m := range cfg.Markets {
		core, ok := byID[m.ID]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("market %d (%s) is not in the core config", m.ID, m.Symbol))
			continue
		case core.Symbol != m.Symbol:
			problems = append(problems, fmt.Sprintf("market %d is %s in the core, %s here", m.ID, core.Symbol, m.Symbol))
		case core.TickSize != m.Tick:
			problems = append(problems, fmt.Sprintf("market %d (%s) tick is %s in the core, %s here", m.ID, m.Symbol, core.TickSize, m.Tick))
		}
		if core.MinPrice > 0 && m.BandLo < core.MinPrice || core.MaxPrice > 0 && m.BandHi > core.MaxPrice {
			log.Printf("[markets] %s band %s..%s is outside the core's %s..%s", m.Symbol, m.BandLo, m.BandHi, core.MinPrice, core.MaxPrice)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// seed funds the whole bot population (idempotent shortfall deposits).
// Depth-keeper bots carry larger floats: they are the structural liquidity
// and a sustained pump can sell a plain float through in minutes.
func seed(ctx context.Context, cfg *Config, client *oms.Client) error {
	var targets []accounts.Target
	for i, m := range cfg.Markets {
		for j, bot := range cfg.Bots(i) {
			usd, base := cfg.USDFloat, m.BaseFloat
			if j >= makersPerMarket+takersPerMarket && j < makersPerMarket+takersPerMarket+depthPerMarket {
				usd, base = usd*3, base*3
			}
			targets = append(targets, accounts.Target{
				UserID: bot, USD: usd,
				BaseAsset: m.BaseAssetID, BaseFloat: base,
			})
		}
	}
	// The per-market stabilizer is the liquidity backstop: fund it well above
	// every other bot (both sides) so it can always quote the missing side.
	if cfg.StabilizerEnabled {
		mult := cfg.StabilizerFundMult
		if mult < 1 {
			mult = 1
		}
		for i, m := range cfg.Markets {
			targets = append(targets, accounts.Target{
				UserID: cfg.StabilizerBot(i), USD: cfg.USDFloat * oms.Money(mult),
				BaseAsset: m.BaseAssetID, BaseFloat: m.BaseFloat * oms.Money(mult),
			})
		}
	}
	// The canary bot trades every market at tiny size; fund USD only plus a
	// sliver of each base asset via the first market's target row.
	targets = append(targets, accounts.Target{UserID: cfg.CanaryBot, USD: cfg.USDFloat})
	s := &accounts.Seeder{Client: client, FaucetMax: cfg.FaucetMax}
	// Retry the whole pass on transient failure (e.g. the core briefly
	// unavailable at boot): a crash here disarms the sim service and takes the
	// demo down. Every deposit is resent only with its own Idempotency-Key.
	// A deposit whose outcome stayed unknown is kept by the seeder: the next
	// pass resends it under that key before it reads the balance, and funds
	// no shortfall of that asset while it is still unknown, so a deposit
	// still in flight is never funded a second time under a new key.
	const maxAttempts = 6
	var n int
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		n, err = s.Seed(ctx, targets)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt == maxAttempts {
			return fmt.Errorf("seeding bots: %w (after %d attempts)", err, maxAttempts)
		}
		backoff := time.Duration(attempt) * time.Second
		log.Printf("[seed] attempt %d/%d failed (%v); retrying in %s", attempt, maxAttempts, err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	log.Printf("[seed] %d bots checked, %d deposits made", len(targets), n)
	return nil
}

// onceCheck exercises the full order lifecycle once, far from the touch so
// nothing fills: create (201 PENDING_NEW) -> NEW via GET -> cancel -> closed.
func onceCheck(ctx context.Context, cfg *Config, client *oms.Client) error {
	m := cfg.Markets[0]
	bot := cfg.CanaryBot

	// Fund the canary enough for one far bid.
	s := &accounts.Seeder{Client: client, FaucetMax: cfg.FaucetMax}
	if _, err := s.Seed(ctx, []accounts.Target{{UserID: bot, USD: cfg.USDFloat}}); err != nil {
		return err
	}

	// Bid pinned to the band floor: deep out of the money, engine-legal.
	price := m.BandLo.RoundToTick(m.Tick)
	qty := oms.MoneyFromFloat(m.MinQty)
	resp, err := client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: bot, MarketID: m.ID, Side: "BUY", OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: qty,
	})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if !resp.Accepted {
		return fmt.Errorf("create rejected: %q", resp.RejectReason)
	}
	log.Printf("[once] created %s (%s) on %s at %s x %s", resp.OrderID, resp.Status, m.Symbol, price, qty)

	// The matching engine's ack: the order must reach a resting status.
	deadline := time.Now().Add(10 * time.Second)
	for {
		o, err := client.GetOrder(ctx, bot, resp.OrderID)
		if err == nil && (o.Status == "NEW" || o.Status == "PARTIALLY_FILLED") {
			break
		}
		if err == nil && oms.IsTerminalStatus(o.Status) {
			return fmt.Errorf("order went terminal before cancel: %s (reason %q)", o.Status, o.Reason)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("order never reached NEW (last err %v)", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}

	if err := client.CancelOrder(ctx, bot, resp.OrderID); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}
	// A closed order is read from history. A gateway without history answers
	// 503 HISTORY_UNAVAILABLE; only then the order's absence from the open
	// orders is accepted as closed.
	deadline = time.Now().Add(10 * time.Second)
	for {
		o, err := client.GetOrder(ctx, bot, resp.OrderID)
		if err == nil && o.Status == "CANCELLED" {
			return nil
		}
		var apiErr *oms.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "HISTORY_UNAVAILABLE" {
			open, lerr := client.ActiveOrders(ctx, bot)
			if lerr == nil && !hasOrder(open, resp.OrderID) {
				log.Printf("[once] %s is no longer open (the gateway has no history to show CANCELLED)", resp.OrderID)
				return nil
			}
		}
		if time.Now().After(deadline) {
			status := "unknown"
			if err == nil {
				status = o.Status
			}
			return fmt.Errorf("order never CANCELLED (last status %s, err %v)", status, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func hasOrder(list []oms.OrderResponse, id string) bool {
	for _, o := range list {
		if o.OrderID == id {
			return true
		}
	}
	return false
}
