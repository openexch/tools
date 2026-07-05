// market-sim: agent-based market simulator + synthetic demo health check for
// the Open Exchange stack. Drives the real user path (OMS REST) with maker/
// taker/noise agents anchored to a pluggable reference price (live Binance
// returns or a GBM fallback). See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openexch/tools/market-sim/accounts"
	"github.com/openexch/tools/market-sim/oms"
)

func main() {
	cfg := DefaultConfig()
	mode := flag.String("mode", "run", "run | seed | once (seed: fund bots and exit; once: single order round-trip check)")
	flag.StringVar(&cfg.OMSBaseURL, "oms-url", envOr("OMS_URL", cfg.OMSBaseURL), "OMS REST base URL")
	flag.StringVar(&cfg.MarketWSURL, "market-ws-url", envOr("MARKET_WS_URL", cfg.MarketWSURL), "match-gateway WebSocket URL")
	flag.StringVar(&cfg.AuthTemplate, "auth-template", envOr("SIM_AUTH_TEMPLATE", cfg.AuthTemplate), "bearer token template receiving the bot userId")
	markets := flag.String("markets", "", "comma-separated market symbols to simulate (default: all)")
	flag.Int64Var(&cfg.BotBase, "bot-base", cfg.BotBase, "first bot userId (population is contiguous)")
	flag.IntVar(&cfg.BotsPerMarket, "bots-per-market", cfg.BotsPerMarket, "bots per market")
	source := flag.String("source", envOr("SIM_SOURCE", "auto"), "reference price source: auto | binance | gbm")
	binanceURL := flag.String("binance-url", envOr("SIM_BINANCE_URL", "wss://stream.binance.com:9443/ws"), "Binance WS base URL")
	globalOps := flag.Float64("global-ops", 100, "global OMS operations/sec cap across all markets")
	healthAddr := flag.String("health-addr", envOr("SIM_HEALTH_ADDR", "127.0.0.1:8090"), "health/metrics/control listen address (empty = disabled)")
	corsOrigin := flag.String("cors-origin", envOr("SIM_CORS_ORIGIN", "https://trade.openexch.io"), "browser origin asserted by the CORS canary")
	publicOMS := flag.String("oms-public-url", envOr("SIM_PUBLIC_OMS_URL", "https://oms.openexch.io"), "public OMS edge probed by the CORS canary (empty = local only)")
	anchorFile := flag.String("anchor-file", envOr("SIM_ANCHOR_FILE", "anchors.json"), "reference-price persistence file (empty = disabled)")
	flag.Parse()
	cfg.SelectMarkets(*markets)

	if len(cfg.Markets) == 0 {
		log.Fatal("no markets selected")
	}

	client := oms.NewClient(cfg.OMSBaseURL, cfg.AuthTemplate)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "seed":
		if err := seed(ctx, &cfg, client); err != nil {
			log.Fatalf("seed failed: %v", err)
		}
	case "once":
		if err := onceCheck(ctx, &cfg, client); err != nil {
			log.Fatalf("once check FAILED: %v", err)
		}
		log.Print("once check OK")
	case "run":
		hOpts := HealthOpts{Addr: *healthAddr, CORSOrigin: *corsOrigin, PublicOMSURL: *publicOMS}
		if err := run(ctx, &cfg, client, *source, *binanceURL, *globalOps, hOpts, *anchorFile); err != nil {
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
	// The canary bot trades every market at tiny size; fund USD only plus a
	// sliver of each base asset via the first market's target row.
	targets = append(targets, accounts.Target{UserID: cfg.CanaryBot, USD: cfg.USDFloat})
	s := &accounts.Seeder{Client: client}
	n, err := s.Seed(ctx, targets)
	if err != nil {
		return err
	}
	log.Printf("[seed] %d bots checked, %d deposits made", len(targets), n)
	return nil
}

// onceCheck exercises the full order lifecycle once, far from the touch so
// nothing fills: create -> visible via GET -> cancel -> terminal. This is
// the Phase 0 verification path and the skeleton of the Phase 3 canary.
func onceCheck(ctx context.Context, cfg *Config, client *oms.Client) error {
	m := cfg.Markets[0]
	bot := cfg.CanaryBot

	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("OMS health: %w", err)
	}
	// Fund the canary enough for one far bid.
	s := &accounts.Seeder{Client: client}
	if _, err := s.Seed(ctx, []accounts.Target{{UserID: bot, USD: cfg.USDFloat}}); err != nil {
		return err
	}

	// Bid pinned to the band floor: deep out of the money, engine-legal.
	price := m.BandLo.RoundToTick(m.Tick)
	qty := oms.MoneyFromFloat(m.MinQty)
	clientID := fmt.Sprintf("sim-once-%d", time.Now().UnixMilli())
	resp, err := client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: bot, MarketID: m.ID, Side: "BUY", OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: qty, ClientOrderID: clientID,
	})
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	if !resp.Accepted {
		return fmt.Errorf("create rejected: %q", resp.RejectReason)
	}
	log.Printf("[once] created %s on %s at %s x %s", resp.OmsOrderID, m.Symbol, price, qty)

	// Order must become visible and reach a resting status.
	deadline := time.Now().Add(10 * time.Second)
	for {
		o, err := client.GetOrder(ctx, bot, resp.OmsOrderID)
		if err == nil && (o.Status == "NEW" || o.Status == "PARTIALLY_FILLED") {
			break
		}
		if err == nil && oms.IsTerminalStatus(o.Status) {
			return fmt.Errorf("order went terminal before cancel: %s (reject %q)", o.Status, o.RejectReason)
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

	if err := client.CancelOrder(ctx, bot, resp.OmsOrderID); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		o, err := client.GetOrder(ctx, bot, resp.OmsOrderID)
		if err == nil && o.Status == "CANCELLED" {
			return nil
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
