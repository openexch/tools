package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/openexch/tools/market-sim/agents"
	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/health"
	"github.com/openexch/tools/market-sim/oms"
	"github.com/openexch/tools/market-sim/refprice"
)

// pump forwards user-WS order events into a scheduler's fill channel
// (drop-on-full; the reconciler covers losses).
func pump(in <-chan oms.OrderResponse, out chan<- oms.OrderResponse) {
	for o := range in {
		select {
		case out <- o:
		default:
		}
	}
}

// passiveChecks derives health from the flow the agents already generate:
// OMS reachability, market-data freshness, and recent fills.
func passiveChecks(ctx context.Context, cfg *Config, client *oms.Client, feedClient *feed.Client,
	stats *agents.Stats, registry *health.Registry) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	lastFills := stats.Fills.Load()
	lastFillAt := time.Now()
	startedAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := client.Health(hctx)
			cancel()
			detail := ""
			if err != nil {
				detail = err.Error()
			}
			registry.Set("oms_reachable", err == nil, detail, true)

			stale := ""
			for _, m := range cfg.Markets {
				if age := time.Since(feedClient.View(m.ID).LastMsgAt); age > 30*time.Second {
					stale += m.Symbol + " "
				}
			}
			registry.Set("market_data_fresh", stale == "", strings.TrimSpace(stale), true)

			// The takers guarantee steady fills; silence means the trade
			// path (engine -> OMS -> user WS) stopped working end-to-end.
			if f := stats.Fills.Load(); f != lastFills {
				lastFills = f
				lastFillAt = time.Now()
			}
			quiet := time.Since(lastFillAt)
			registry.Set("fills_recent", quiet < 5*time.Minute,
				fmt.Sprintf("last fill %s ago", quiet.Truncate(time.Second)), true)

			// Book depth floor: the gateway broadcasts up to 20 levels per
			// side; the depth keeper's job is to keep that view full. Warmup
			// grace covers ladder build-up after a (re)start.
			if time.Since(startedAt) < 2*time.Minute {
				registry.Set("book_depth", true, "warming up", true)
			} else {
				thin := ""
				for _, m := range cfg.Markets {
					v := feedClient.View(m.ID)
					if len(v.Bids) < 18 || len(v.Asks) < 18 {
						thin += fmt.Sprintf("%s(%d/%d) ", m.Symbol, len(v.Bids), len(v.Asks))
					}
				}
				registry.Set("book_depth", thin == "", strings.TrimSpace(thin), true)
			}
		}
	}
}

// Population split within each market's bot pool (10 bots per market).
const (
	makersPerMarket = 4
	takersPerMarket = 3
	depthPerMarket  = 2 // one per SIDE: a fast move re-ladders within per-user rate limits
	noisePerMarket  = 1
)

// HealthOpts carries the Phase 3 observability configuration.
type HealthOpts struct {
	Addr         string // health server listen address ("" = disabled)
	CORSOrigin   string // demo UI origin asserted by the CORS canary
	PublicOMSURL string // public edge to probe ("" = local only)
}

// loadAnchors restores persisted reference prices so the chart continues
// where it left off across sim restarts instead of snapping back to the
// configured anchor start.
func loadAnchors(path string, router *refprice.Router) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return // first run
	}
	var anchors map[string]float64
	if json.Unmarshal(data, &anchors) != nil {
		return
	}
	for sym, a := range anchors {
		router.SetAnchor(sym, a)
	}
	log.Printf("[run] restored anchors from %s: %v", path, anchors)
}

func saveAnchors(path string, router *refprice.Router) {
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(router.Anchors(), "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0644) == nil {
		os.Rename(tmp, path)
	}
}

// run wires the whole sim: reference-price router -> agents -> OMS, with the
// observed book closing the loop, and blocks until ctx is cancelled.
func run(ctx context.Context, cfg *Config, client *oms.Client, source, binanceURL string, globalOps float64, hOpts HealthOpts, anchorFile string) error {
	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("OMS not reachable: %w", err)
	}
	if err := seed(ctx, cfg, client); err != nil {
		return fmt.Errorf("seeding bots: %w", err)
	}

	// Reference price: live Binance returns, GBM fallback, band-anchored.
	var binMkts []refprice.BinanceMarket
	var gbmMkts []refprice.GBMMarket
	var bands []refprice.MarketBand
	var marketIDs []int
	for _, m := range cfg.Markets {
		if m.BinanceSym != "" {
			binMkts = append(binMkts, refprice.BinanceMarket{Symbol: m.Symbol, BinanceSym: m.BinanceSym})
		}
		gbmMkts = append(gbmMkts, refprice.GBMMarket{Symbol: m.Symbol, VolPerSec: m.VolPerSec})
		bands = append(bands, refprice.MarketBand{
			Symbol: m.Symbol, AnchorStart: m.AnchorStart.Float(),
			BandLo: m.BandLo.Float(), BandHi: m.BandHi.Float(), MarginPct: cfg.BandMarginPct,
		})
		marketIDs = append(marketIDs, m.ID)
	}
	var live refprice.Source
	if len(binMkts) > 0 && source != "gbm" {
		live = refprice.NewBinanceSource(binanceURL, binMkts)
	}
	router := refprice.NewRouter(live, refprice.NewGBMSource(gbmMkts, 0), bands)
	if !router.SetMode(source) {
		return fmt.Errorf("invalid -source %q", source)
	}
	loadAnchors(anchorFile, router)
	router.Start()
	defer router.Stop()

	// Observed book: the closed loop against the real exchange.
	feedClient := feed.NewClient(cfg.MarketWSURL, marketIDs)
	feedClient.Start()
	defer feedClient.Stop()

	// Per-bot ceiling stays far under the OMS user limits (100/s, 1000/min);
	// the depth keepers need burst room to re-ladder through a price move.
	governor := agents.NewGovernor(globalOps, globalOps, 8, 20)
	stats := agents.NewStats()

	// OMS user-WS base URL derives from the REST base (path /ws/v1; the
	// API.md shorthand "/ws" is the unversioned spelling).
	wsBase := strings.Replace(cfg.OMSBaseURL, "http://", "ws://", 1)
	wsBase = strings.Replace(wsBase, "https://", "wss://", 1) + "/ws/v1"

	var schedulers []*agents.Scheduler
	var followers []*oms.UserWS
	var healths []*agents.MarketHealth
	for i, m := range cfg.Markets {
		params := agents.MarketParams{
			ID: m.ID, Symbol: m.Symbol, Tick: m.Tick,
			BandLo: m.BandLo, BandHi: m.BandHi,
			MinQty: m.MinQty, MaxQty: m.MaxQty,
			BaseFloat: m.BaseFloat.Float(), BaseAssetID: m.BaseAssetID,
		}
		mh := &agents.MarketHealth{Symbol: m.Symbol}
		healths = append(healths, mh)
		env := agents.Env{Client: client, Router: router, Feed: feedClient,
			Governor: governor, Stats: stats, Health: mh}
		bots := cfg.Bots(i)
		s := &agents.Scheduler{Symbol: m.Symbol, Fills: make(chan oms.OrderResponse, 256)}
		for j := 0; j < makersPerMarket && j < len(bots); j++ {
			s.Makers = append(s.Makers, agents.NewMaker(bots[j], params, env))
			// Follow this maker's order updates so fills leave the ladder
			// promptly (reconcile remains the safety net for drops).
			f := oms.NewUserWS(wsBase, fmt.Sprintf(cfg.AuthTemplate, bots[j]), bots[j], 128)
			f.Start()
			followers = append(followers, f)
			go pump(f.Out, s.Fills)
		}
		for j := makersPerMarket; j < makersPerMarket+takersPerMarket && j < len(bots); j++ {
			s.Takers = append(s.Takers, agents.NewTaker(bots[j], params, env))
		}
		j := makersPerMarket + takersPerMarket
		for k := 0; k < depthPerMarket && j < len(bots); k++ {
			side := "BUY"
			if k%2 == 1 {
				side = "SELL"
			}
			s.Depth = append(s.Depth, agents.NewDepth(bots[j], side, params, env))
			j++
		}
		for k := 0; k < noisePerMarket && j < len(bots); k++ {
			s.Noise = append(s.Noise, agents.NewNoise(bots[j], params, env))
			j++
		}
		schedulers = append(schedulers, s)
		s.Start()
	}
	defer func() {
		for _, f := range followers {
			f.Stop()
		}
	}()
	log.Printf("[run] simulating %d markets, %d makers + %d takers + %d noise each, source=%s",
		len(cfg.Markets), makersPerMarket, takersPerMarket, noisePerMarket, router.ActiveSource())

	// Phase 3: observability — the sim doubles as the demo canary.
	if hOpts.Addr != "" {
		registry := health.NewRegistry()
		cm := cfg.Markets[len(cfg.Markets)-1] // least-visible market hosts the canary
		canary := &health.Canary{
			Client: client, Router: router, Registry: registry, Bot: cfg.CanaryBot,
			MarketID: cm.ID, Symbol: cm.Symbol, Tick: cm.Tick,
			BandLo: cm.BandLo, BandHi: cm.BandHi, MinQty: cm.MinQty,
		}
		go canary.Run(ctx)

		targets := []health.Target{{Name: "local", BaseURL: cfg.OMSBaseURL, Critical: true}}
		if hOpts.PublicOMSURL != "" {
			targets = append(targets, health.Target{Name: "public", BaseURL: hOpts.PublicOMSURL, Critical: true})
		}
		cors := &health.CORSProbe{Registry: registry, Origin: hOpts.CORSOrigin, Targets: targets}
		go cors.Run(ctx)

		go passiveChecks(ctx, cfg, client, feedClient, stats, registry)

		hs := &health.Server{
			Addr: hOpts.Addr, Registry: registry, Stats: stats, Router: router, Canary: canary,
			FeedStale: func() map[string]float64 {
				out := map[string]float64{}
				for _, m := range cfg.Markets {
					out[m.Symbol] = time.Since(feedClient.View(m.ID).LastMsgAt).Seconds()
				}
				return out
			},
			Pause: func(p bool) {
				for _, h := range healths {
					h.SetManualPause(p)
				}
			},
		}
		srv := hs.Start()
		defer srv.Close()
	}

	// Periodic re-seed keeps the bot population solvent forever: seeding is
	// shortfall-only (top-up below 90% of target), so a healthy population
	// is a no-op while a pump that drained the sell-side depth bot gets its
	// float restored within minutes (top-ups are logged and counted).
	go func() {
		reseed := time.NewTicker(3 * time.Minute)
		defer reseed.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-reseed.C:
				if err := seed(ctx, cfg, client); err != nil && ctx.Err() == nil {
					log.Printf("[run] re-seed: %v", err)
				}
			}
		}
	}()

	report := time.NewTicker(30 * time.Second)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Print("[run] shutting down, clearing sim quotes...")
			saveAnchors(anchorFile, router)
			for _, s := range schedulers {
				s.Stop(10 * time.Second)
			}
			return nil
		case <-report.C:
			saveAnchors(anchorFile, router)
			anchors := ""
			for _, m := range cfg.Markets {
				if st, ok := router.Snapshot(m.Symbol); ok {
					anchors += fmt.Sprintf(" %s=%.2f", m.Symbol, st.Anchor)
				}
			}
			log.Printf("[run] source=%s%s | %s", router.ActiveSource(), anchors, stats.Summary())
		}
	}
}
