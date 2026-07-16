package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
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
	Addr            string // health server listen address ("" = disabled)
	CORSOrigin      string // demo UI origin asserted by the CORS canary
	PublicOMSURL    string // public edge to probe ("" = local only)
	EdgeWSURL       string // public market-data WS (the edge relay path) ("" = check disabled)
	BridgeHealthURL string // settlement bridge health endpoint ("" = check disabled)
}

// edgeLagTracker measures the edge relay's ADDED latency by same-clock
// diffing: the local and edge feed clients both see every BOOK_DELTA of the
// watched market, identified by its unique v4 bookVersion, and both run on
// this process's clock. Replayed deltas (subscribe/refresh re-sends after a
// reconnect) would pair a fresh edge arrival with a stale local one — the
// first edge arrival consumes the pair, and samples over lagMaxSample are
// discarded rather than poisoning the average.
type edgeLagTracker struct {
	mu      sync.Mutex
	local   map[int64]time.Time
	order   []int64 // insertion order, for eviction
	ewmaMs  float64
	samples uint64
}

const (
	lagWindow    = 4096
	lagMaxSample = 2 * time.Second
)

func newEdgeLagTracker() *edgeLagTracker {
	return &edgeLagTracker{local: make(map[int64]time.Time, lagWindow)}
}

func (t *edgeLagTracker) recordLocal(v int64) {
	now := time.Now()
	t.mu.Lock()
	if _, dup := t.local[v]; !dup {
		t.local[v] = now
		t.order = append(t.order, v)
		if len(t.order) > lagWindow {
			delete(t.local, t.order[0])
			t.order = t.order[1:]
		}
	}
	t.mu.Unlock()
}

func (t *edgeLagTracker) recordEdge(v int64) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.local[v]
	if !ok {
		return
	}
	delete(t.local, v) // first edge arrival wins; replays cannot resample
	lag := now.Sub(at)
	if lag < 0 || lag > lagMaxSample {
		return
	}
	ms := float64(lag.Microseconds()) / 1000.0
	if t.samples == 0 {
		t.ewmaMs = ms
	} else {
		t.ewmaMs = 0.8*t.ewmaMs + 0.2*ms
	}
	t.samples++
}

// LagMs returns the smoothed relay-added latency, or -1 before any sample.
func (t *edgeLagTracker) LagMs() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.samples == 0 {
		return -1
	}
	return t.ewmaMs
}

// edgeFeedCheck proves the path real viewers use: the public market WS
// (market.openexch.io/ws → the market-relay Worker → Durable Object). The
// local feed staying fresh while this one stalls is exactly the half-open
// publisher failure seen live on 2026-07-07 — the gateway was healthy but
// the edge served a frozen feed. Critical: a stale edge IS a demo outage,
// so it pages through admin_demo_healthy / DemoUnhealthy.
func edgeFeedCheck(ctx context.Context, edgeFeed *feed.Client, market MarketSpec, lag *edgeLagTracker, registry *health.Registry) {
	const staleAfter = 60 * time.Second
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	startedAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(startedAt) < 90*time.Second {
				registry.Set("edge_feed_fresh", true, "warming up", true)
				continue
			}
			age := time.Since(edgeFeed.View(market.ID).LastMsgAt)
			detail := fmt.Sprintf("%s last frame %s ago", market.Symbol, age.Truncate(time.Second))
			if ms := lag.LagMs(); ms >= 0 {
				detail += fmt.Sprintf(", relay lag ~%.0fms", ms)
			}
			registry.Set("edge_feed_fresh", age <= staleAfter, detail, true)
		}
	}
}

// settlementCheck probes the settlement bridge's health endpoint. A HALTED
// bridge (it latches on a detected journal gap) forwards NOTHING to the Assets
// Engine, so fills never draw down their holds — money stops settling and every
// filled order's collateral leaks, draining every bot within ~an hour until the
// book goes one-sided. The book_depth / fills_recent checks only catch that
// LATE (once a side finally empties); this catches it the instant the bridge
// halts. Critical: a stalled settlement IS a demo outage. The bridge returns
// HTTP 503 + {"halted":true} when halted, 200 otherwise (assets-bridge
// BridgeMetricsServer). This exact stall (ME restored a stale snapshot while the
// AE reset to genesis, tradeId mismatch → bridge halt) caused the 2026-07-15
// outage and read as a false-green because nothing watched settlement.
func settlementCheck(ctx context.Context, healthURL string, registry *health.Registry) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
			if err != nil {
				registry.Set("settlement_flowing", false, "bad bridge health URL: "+err.Error(), true)
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				registry.Set("settlement_flowing", false, "settlement bridge unreachable: "+err.Error(), true)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// 503 or an explicit halted:true both mean the bridge stopped forwarding.
			halted := resp.StatusCode == http.StatusServiceUnavailable ||
				strings.Contains(string(body), "\"halted\":true")
			detail := ""
			if halted {
				detail = "settlement bridge HALTED — no money settling, holds leaking: " +
					strings.TrimSpace(string(body))
			}
			registry.Set("settlement_flowing", !halted, detail, true)
		}
	}
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
	// Edge-lag measurement taps BOTH feeds for the watched market's deltas;
	// callbacks must be in place before Start (plain field, no lock).
	var edgeLag *edgeLagTracker
	if hOpts.EdgeWSURL != "" {
		edgeLag = newEdgeLagTracker()
		watchID := cfg.Markets[0].ID
		feedClient.OnFrameVersion = func(marketID int, v int64) {
			if marketID == watchID {
				edgeLag.recordLocal(v)
			}
		}
	}
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
			// Follow depth-bot order updates too: eaten rungs must leave the
			// ladder immediately or the keeper can't refill through a move.
			f := oms.NewUserWS(wsBase, fmt.Sprintf(cfg.AuthTemplate, bots[j]), bots[j], 128)
			f.Start()
			followers = append(followers, f)
			go pump(f.Out, s.Fills)
			j++
		}
		for k := 0; k < noisePerMarket && j < len(bots); k++ {
			s.Noise = append(s.Noise, agents.NewNoise(bots[j], params, env))
			j++
		}
		// The liquidity backstop: one privileged bot per market that wakes only
		// when the book goes one-sided or crossed (e.g. after a regime dump) and
		// otherwise stays dormant. Follow its order events so filled backfill
		// rungs leave its ladder promptly.
		if cfg.StabilizerEnabled {
			stabBot := cfg.StabilizerBot(i)
			s.Stabilizer = agents.NewStabilizer(stabBot, params, env)
			f := oms.NewUserWS(wsBase, fmt.Sprintf(cfg.AuthTemplate, stabBot), stabBot, 128)
			f.Start()
			followers = append(followers, f)
			go pump(f.Out, s.Fills)
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

		// Watch the PUBLIC viewer path (edge relay) with its own feed client,
		// subscribed to the first market only — one edge connection suffices
		// to prove publisher->DO->viewer freshness.
		var edgeFeed *feed.Client
		if hOpts.EdgeWSURL != "" {
			edgeFeed = feed.NewClient(hOpts.EdgeWSURL, []int{cfg.Markets[0].ID})
			edgeFeed.OnFrameVersion = func(_ int, v int64) { edgeLag.recordEdge(v) }
			edgeFeed.Start()
			defer edgeFeed.Stop()
			go edgeFeedCheck(ctx, edgeFeed, cfg.Markets[0], edgeLag, registry)
		} else {
			// No edge URL => the freshness check never runs. Register it as a
			// failing critical check rather than leaving it unregistered, so a
			// misconfigured deploy reads unhealthy instead of silently green.
			registry.Set("edge_feed_fresh", false, "SIM_EDGE_WS_URL not configured", true)
		}

		// Watch the settlement bridge: a halt stops all money settlement and
		// leaks every fill's hold (the 2026-07-15 outage). Register failing when
		// unconfigured so a misconfigured deploy reads unhealthy, never green.
		if hOpts.BridgeHealthURL != "" {
			go settlementCheck(ctx, hOpts.BridgeHealthURL, registry)
		} else {
			registry.Set("settlement_flowing", false, "SIM_BRIDGE_HEALTH_URL not configured", true)
		}

		hs := &health.Server{
			Addr: hOpts.Addr, Registry: registry, Stats: stats, Router: router, Canary: canary,
			FeedStale: func() map[string]float64 {
				out := map[string]float64{}
				for _, m := range cfg.Markets {
					out[m.Symbol] = time.Since(feedClient.View(m.ID).LastMsgAt).Seconds()
				}
				return out
			},
			EdgeStale: func() float64 {
				if edgeFeed == nil {
					return -1 // check disabled
				}
				return time.Since(edgeFeed.View(cfg.Markets[0].ID).LastMsgAt).Seconds()
			},
			EdgeLag: func() float64 {
				if edgeLag == nil {
					return -1
				}
				return edgeLag.LagMs()
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
