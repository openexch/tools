package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/openexch/tools/market-sim/agents"
	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/oms"
	"github.com/openexch/tools/market-sim/refprice"
)

// Population split within each market's bot pool: the rest of the pool is
// reserved for Phase 2 noise agents.
const (
	makersPerMarket = 4
	takersPerMarket = 3
)

// run wires the whole sim: reference-price router -> agents -> OMS, with the
// observed book closing the loop, and blocks until ctx is cancelled.
func run(ctx context.Context, cfg *Config, client *oms.Client, source, binanceURL string, globalOps float64) error {
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
	router.Start()
	defer router.Stop()

	// Observed book: the closed loop against the real exchange.
	feedClient := feed.NewClient(cfg.MarketWSURL, marketIDs)
	feedClient.Start()
	defer feedClient.Stop()

	// Per-bot ceiling stays far under the OMS user limits (100/s, 1000/min).
	governor := agents.NewGovernor(globalOps, globalOps, 5, 10)
	stats := agents.NewStats()

	var schedulers []*agents.Scheduler
	for i, m := range cfg.Markets {
		params := agents.MarketParams{
			ID: m.ID, Symbol: m.Symbol, Tick: m.Tick,
			BandLo: m.BandLo, BandHi: m.BandHi,
			MinQty: m.MinQty, MaxQty: m.MaxQty,
		}
		env := agents.Env{Client: client, Router: router, Feed: feedClient, Governor: governor, Stats: stats}
		bots := cfg.Bots(i)
		s := &agents.Scheduler{Symbol: m.Symbol}
		for j := 0; j < makersPerMarket && j < len(bots); j++ {
			s.Makers = append(s.Makers, agents.NewMaker(bots[j], params, env))
		}
		for j := makersPerMarket; j < makersPerMarket+takersPerMarket && j < len(bots); j++ {
			s.Takers = append(s.Takers, agents.NewTaker(bots[j], params, env))
		}
		schedulers = append(schedulers, s)
		s.Start()
	}
	log.Printf("[run] simulating %d markets, %d makers + %d takers each, source=%s",
		len(cfg.Markets), makersPerMarket, takersPerMarket, router.ActiveSource())

	report := time.NewTicker(30 * time.Second)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Print("[run] shutting down, clearing sim quotes...")
			for _, s := range schedulers {
				s.Stop(10 * time.Second)
			}
			return nil
		case <-report.C:
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
