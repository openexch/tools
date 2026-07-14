package main

import (
	"strings"

	"github.com/openexch/tools/market-sim/oms"
)

// MarketSpec carries per-market engine constraints and sim tuning. Band and
// tick mirror the engine's MarketConfig (documented in order-management/
// docs/API.md; not yet discoverable via the API, match#64) — orders off-tick
// or out-of-band are engine-rejected with an empty rejectReason.
type MarketSpec struct {
	ID          int
	Symbol      string
	BaseAssetID int
	BinanceSym  string // lower-case Binance stream symbol; "" = no live feed

	BandLo oms.Money
	BandHi oms.Money
	Tick   oms.Money

	// AnchorStart seeds the reference price inside the band; live-source
	// returns are applied to the anchor, never raw external price levels
	// (live BTC can sit outside the engine band).
	AnchorStart oms.Money
	// VolPerSec is the GBM fallback's per-second log-return stddev.
	VolPerSec float64

	// Order sizing for agents (base-asset units).
	MinQty float64
	MaxQty float64

	// Seeder targets per bot.
	BaseFloat oms.Money // base asset
}

// DefaultMarkets is the live 5-market table (ids/bands/ticks per API.md).
func DefaultMarkets() []MarketSpec {
	return []MarketSpec{
		{
			ID: 1, Symbol: "BTC-USD", BaseAssetID: 1, BinanceSym: "btcusdt",
			BandLo: oms.MustMoney("50000"), BandHi: oms.MustMoney("150000"), Tick: oms.MustMoney("1"),
			AnchorStart: oms.MustMoney("100000"), VolPerSec: 0.0004,
			MinQty: 0.001, MaxQty: 0.2, BaseFloat: oms.MustMoney("5"),
		},
		{
			ID: 2, Symbol: "ETH-USD", BaseAssetID: 2, BinanceSym: "ethusdt",
			BandLo: oms.MustMoney("1000"), BandHi: oms.MustMoney("10000"), Tick: oms.MustMoney("0.5"),
			AnchorStart: oms.MustMoney("3500"), VolPerSec: 0.0005,
			MinQty: 0.01, MaxQty: 5, BaseFloat: oms.MustMoney("100"),
		},
		{
			ID: 3, Symbol: "SOL-USD", BaseAssetID: 3, BinanceSym: "solusdt",
			BandLo: oms.MustMoney("50"), BandHi: oms.MustMoney("500"), Tick: oms.MustMoney("0.05"),
			AnchorStart: oms.MustMoney("150"), VolPerSec: 0.0006,
			MinQty: 0.1, MaxQty: 100, BaseFloat: oms.MustMoney("2000"),
		},
		{
			ID: 4, Symbol: "XRP-USD", BaseAssetID: 4, BinanceSym: "xrpusdt",
			BandLo: oms.MustMoney("0.5"), BandHi: oms.MustMoney("10"), Tick: oms.MustMoney("0.001"),
			AnchorStart: oms.MustMoney("2"), VolPerSec: 0.0006,
			MinQty: 10, MaxQty: 5000, BaseFloat: oms.MustMoney("100000"),
		},
		{
			ID: 5, Symbol: "DOGE-USD", BaseAssetID: 5, BinanceSym: "dogeusdt",
			BandLo: oms.MustMoney("0.05"), BandHi: oms.MustMoney("1"), Tick: oms.MustMoney("0.0001"),
			AnchorStart: oms.MustMoney("0.2"), VolPerSec: 0.0007,
			MinQty: 100, MaxQty: 50000, BaseFloat: oms.MustMoney("1000000"),
		},
	}
}

// Config is the full sim configuration (populated from flags in main.go).
type Config struct {
	OMSBaseURL    string
	MarketWSURL   string
	AuthTemplate  string
	Markets       []MarketSpec
	BotBase       int64 // first bot userId; population is contiguous from here
	BotsPerMarket int   // makers+takers+noise share this pool per market
	CanaryBot     int64

	// Stabilizer is the per-market liquidity backstop (one bot per market at
	// StabilizerBase+i). Privileged-funded (StabilizerFundMult x the normal
	// float) so it can always quote the missing side.
	StabilizerEnabled  bool
	StabilizerBase     int64
	StabilizerFundMult int64

	// Funding targets per bot (quote side; base side is per-market BaseFloat).
	USDFloat oms.Money

	// bandMarginPct keeps the anchor this % inside the hard band so the 10%
	// price collar and band rejects never fire at the edges.
	BandMarginPct float64
}

func DefaultConfig() Config {
	return Config{
		OMSBaseURL:    "http://127.0.0.1:8080",
		MarketWSURL:   "ws://127.0.0.1:8081/ws",
		AuthTemplate:  "dev:%d",
		Markets:       DefaultMarkets(),
		BotBase:       900001,
		BotsPerMarket: 10,
		CanaryBot:     900999,

		StabilizerEnabled:  true,
		StabilizerBase:     900900, // one per market: 900900..; clear of the 900001-900050 pool and the 900999 canary
		StabilizerFundMult: 50,

		USDFloat:      oms.MustMoney("1000000"),
		BandMarginPct: 15,
	}
}

// SelectMarkets filters by comma-separated symbol list ("" = all).
func (c *Config) SelectMarkets(symbols string) {
	if symbols == "" {
		return
	}
	want := map[string]bool{}
	for _, s := range strings.Split(symbols, ",") {
		want[strings.TrimSpace(strings.ToUpper(s))] = true
	}
	var sel []MarketSpec
	for _, m := range c.Markets {
		if want[m.Symbol] {
			sel = append(sel, m)
		}
	}
	c.Markets = sel
}

// Bots returns the bot userIds assigned to market index i (0-based).
func (c *Config) Bots(i int) []int64 {
	out := make([]int64, c.BotsPerMarket)
	for j := range out {
		out[j] = c.BotBase + int64(i*c.BotsPerMarket+j)
	}
	return out
}

// StabilizerBot returns the backstop bot userId for market index i (0-based).
func (c *Config) StabilizerBot(i int) int64 { return c.StabilizerBase + int64(i) }

// AllBots returns every trading bot (excluding the canary).
func (c *Config) AllBots() []int64 {
	var out []int64
	for i := range c.Markets {
		out = append(out, c.Bots(i)...)
	}
	return out
}
