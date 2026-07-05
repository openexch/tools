// Package agents implements the trading population: makers quote ladders
// around the reference anchor, takers cross the observed spread. All flow
// goes through the real OMS path (risk, balances, holds) at human-watchable
// rates under a token-bucket governor.
package agents

import (
	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/oms"
	"github.com/openexch/tools/market-sim/refprice"
)

// MarketParams is the per-market slice of config the agents need (mirrors
// the engine's MarketConfig constraints; see main config.go).
type MarketParams struct {
	ID     int
	Symbol string
	Tick   oms.Money
	BandLo oms.Money
	BandHi oms.Money
	MinQty float64
	MaxQty float64
}

// Env bundles the shared dependencies an agent steps against.
type Env struct {
	Client   *oms.Client
	Router   *refprice.Router
	Feed     *feed.Client
	Governor *Governor
	Stats    *Stats
}

// anchorPrice converts the router's float anchor to an engine-legal price.
func (p MarketParams) legalPrice(f float64) oms.Money {
	return oms.MoneyFromFloat(f).RoundToTick(p.Tick).Clamp(p.BandLo, p.BandHi)
}

// offsetTicks shifts a price by n ticks (n may be negative), staying in band.
func (p MarketParams) offsetTicks(m oms.Money, n int) oms.Money {
	return (m + oms.Money(n)*p.Tick).Clamp(p.BandLo, p.BandHi)
}
