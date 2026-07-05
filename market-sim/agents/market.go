// Package agents implements the trading population: makers quote ladders
// around the reference anchor, takers cross the observed spread. All flow
// goes through the real OMS path (risk, balances, holds) at human-watchable
// rates under a token-bucket governor.
package agents

import (
	"log"
	"sync"
	"time"

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
	// BaseFloat is the per-bot base-asset funding target (inventory pivot).
	BaseFloat float64
	// BaseAssetID for balance lookups during reconcile.
	BaseAssetID int
}

// Env bundles the shared dependencies an agent steps against.
type Env struct {
	Client   *oms.Client
	Router   *refprice.Router
	Feed     *feed.Client
	Governor *Governor
	Stats    *Stats
	Health   *MarketHealth
}

// MarketHealth is per-market shared backoff state. When the server reports
// CIRCUIT_BREAKER_OPEN or MARKET_HALTED the whole market's agents pause new
// flow (cancels keep working) and never auto-reset the breaker — that is an
// admin action.
type MarketHealth struct {
	Symbol string

	mu          sync.Mutex
	pausedUntil time.Time
	reason      string
}

// PauseFor pauses new order flow on this market.
func (h *MarketHealth) PauseFor(d time.Duration, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	until := time.Now().Add(d)
	if until.After(h.pausedUntil) {
		h.pausedUntil = until
		h.reason = reason
		log.Printf("[health %s] pausing new flow for %s: %s", h.Symbol, d, reason)
	}
}

// Paused reports whether new order flow is currently suspended.
func (h *MarketHealth) Paused() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Now().Before(h.pausedUntil)
}

// handleReject applies shared backoff policy for a rejected order and counts
// it. Returns true when the reject also pauses the market.
func (e Env) handleReject(reason string) bool {
	e.Stats.Reject(reason)
	switch reason {
	case "CIRCUIT_BREAKER_OPEN", "MARKET_HALTED":
		if e.Health != nil {
			e.Health.PauseFor(30*time.Second, reason)
		}
		return true
	}
	return false
}

// anchorPrice converts the router's float anchor to an engine-legal price.
func (p MarketParams) legalPrice(f float64) oms.Money {
	return oms.MoneyFromFloat(f).RoundToTick(p.Tick).Clamp(p.BandLo, p.BandHi)
}

// offsetTicks shifts a price by n ticks (n may be negative), staying in band.
func (p MarketParams) offsetTicks(m oms.Money, n int) oms.Money {
	return (m + oms.Money(n)*p.Tick).Clamp(p.BandLo, p.BandHi)
}
