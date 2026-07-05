// Package refprice produces the per-market reference price that anchors all
// agent behavior. Sources emit log-RETURNS, not price levels: the router
// applies them to an anchor seeded inside the engine's price band, which
// keeps live BTC (possibly outside the band) usable, makes source failover
// jump-free, and allows runtime switching.
package refprice

import "time"

// RefTick is one reference-price observation for a market.
type RefTick struct {
	Symbol    string // sim market symbol, e.g. "BTC-USD"
	LogReturn float64
	// TakerSide/Qty hint from live trades ("BUY"/"SELL"/""), drives burst
	// intensity and taker direction bias.
	TakerSide string
	Qty       float64
	At        time.Time
}

// Source produces reference ticks for the markets it was configured with.
type Source interface {
	// Ticks is the shared output channel; closed only on Stop.
	Ticks() <-chan RefTick
	// Healthy reports whether the source is currently producing usable data.
	Healthy() bool
	Name() string
	// Start begins production (idempotent); Stop halts it.
	Start()
	Stop()
}
