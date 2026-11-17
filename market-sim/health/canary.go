package health

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/openexch/tools/market-sim/oms"
	"github.com/openexch/tools/market-sim/refprice"
)

// Canary actively proves the order lifecycle end-to-end on a dedicated bot:
// create a resting far-from-touch order (inside the 10% price collar!),
// see it reach NEW (201 is PENDING_NEW; NEW is the matching engine's ack),
// cancel it, see it CANCELLED. The passive agents prove
// fills; the canary proves the path even when the market is quiet.
type Canary struct {
	Client   *oms.Client
	Router   *refprice.Router
	Registry *Registry
	Bot      int64

	// Market the canary probes (least-visible market by default).
	MarketID int
	Symbol   string
	Tick     oms.Money
	BandLo   oms.Money
	BandHi   oms.Money
	MinQty   float64

	Interval time.Duration // default 20s
	SLA      time.Duration // per-leg deadline, default 5s

	seq int64
	// lastRoundtripMs (last successful full cycle) is exported to /metrics from
	// the HTTP handler goroutine while cycle() writes it from the canary
	// goroutine, so it must be accessed atomically.
	lastRoundtripMs atomic.Int64
}

func (c *Canary) Run(ctx context.Context) {
	if c.Interval <= 0 {
		c.Interval = 20 * time.Second
	}
	if c.SLA <= 0 {
		c.SLA = 5 * time.Second
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, detail := c.cycle(ctx)
			c.Registry.Set("canary_order_roundtrip", ok, detail, true)
			if !ok {
				log.Printf("[canary] FAILED: %s", detail)
			}
		}
	}
}

// RoundtripMs returns the last successful cycle duration.
func (c *Canary) RoundtripMs() int64 { return c.lastRoundtripMs.Load() }

func (c *Canary) cycle(ctx context.Context) (bool, string) {
	state, okState := c.Router.Snapshot(c.Symbol)
	if !okState {
		return false, "no reference price"
	}
	start := time.Now()

	// 5% below the anchor: deep out of the money but inside the collar.
	price := oms.MoneyFromFloat(state.Anchor*0.95).RoundToTick(c.Tick).Clamp(c.BandLo, c.BandHi)
	c.seq++
	resp, err := c.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: c.Bot, MarketID: c.MarketID, Side: "BUY", OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: oms.MoneyFromFloat(c.MinQty),
	})
	if err != nil {
		return false, "create: " + err.Error()
	}
	if !resp.Accepted {
		return false, "create rejected: " + resp.RejectReason
	}

	if ok, why := c.awaitStatus(ctx, resp.OrderID, "NEW"); !ok {
		// Best-effort cleanup before reporting.
		c.Client.CancelOrder(ctx, c.Bot, resp.OrderID)
		return false, "await NEW: " + why
	}
	if err := c.Client.CancelOrder(ctx, c.Bot, resp.OrderID); err != nil {
		return false, "cancel: " + err.Error()
	}
	ok, why := c.awaitStatus(ctx, resp.OrderID, "CANCELLED")
	if !ok {
		return false, "await CANCELLED: " + why
	}
	rt := time.Since(start).Milliseconds()
	c.lastRoundtripMs.Store(rt)
	detail := fmt.Sprintf("roundtrip %dms", rt)
	if why != "" {
		detail += ", " + why
	}
	return true, detail
}

// awaitStatus polls GET /orders/{id} until want. A closed order is read from
// the gateway's history; a gateway without history answers 503
// HISTORY_UNAVAILABLE for it. Only for want CANCELLED, after the cancel was
// acknowledged, and only on exactly that answer, the order's absence from
// the open orders counts as closed (the canary's far-from-touch order cannot
// have filled inside the collar band it was priced in, but this cannot tell
// CANCELLED from EXPIRED: the detail says so).
func (c *Canary) awaitStatus(ctx context.Context, id, want string) (bool, string) {
	deadline := time.Now().Add(c.SLA)
	last := ""
	for time.Now().Before(deadline) {
		o, err := c.Client.GetOrder(ctx, c.Bot, id)
		var apiErr *oms.APIError
		if want == "CANCELLED" && errors.As(err, &apiErr) && apiErr.Code == "HISTORY_UNAVAILABLE" {
			if open, lerr := c.Client.ActiveOrders(ctx, c.Bot); lerr == nil && !containsOrder(open, id) {
				return true, "closed (not open; no history to read its final status)"
			}
		}
		if err == nil {
			last = o.Status
			if o.Status == want {
				return true, ""
			}
			if oms.IsTerminalStatus(o.Status) && want == "NEW" {
				return false, "went terminal early: " + o.Status
			}
		}
		select {
		case <-ctx.Done():
			return false, "cancelled"
		case <-time.After(150 * time.Millisecond):
		}
	}
	return false, fmt.Sprintf("SLA %s exceeded (last status %q)", c.SLA, last)
}

func containsOrder(list []oms.OrderResponse, id string) bool {
	for _, o := range list {
		if o.OrderID == id {
			return true
		}
	}
	return false
}
