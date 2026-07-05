package health

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/openexch/tools/market-sim/oms"
	"github.com/openexch/tools/market-sim/refprice"
)

// Canary actively proves the order lifecycle end-to-end on a dedicated bot:
// create a resting far-from-touch order (inside the 10% price collar!),
// see it reach NEW, cancel it, see it CANCELLED. The passive agents prove
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
	// RoundtripMs is exported to /metrics (last successful full cycle).
	lastRoundtripMs int64
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
func (c *Canary) RoundtripMs() int64 { return c.lastRoundtripMs }

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
		ClientOrderID: fmt.Sprintf("sim-canary-%d", c.seq),
	})
	if err != nil {
		return false, "create: " + err.Error()
	}
	if !resp.Accepted {
		return false, "create rejected: " + resp.RejectReason
	}

	if ok, why := c.awaitStatus(ctx, resp.OmsOrderID, "NEW"); !ok {
		// Best-effort cleanup before reporting.
		c.Client.CancelOrder(ctx, c.Bot, resp.OmsOrderID)
		return false, "await NEW: " + why
	}
	if err := c.Client.CancelOrder(ctx, c.Bot, resp.OmsOrderID); err != nil {
		return false, "cancel: " + err.Error()
	}
	if ok, why := c.awaitStatus(ctx, resp.OmsOrderID, "CANCELLED"); !ok {
		return false, "await CANCELLED: " + why
	}
	c.lastRoundtripMs = time.Since(start).Milliseconds()
	return true, fmt.Sprintf("roundtrip %dms", c.lastRoundtripMs)
}

func (c *Canary) awaitStatus(ctx context.Context, id, want string) (bool, string) {
	deadline := time.Now().Add(c.SLA)
	last := ""
	for time.Now().Before(deadline) {
		o, err := c.Client.GetOrder(ctx, c.Bot, id)
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
