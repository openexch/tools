package agents

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/openexch/tools/market-sim/dist"
	"github.com/openexch/tools/market-sim/oms"
)

// Noise places low-rate deep limit orders and randomly cancels its own,
// including the occasional place-then-cancel flicker: it makes the book's
// depth ebb and the orderCount texture look organic without moving price.
type Noise struct {
	Bot    int64
	Params MarketParams
	Env    Env

	MaxOpen int

	seq    int64
	orders []noiseOrder // oldest first
	nextAt time.Time
}

type noiseOrder struct {
	id       string
	placedAt time.Time
}

func NewNoise(bot int64, p MarketParams, env Env) *Noise {
	return &Noise{Bot: bot, Params: p, Env: env, MaxOpen: 6}
}

func (n *Noise) Due(now time.Time) bool { return now.After(n.nextAt) }

func (n *Noise) Step(ctx context.Context) {
	defer func() {
		// Slow cadence: one action every ~2-6s per noise bot.
		n.nextAt = time.Now().Add(2*time.Second + time.Duration(rand.Int63n(int64(4*time.Second))))
	}()
	if n.Env.Health != nil && n.Env.Health.Paused() {
		return
	}
	if !n.Env.Governor.Allow(n.Bot) {
		n.Env.Stats.Throttled.Add(1)
		return
	}

	// Bias toward cancelling when full, placing when empty.
	pPlace := 1.0 - float64(len(n.orders))/float64(n.MaxOpen)
	if rand.Float64() < pPlace {
		n.place(ctx)
	} else if len(n.orders) > 0 {
		n.cancelRandom(ctx)
	}
}

func (n *Noise) place(ctx context.Context) {
	state, ok := n.Env.Router.Snapshot(n.Params.Symbol)
	if !ok {
		return
	}
	side := "BUY"
	offset := -(5 + dist.ExponentialLevel(0.2))
	if rand.Float64() < 0.5 {
		side = "SELL"
		offset = -offset
	}
	price := n.Params.offsetTicks(n.Params.legalPrice(state.Anchor), offset)
	qty := dist.ClampQuantity(dist.ParetoQuantity(n.Params.MinQty*2, 1.5), n.Params.MinQty, n.Params.MaxQty/2)
	n.seq++
	resp, err := n.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: n.Bot, MarketID: n.Params.ID, Side: side, OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("sim-%d-%d", n.Bot, n.seq),
	})
	if err != nil {
		n.Env.Stats.Errors.Add(1)
		log.Printf("[noise %d %s] create: %v", n.Bot, n.Params.Symbol, err)
		return
	}
	if !resp.Accepted {
		n.Env.handleReject(resp.RejectReason)
		return
	}
	n.Env.Stats.Placed.Add(1)
	n.orders = append(n.orders, noiseOrder{id: resp.OmsOrderID, placedAt: time.Now()})
	// Occasional flicker: cancel-shortly-after-place.
	if rand.Float64() < 0.15 {
		n.nextAt = time.Now().Add(500 * time.Millisecond)
	}
}

func (n *Noise) cancelRandom(ctx context.Context) {
	i := rand.Intn(len(n.orders))
	// Prefer the oldest half so depth turns over.
	if i > len(n.orders)/2 {
		i = 0
	}
	o := n.orders[i]
	if err := n.Env.Client.CancelOrder(ctx, n.Bot, o.id); err != nil && !isGone(err) {
		n.Env.Stats.Errors.Add(1)
		return
	}
	n.Env.Stats.Cancelled.Add(1)
	n.orders = append(n.orders[:i], n.orders[i+1:]...)
}

// CancelAll clears live noise orders (shutdown path).
func (n *Noise) CancelAll(ctx context.Context) {
	for _, o := range n.orders {
		if err := n.Env.Client.CancelOrder(ctx, n.Bot, o.id); err == nil || isGone(err) {
			continue
		}
	}
	n.orders = nil
}
