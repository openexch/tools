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

// Taker sends IOC limit orders that cross the observed touch. Arrivals are
// Poisson, modulated by the reference feed's trade intensity (bursts follow
// the real market when the live source is up); direction follows the taker
// bias so the local last-trade tracks the reference trend. This is what
// paints trades and candles on the demo UI.
type Taker struct {
	Bot    int64
	Params MarketParams
	Env    Env

	BaseRate  float64 // arrivals/sec at quiet flow
	SlipTicks int     // how deep past the touch the IOC reaches

	seq int64
}

func NewTaker(bot int64, p MarketParams, env Env) *Taker {
	return &Taker{Bot: bot, Params: p, Env: env, BaseRate: 0.4, SlipTicks: 3}
}

// Tick performs one Poisson draw for the elapsed interval and maybe trades.
func (t *Taker) Tick(ctx context.Context, dt time.Duration) {
	if t.Env.Health != nil && t.Env.Health.Paused() {
		return
	}
	state, ok := t.Env.Router.Snapshot(t.Params.Symbol)
	if !ok {
		return
	}
	rate := t.BaseRate * (1 + dist.BurstProbability(0, state.TradeRate, 0.5))
	if rand.Float64() >= rate*dt.Seconds() {
		return
	}
	if !t.Env.Governor.Allow(t.Bot) {
		t.Env.Stats.Throttled.Add(1)
		return
	}

	pBuy := clamp01(0.5 + 0.3*state.TakerBias)
	side := "SELL"
	if rand.Float64() < pBuy {
		side = "BUY"
	}

	// Cross the observed touch; fall back to the anchor when the feed has
	// no opposite side yet.
	book := t.Env.Feed.View(t.Params.ID)
	var ref float64
	if side == "BUY" {
		ref = book.BestAsk
	} else {
		ref = book.BestBid
	}
	if ref <= 0 {
		ref = state.Anchor
	}
	slip := t.SlipTicks
	if side == "SELL" {
		slip = -slip
	}
	price := t.Params.offsetTicks(t.Params.legalPrice(ref), slip)

	qty := dist.ClampQuantity(
		dist.ParetoQuantity(t.Params.MinQty*2, 1.5),
		t.Params.MinQty, t.Params.MaxQty/4,
	)
	t.seq++
	resp, err := t.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: t.Bot, MarketID: t.Params.ID, Side: side, OrderType: "LIMIT",
		TimeInForce: "IOC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("sim-%d-%d", t.Bot, t.seq),
	})
	if err != nil {
		t.Env.Stats.Errors.Add(1)
		log.Printf("[taker %d %s] create: %v", t.Bot, t.Params.Symbol, err)
		return
	}
	if !resp.Accepted {
		t.Env.handleReject(resp.RejectReason)
		return
	}
	t.Env.Stats.Placed.Add(1)
}

func clamp01(f float64) float64 {
	if f < 0.1 {
		return 0.1
	}
	if f > 0.9 {
		return 0.9
	}
	return f
}
