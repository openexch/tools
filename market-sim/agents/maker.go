package agents

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/openexch/tools/market-sim/dist"
	"github.com/openexch/tools/market-sim/oms"
)

// Maker quotes a small ladder on both sides of the anchor and keeps it
// fresh with REAL cancels and re-posts (the gap that made binance-replay
// books grow forever). Quote placement uses the ported research
// distributions; the center skews against observed book imbalance.
type Maker struct {
	Bot    int64
	Params MarketParams
	Env    Env

	Levels       int           // ladder depth per side
	BaseSpread   int           // ticks between anchor and the first level
	RefreshDrift int           // re-quote when the anchor moved this many ticks
	TTLMean      time.Duration // exponential order lifetime
	SkewStrength float64       // ImbalanceSkew strength

	seq    int64
	orders map[string]*makerOrder // omsOrderId -> order
	nextAt time.Time
}

type makerOrder struct {
	side     string
	price    oms.Money
	placedAt time.Time
	ttl      time.Duration
}

func NewMaker(bot int64, p MarketParams, env Env) *Maker {
	return &Maker{
		Bot: bot, Params: p, Env: env,
		Levels: 3, BaseSpread: 2, RefreshDrift: 6,
		TTLMean: 25 * time.Second, SkewStrength: 0.2,
		orders: map[string]*makerOrder{},
	}
}

// Due reports whether this maker wants a step now.
func (m *Maker) Due(now time.Time) bool { return now.After(m.nextAt) }

// Step reconciles the ladder once: drop stale quotes, top up missing ones.
// Every OMS op passes the governor; when throttled the rest of the step is
// skipped (retried on the next due cycle).
func (m *Maker) Step(ctx context.Context) {
	defer m.reschedule()
	state, ok := m.Env.Router.Snapshot(m.Params.Symbol)
	if !ok {
		return
	}
	book := m.Env.Feed.View(m.Params.ID)
	skewTicks := int(dist.ImbalanceSkew(book.Imbalance, m.SkewStrength) * 8)
	center := m.Params.legalPrice(state.Anchor)
	center = m.Params.offsetTicks(center, skewTicks)
	now := time.Now()

	// 1. Cancel quotes that aged out or drifted from the current center.
	drift := oms.Money(m.RefreshDrift) * m.Params.Tick
	for id, o := range m.orders {
		expired := now.Sub(o.placedAt) > o.ttl
		drifted := o.price > center+drift || o.price < center-drift
		if !expired && !drifted {
			continue
		}
		if !m.Env.Governor.Allow(m.Bot) {
			m.Env.Stats.Throttled.Add(1)
			return
		}
		if err := m.Env.Client.CancelOrder(ctx, m.Bot, id); err != nil && !isGone(err) {
			m.Env.Stats.Errors.Add(1)
			log.Printf("[maker %d %s] cancel %s: %v", m.Bot, m.Params.Symbol, id, err)
			continue
		}
		// Cancelled — or 404: already filled/terminal, equally gone.
		m.Env.Stats.Cancelled.Add(1)
		delete(m.orders, id)
	}

	// 2. Top the ladder back up to Levels per side.
	counts := map[string]int{}
	for _, o := range m.orders {
		counts[o.side]++
	}
	for _, side := range []string{"BUY", "SELL"} {
		for counts[side] < m.Levels {
			if !m.place(ctx, side, center) {
				return
			}
			counts[side]++
		}
	}
}

func (m *Maker) place(ctx context.Context, side string, center oms.Money) bool {
	if !m.Env.Governor.Allow(m.Bot) {
		m.Env.Stats.Throttled.Add(1)
		return false
	}
	level := dist.ExponentialLevel(0.3)
	if level > 8 {
		level = 8
	}
	offset := m.BaseSpread + level
	if side == "BUY" {
		offset = -offset
	}
	price := m.Params.offsetTicks(center, offset)
	qty := dist.ClampQuantity(
		dist.ParetoQuantity(m.Params.MinQty*3, 1.5),
		m.Params.MinQty, m.Params.MaxQty,
	)
	m.seq++
	req := oms.CreateOrderRequest{
		UserID: m.Bot, MarketID: m.Params.ID, Side: side, OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("sim-%d-%d", m.Bot, m.seq),
	}
	resp, err := m.Env.Client.CreateOrder(ctx, req)
	if err != nil {
		m.Env.Stats.Errors.Add(1)
		log.Printf("[maker %d %s] create: %v", m.Bot, m.Params.Symbol, err)
		return false
	}
	if !resp.Accepted {
		m.Env.Stats.Reject(resp.RejectReason)
		return false
	}
	m.Env.Stats.Placed.Add(1)
	ttl := time.Duration(rand.ExpFloat64() * float64(m.TTLMean))
	if ttl < 3*time.Second {
		ttl = 3 * time.Second
	}
	m.orders[resp.OmsOrderID] = &makerOrder{side: side, price: price, placedAt: time.Now(), ttl: ttl}
	return true
}

func (m *Maker) reschedule() {
	// Jittered ~1.5-3.5s between reconcile passes per maker.
	m.nextAt = time.Now().Add(1500*time.Millisecond + time.Duration(rand.Int63n(2000))*time.Millisecond)
}

// CancelAll best-effort clears this maker's live quotes (shutdown path;
// bypasses the governor).
func (m *Maker) CancelAll(ctx context.Context) {
	for id := range m.orders {
		if err := m.Env.Client.CancelOrder(ctx, m.Bot, id); err == nil || isGone(err) {
			delete(m.orders, id)
		}
	}
}

// isGone treats NOT_FOUND as convergence: the order is already terminal
// (usually filled between our snapshot and the cancel).
func isGone(err error) bool {
	var apiErr *oms.APIError
	return errors.As(err, &apiErr) && apiErr.Code == "NOT_FOUND"
}
