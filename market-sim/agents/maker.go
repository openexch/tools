package agents

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
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
	// InvSkewTicksMax caps the inventory-driven quote shift (Avellaneda-
	// Stoikov flavor: long inventory shifts quotes down to sell it off).
	InvSkewTicksMax int
	// RebalanceFrac: when |inventory delta| exceeds this fraction of the
	// base float, place an aggressive reducing order during reconcile.
	RebalanceFrac float64

	seq       int64
	orders    map[string]*makerOrder // omsOrderId -> order
	nextAt    time.Time
	nextRecAt time.Time // next reconcile
	holdOff   time.Time // placement backoff (e.g. after OPEN_ORDER_LIMIT)
	invDelta  float64   // base-asset inventory minus float target (from reconcile)
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
		InvSkewTicksMax: 6, RebalanceFrac: 0.3,
		orders: map[string]*makerOrder{},
		// Stagger first reconciles across the population.
		nextRecAt: time.Now().Add(time.Duration(rand.Int63n(int64(30 * time.Second)))),
	}
}

// HasOrder reports whether this maker owns the given omsOrderId (scheduler
// uses it to route WS order events; same goroutine as Step).
func (m *Maker) HasOrder(id string) bool {
	_, ok := m.orders[id]
	return ok
}

// OnOrderEvent applies a pushed order update (OMS user-WS): terminal orders
// leave the ladder immediately instead of waiting for TTL + cancel-404.
func (m *Maker) OnOrderEvent(o oms.OrderResponse) {
	if _, ok := m.orders[o.OmsOrderID]; !ok {
		return
	}
	if oms.IsTerminalStatus(o.Status) {
		if o.Status == "FILLED" {
			m.Env.Stats.Fills.Add(1)
		}
		delete(m.orders, o.OmsOrderID)
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
	skewTicks += m.inventorySkewTicks()
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

	// 2. Top the ladder back up to Levels per side (unless the market is
	// paused by a breaker/halt or this bot is backing off).
	if (m.Env.Health != nil && m.Env.Health.Paused()) || now.Before(m.holdOff) {
		return
	}
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

// inventorySkewTicks shifts the quote center against accumulated inventory:
// long inventory -> quote lower (sell it off), short -> higher.
func (m *Maker) inventorySkewTicks() int {
	if m.Params.BaseFloat <= 0 {
		return 0
	}
	frac := m.invDelta / m.Params.BaseFloat // -1..+1-ish
	ticks := int(-frac * float64(m.InvSkewTicksMax) * 2)
	if ticks > m.InvSkewTicksMax {
		ticks = m.InvSkewTicksMax
	}
	if ticks < -m.InvSkewTicksMax {
		ticks = -m.InvSkewTicksMax
	}
	return ticks
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
		m.Env.handleReject(resp.RejectReason)
		if resp.RejectReason == "OPEN_ORDER_LIMIT" {
			// Phantom or real, the fix is the same: reconcile against the
			// server NOW and stop placing briefly (oms#65 background).
			m.nextRecAt = time.Now()
			m.holdOff = time.Now().Add(10 * time.Second)
		}
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

// ReconcileDue reports whether this maker's periodic server-truth sync is due.
func (m *Maker) ReconcileDue(now time.Time) bool { return now.After(m.nextRecAt) }

// Reconcile syncs local intended state with the server (closing the drift
// binance-replay never handled): cancel server-side orphans that carry our
// clientOrderId prefix, drop local entries the server no longer has, refresh
// inventory from balances, and rebalance runaway inventory with a reducing
// order. Runs on the scheduler goroutine (same as Step).
func (m *Maker) Reconcile(ctx context.Context) {
	defer func() {
		m.nextRecAt = time.Now().Add(25*time.Second + time.Duration(rand.Int63n(int64(10*time.Second))))
	}()

	active, err := m.Env.Client.ActiveOrders(ctx, m.Bot)
	if err != nil {
		m.Env.Stats.Errors.Add(1)
		log.Printf("[maker %d %s] reconcile list: %v", m.Bot, m.Params.Symbol, err)
		return
	}
	server := map[string]bool{}
	prefix := fmt.Sprintf("sim-%d-", m.Bot)
	for _, o := range active {
		server[o.OmsOrderID] = true
		if _, known := m.orders[o.OmsOrderID]; known {
			continue
		}
		// Server-side orphan from a lost response or a previous run: cancel
		// anything with our idempotency prefix that we no longer intend.
		if o.MarketID == m.Params.ID && strings.HasPrefix(o.ClientOrderID, prefix) {
			if err := m.Env.Client.CancelOrder(ctx, m.Bot, o.OmsOrderID); err == nil || isGone(err) {
				m.Env.Stats.Orphans.Add(1)
			}
		}
	}
	// Local entries the server no longer knows: filled or lost; drop them.
	for id := range m.orders {
		if !server[id] {
			delete(m.orders, id)
		}
	}

	// Inventory refresh from balances (total base vs the funding float).
	acct, err := m.Env.Client.GetAccount(ctx, m.Bot)
	if err != nil {
		return
	}
	for _, a := range acct.Assets {
		if a.AssetID == m.Params.BaseAssetID {
			m.invDelta = a.Total.Float() - m.Params.BaseFloat
		}
	}

	// Rebalance runaway inventory INSIDE the market (an aggressive reducing
	// IOC at the touch) so books stay consistent; deposits stay a floor
	// guard only, or the sim would mask insolvency.
	if m.Params.BaseFloat > 0 && absF(m.invDelta) > m.RebalanceFrac*m.Params.BaseFloat {
		m.rebalance(ctx)
	}
}

func (m *Maker) rebalance(ctx context.Context) {
	if m.Env.Health != nil && m.Env.Health.Paused() {
		return
	}
	if !m.Env.Governor.Allow(m.Bot) {
		m.Env.Stats.Throttled.Add(1)
		return
	}
	book := m.Env.Feed.View(m.Params.ID)
	side, ref := "SELL", book.BestBid
	if m.invDelta < 0 {
		side, ref = "BUY", book.BestAsk
	}
	if ref <= 0 {
		return
	}
	slip := 2
	if side == "SELL" {
		slip = -2
	}
	price := m.Params.offsetTicks(m.Params.legalPrice(ref), slip)
	qty := dist.ClampQuantity(absF(m.invDelta)/4, m.Params.MinQty, m.Params.MaxQty)
	m.seq++
	resp, err := m.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: m.Bot, MarketID: m.Params.ID, Side: side, OrderType: "LIMIT",
		TimeInForce: "IOC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("sim-%d-%d", m.Bot, m.seq),
	})
	if err != nil {
		m.Env.Stats.Errors.Add(1)
		return
	}
	if !resp.Accepted {
		m.Env.handleReject(resp.RejectReason)
		return
	}
	m.Env.Stats.Placed.Add(1)
	log.Printf("[maker %d %s] rebalancing inventory delta %.4f: %s %.4f @ %s",
		m.Bot, m.Params.Symbol, m.invDelta, side, qty, price)
}

func absF(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
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
