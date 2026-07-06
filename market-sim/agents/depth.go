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

// Depth is the book-floor keeper: it maintains a wide ladder of resting
// orders on BOTH sides so the visible book never thins out. The market
// gateway broadcasts at most 20 levels per side (GatewayOrderBook
// MAX_LEVELS); this agent holds ~25 distinct engine-side levels per side so
// the visible 20 stay full even while takers eat the touch.
type Depth struct {
	Bot    int64
	Side   string // "BUY" or "SELL": one bot per side so a fast move can be re-laddered within per-user rate limits
	Params MarketParams
	Env    Env

	Levels  int // ladder depth (target distinct price levels on this side)
	TTLMean time.Duration

	// spacing in ticks between ladder levels, derived from price scale so
	// the full span stays ~0.5-1.5% of price across all markets.
	spacing int

	seq    int64
	orders map[string]*depthOrder
	nextAt time.Time
	// lastForcedRec rate-limits the thin-book emergency reconcile.
	lastForcedRec time.Time
}

type depthOrder struct {
	side     string
	price    oms.Money
	offset   int // ticks from center at placement
	placedAt time.Time
	ttl      time.Duration
}

func NewDepth(bot int64, side string, p MarketParams, env Env) *Depth {
	// spacing ≈ 0.02% of price per level; at least 1 tick.
	mid := (p.BandLo + p.BandHi).Float() / 2
	spacing := int(mid * 0.0002 / p.Tick.Float())
	if spacing < 1 {
		spacing = 1
	}
	return &Depth{
		Bot: bot, Side: side, Params: p, Env: env,
		// 35 rungs = 15 spare beyond the gateway's 20 visible levels, so
		// takers eating the near rungs during a move never thin the
		// visible book below 20.
		Levels: 35, TTLMean: 4 * time.Minute, spacing: spacing,
		orders: map[string]*depthOrder{},
	}
}

func (d *Depth) Due(now time.Time) bool { return now.After(d.nextAt) }

// OnOrderEvent applies a pushed order update (OMS user-WS). Without this,
// rungs eaten by takers during a pump/dump stayed in d.orders as zombies
// until the 45s reconcile — the keeper believed the ladder was full and
// placed NOTHING while the visible side drained (the drained-book bug).
func (d *Depth) OnOrderEvent(o oms.OrderResponse) {
	if _, ok := d.orders[o.OmsOrderID]; !ok {
		return
	}
	if oms.IsTerminalStatus(o.Status) {
		if o.Status == "FILLED" {
			d.Env.Stats.Fills.Add(1)
		}
		delete(d.orders, o.OmsOrderID)
	}
}

// Step slides the ladder with the anchor: cancel rungs that fell out of the
// window (or crossed the center after a move), then fill empty rungs. Ops
// are budgeted per step so a fast move re-ladders over a few seconds rather
// than bursting through the rate governor.
func (d *Depth) Step(ctx context.Context) {
	state, ok := d.Env.Router.Snapshot(d.Params.Symbol)
	if !ok {
		d.nextAt = time.Now().Add(time.Second)
		return
	}
	center := d.Params.legalPrice(state.Anchor)
	now := time.Now()

	// Safety net for dropped WS events: if OUR side of the visible book is
	// thin while the local ladder claims to be full, some entries are
	// zombies (filled orders we never heard about) — reconcile against the
	// server now instead of waiting for the 45s sweep, so the refill below
	// works from real occupancy.
	if len(d.orders) >= d.Levels*3/4 && now.Sub(d.lastForcedRec) > 3*time.Second {
		book := d.Env.Feed.View(d.Params.ID)
		visible := len(book.Bids)
		if d.Side == "SELL" {
			visible = len(book.Asks)
		}
		if visible < 16 {
			d.lastForcedRec = now
			d.Reconcile(ctx)
		}
	}
	// Separate budgets so a sliding window (cancels at the far end) can
	// never starve rebuilding the near end.
	cancelBudget, placeBudget := 5, 10

	// The ladder starts behind the makers (they own the touch region).
	minOff := 4
	maxOff := minOff + (d.Levels-1)*d.spacing

	// 1. Trim rungs that expired or slid outside the window — but ONLY
	// while the ladder is full. A deep rung left behind by a pump is still
	// one of the top-20 visible levels; removing it before its replacement
	// exists is exactly how the visible book thins out mid-move.
	if len(d.orders) >= d.Levels {
		for id, o := range d.orders {
			off := d.ticksFrom(center, o.price)
			stale := now.Sub(o.placedAt) > o.ttl
			outside := off < minOff-d.spacing || off > maxOff+3*d.spacing
			if !stale && !outside || cancelBudget == 0 {
				continue
			}
			if !d.Env.Governor.Allow(d.Bot) {
				d.Env.Stats.Throttled.Add(1)
				break
			}
			cancelBudget--
			if err := d.Env.Client.CancelOrder(ctx, d.Bot, id); err != nil && !isGone(err) {
				d.Env.Stats.Errors.Add(1)
				continue
			}
			d.Env.Stats.Cancelled.Add(1)
			delete(d.orders, id)
		}
	}

	// 2. Fill empty rungs, nearest first.
	deficit := 0
	if d.Env.Health == nil || !d.Env.Health.Paused() {
		occupied := map[int]bool{}
		for _, o := range d.orders {
			occupied[d.rung(d.ticksFrom(center, o.price))] = true
		}
		for i := 0; i < d.Levels; i++ {
			off := minOff + i*d.spacing
			if occupied[d.rung(off)] {
				continue
			}
			if placeBudget == 0 {
				deficit++
				continue
			}
			if !d.place(ctx, center, off) {
				deficit++
				placeBudget = 0
				continue
			}
			placeBudget--
			occupied[d.rung(off)] = true
		}
	}

	// Catch up quickly while rungs are missing; idle cadence otherwise.
	if deficit > 0 {
		d.nextAt = time.Now().Add(400 * time.Millisecond)
	} else {
		d.nextAt = time.Now().Add(1200*time.Millisecond + time.Duration(rand.Int63n(1200))*time.Millisecond)
	}
}

// rung buckets an offset onto the ladder grid so slightly-drifted orders
// still count as occupying their rung.
func (d *Depth) rung(off int) int { return (off + d.spacing/2) / d.spacing }

// ticksFrom returns how many ticks price sits from center on this bot's side
// (positive = correct side of the book; negative = crossed after a move).
func (d *Depth) ticksFrom(center, price oms.Money) int {
	diff := int((center - price) / d.Params.Tick)
	if d.Side == "SELL" {
		return -diff
	}
	return diff
}

func (d *Depth) place(ctx context.Context, center oms.Money, off int) bool {
	if !d.Env.Governor.Allow(d.Bot) {
		d.Env.Stats.Throttled.Add(1)
		return false
	}
	o := off
	if d.Side == "BUY" {
		o = -off
	}
	price := d.Params.offsetTicks(center, o)
	// Depth qty grows away from the touch (the classic depth profile).
	scale := 1 + float64(off)/float64(d.spacing*8)
	qty := dist.ClampQuantity(dist.ParetoQuantity(d.Params.MinQty*3, 1.5)*scale,
		d.Params.MinQty, d.Params.MaxQty)
	d.seq++
	resp, err := d.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: d.Bot, MarketID: d.Params.ID, Side: d.Side, OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("sim-%d-%d", d.Bot, d.seq),
	})
	if err != nil {
		d.Env.Stats.Errors.Add(1)
		log.Printf("[depth %d %s] create: %v", d.Bot, d.Params.Symbol, err)
		return false
	}
	if !resp.Accepted {
		d.Env.handleReject(resp.RejectReason)
		return false
	}
	d.Env.Stats.Placed.Add(1)
	ttl := time.Duration(rand.ExpFloat64() * float64(d.TTLMean))
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	d.orders[resp.OmsOrderID] = &depthOrder{side: d.Side, price: price, offset: off, placedAt: time.Now(), ttl: ttl}
	return true
}

// Reconcile drops local entries the server no longer has (fills/losses);
// orphan cleanup happens via the maker-style prefix sweep in its own pass.
func (d *Depth) Reconcile(ctx context.Context) {
	active, err := d.Env.Client.ActiveOrders(ctx, d.Bot)
	if err != nil {
		return
	}
	server := map[string]bool{}
	for _, o := range active {
		server[o.OmsOrderID] = true
	}
	for id := range d.orders {
		if !server[id] {
			delete(d.orders, id)
		}
	}
}

// CancelAll clears the ladder (shutdown path).
func (d *Depth) CancelAll(ctx context.Context) {
	for id := range d.orders {
		if err := d.Env.Client.CancelOrder(ctx, d.Bot, id); err == nil || isGone(err) {
			delete(d.orders, id)
		}
	}
}
