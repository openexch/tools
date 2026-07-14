package agents

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/openexch/tools/market-sim/dist"
	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/oms"
)

// Stabilizer is the market's liquidity backstop: a designated market maker /
// arbitrageur that stays DORMANT while the book is healthy and only wakes when
// a fast move (a regime dump/pump) leaves the book one-sided or crossed with
// stale levels the organic depth bots could not re-ladder past in time. It does
// two things a real DMM/arb does:
//
//  1. Clears stale crossed levels — bids resting ABOVE the fair price (or asks
//     resting BELOW it) — by hitting them with marketable IOC orders, i.e. it
//     arbitrages them away. This is what unwinds the "20 bids / 0 asks with the
//     top bid above the last trade" state seen after a dump.
//  2. Backfills the thin side with a small resting ladder around the fair price
//     so the visible book is never one-sided during a move.
//
// It is privileged-funded (re-seeded well above every other bot) so it can
// always quote the missing side; a backstop that runs dry is not a backstop.
// The wake thresholds keep it a BACKSTOP, not a constant quoter: while both
// sides are healthy it does nothing, so it never flattens the volatility the
// regime engine exists to produce.
type Stabilizer struct {
	Bot    int64
	Params MarketParams
	Env    Env

	seq    int64
	orders map[string]*stabOrder // our resting backfill orders
	nextAt time.Time
}

type stabOrder struct {
	side     string
	price    oms.Money
	placedAt time.Time
	ttl      time.Duration
}

const (
	// stabMinSideLevels: fewer visible levels than this on a side wakes the
	// backfill. Well below the depth keeper's 20-level target, so the
	// stabilizer only steps in on a genuine one-sided book, not normal churn.
	stabMinSideLevels = 6
	// stabStaleTolPct: a bid more than this fraction ABOVE fair (or an ask
	// below fair) is a stale crossed level to arbitrage away. Comfortably
	// outside the maker touch region so normal near-touch quotes are untouched.
	stabStaleTolPct = 0.004
	// stabBackfillLevels: ladder rungs the stabilizer restores on a thin side.
	// Enough to lift the side off the floor, not enough to own the book.
	stabBackfillLevels = 8
	// per-step op budgets so a burst never blows through the rate governor.
	stabClearBudget    = 6
	stabBackfillBudget = 8
	stabRetireBudget   = 8
)

func NewStabilizer(bot int64, p MarketParams, env Env) *Stabilizer {
	return &Stabilizer{Bot: bot, Params: p, Env: env, orders: map[string]*stabOrder{}}
}

func (s *Stabilizer) Due(now time.Time) bool { return now.After(s.nextAt) }

// OnOrderEvent drops our resting backfill orders once they fill or otherwise
// terminate (fed from the OMS user-WS, same as the maker/depth keepers).
func (s *Stabilizer) OnOrderEvent(o oms.OrderResponse) {
	if _, ok := s.orders[o.OmsOrderID]; !ok {
		return
	}
	if oms.IsTerminalStatus(o.Status) {
		if o.Status == "FILLED" {
			s.Env.Stats.Fills.Add(1)
		}
		delete(s.orders, o.OmsOrderID)
	}
}

// Step assesses the book against the fair reference price and, only if the book
// has broken, clears stale crossed levels then backfills the thin side. When
// the organic book has recovered it retires its own orders and goes idle.
func (s *Stabilizer) Step(ctx context.Context) {
	state, ok := s.Env.Router.Snapshot(s.Params.Symbol)
	if !ok {
		s.nextAt = time.Now().Add(time.Second)
		return
	}
	fair := s.Params.legalPrice(state.Anchor)
	book := s.Env.Feed.View(s.Params.ID)
	now := time.Now()

	// A halted market is an admin decision — never add flow into it; just let
	// our resting orders age out and re-check later.
	if s.Env.Health != nil && s.Env.Health.Paused() {
		s.retire(ctx, now, true)
		s.nextAt = now.Add(2 * time.Second)
		return
	}

	// 1. Arbitrage stale crossed levels first, so the backfill below rests
	//    instead of crossing a bid that should not be there.
	cleared := s.clearStale(ctx, book, fair)

	// 2. Backfill a side that has gone thin.
	askThin := len(book.Asks) < stabMinSideLevels
	bidThin := len(book.Bids) < stabMinSideLevels
	placed := 0
	if askThin {
		placed += s.backfill(ctx, "SELL", fair, book)
	}
	if bidThin {
		placed += s.backfill(ctx, "BUY", fair, book)
	}

	// 3. Withdraw once the organic book has recovered (both sides healthy and
	//    nothing stale), or on TTL, so the stabilizer does not linger as a
	//    permanent quoter and flatten the market.
	healthy := !askThin && !bidThin && cleared == 0
	s.retire(ctx, now, healthy)

	if cleared > 0 || placed > 0 {
		s.Env.Stats.Stabilized.Add(1)
		log.Printf("[stabilizer %s] intervened: cleared %d stale level(s), backfilled %d rung(s) around %s",
			s.Params.Symbol, cleared, placed, fair)
	}

	// Fast cadence while the book is broken; idle otherwise.
	if cleared > 0 || placed > 0 || askThin || bidThin {
		s.nextAt = now.Add(300*time.Millisecond + time.Duration(rand.Int63n(200))*time.Millisecond)
	} else {
		s.nextAt = now.Add(2*time.Second + time.Duration(rand.Int63n(1500))*time.Millisecond)
	}
}

// clearStale hits bids resting above fair (and asks below it) with marketable
// IOC orders so the crossed/stale levels fill and vanish. Returns the number of
// clearing orders sent this step.
func (s *Stabilizer) clearStale(ctx context.Context, book feed.BookView, fair oms.Money) int {
	f := fair.Float()
	hiBid := f * (1 + stabStaleTolPct)
	loAsk := f * (1 - stabStaleTolPct)
	budget := stabClearBudget
	sent := 0

	for _, lvl := range book.Bids {
		if budget == 0 {
			break
		}
		if lvl.Price <= hiBid {
			break // bids are best-first; once at/below the band the rest are fine
		}
		if s.hit(ctx, "SELL", oms.MoneyFromFloat(lvl.Price), lvl.Quantity) {
			sent++
			budget--
		}
	}
	for _, lvl := range book.Asks {
		if budget == 0 {
			break
		}
		if lvl.Price >= loAsk {
			break // asks are best-first; once at/above the band the rest are fine
		}
		if s.hit(ctx, "BUY", oms.MoneyFromFloat(lvl.Price), lvl.Quantity) {
			sent++
			budget--
		}
	}
	return sent
}

// hit sends one marketable IOC order priced to cross the given stale level.
func (s *Stabilizer) hit(ctx context.Context, side string, price oms.Money, levelQty float64) bool {
	if !s.Env.Governor.Allow(s.Bot) {
		s.Env.Stats.Throttled.Add(1)
		return false
	}
	qty := dist.ClampQuantity(levelQty, s.Params.MinQty, s.Params.MaxQty)
	p := price.Clamp(s.Params.BandLo, s.Params.BandHi)
	s.seq++
	resp, err := s.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
		UserID: s.Bot, MarketID: s.Params.ID, Side: side, OrderType: "LIMIT",
		TimeInForce: "IOC", Price: &p, Quantity: oms.MoneyFromFloat(qty),
		ClientOrderID: fmt.Sprintf("stab-%d-%d", s.Bot, s.seq),
	})
	if err != nil {
		s.Env.Stats.Errors.Add(1)
		return false
	}
	if !resp.Accepted {
		s.Env.handleReject(resp.RejectReason)
		return false
	}
	s.Env.Stats.Placed.Add(1)
	return true
}

// backfill lays a small resting GTC ladder on a thin side, starting just past
// the touch (never crossing the opposite best) and stepping away from fair.
func (s *Stabilizer) backfill(ctx context.Context, side string, fair oms.Money, book feed.BookView) int {
	// spacing in ticks (~0.03% of price), at least 1 — same convention as Depth.
	spacingTicks := int(fair.Float() * 0.0003 / s.Params.Tick.Float())
	if spacingTicks < 1 {
		spacingTicks = 1
	}
	// Anchor the ladder so a rung can never cross the resting opposite side.
	base := fair
	if side == "SELL" {
		if book.BestBid > 0 {
			if floor := oms.MoneyFromFloat(book.BestBid) + s.Params.Tick; floor > base {
				base = floor
			}
		}
	} else if book.BestAsk > 0 {
		if ceil := oms.MoneyFromFloat(book.BestAsk) - s.Params.Tick; ceil < base {
			base = ceil
		}
	}

	budget := stabBackfillBudget
	placed := 0
	for i := 0; i < stabBackfillLevels && budget > 0; i++ {
		ticks := i * spacingTicks
		if side == "BUY" {
			ticks = -ticks
		}
		price := s.Params.offsetTicks(base, ticks)
		if !s.Env.Governor.Allow(s.Bot) {
			s.Env.Stats.Throttled.Add(1)
			break
		}
		qty := dist.ClampQuantity(dist.ParetoQuantity(s.Params.MinQty*3, 1.5),
			s.Params.MinQty, s.Params.MaxQty)
		s.seq++
		resp, err := s.Env.Client.CreateOrder(ctx, oms.CreateOrderRequest{
			UserID: s.Bot, MarketID: s.Params.ID, Side: side, OrderType: "LIMIT",
			TimeInForce: "GTC", Price: &price, Quantity: oms.MoneyFromFloat(qty),
			ClientOrderID: fmt.Sprintf("stab-%d-%d", s.Bot, s.seq),
		})
		if err != nil {
			s.Env.Stats.Errors.Add(1)
			break
		}
		if !resp.Accepted {
			s.Env.handleReject(resp.RejectReason)
			break
		}
		s.Env.Stats.Placed.Add(1)
		budget--
		placed++
		ttl := 45*time.Second + time.Duration(rand.Int63n(30))*time.Second
		s.orders[resp.OmsOrderID] = &stabOrder{side: side, price: price, placedAt: time.Now(), ttl: ttl}
	}
	return placed
}

// retire cancels our resting orders that have aged out, or all of them once the
// organic book is healthy again, so the stabilizer steps back out of the market.
func (s *Stabilizer) retire(ctx context.Context, now time.Time, healthy bool) {
	budget := stabRetireBudget
	for id, o := range s.orders {
		if budget == 0 {
			break
		}
		if !healthy && now.Sub(o.placedAt) <= o.ttl {
			continue
		}
		budget--
		if err := s.Env.Client.CancelOrder(ctx, s.Bot, id); err != nil && !isGone(err) {
			s.Env.Stats.Errors.Add(1)
			continue
		}
		s.Env.Stats.Cancelled.Add(1)
		delete(s.orders, id)
	}
}

// CancelAll clears our resting orders on shutdown.
func (s *Stabilizer) CancelAll(ctx context.Context) {
	for id := range s.orders {
		if err := s.Env.Client.CancelOrder(ctx, s.Bot, id); err == nil || isGone(err) {
			delete(s.orders, id)
		}
	}
}
