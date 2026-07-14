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
	// stabMinSideLevels: a side thinner than this wakes the backfill. One above
	// the demo's book_depth floor (run.go requires >=18 both sides) so the
	// stabilizer refills a side just BEFORE it would touch the floor, leaving a
	// level of margin against a burst of takers between steps.
	stabMinSideLevels = 19
	// stabTargetLevels: refill a thin side up to this many levels, comfortably
	// above the floor so it survives a burst of takers before the next step.
	stabTargetLevels = 20
	// stabStaleTolPct: a bid more than this fraction ABOVE fair (or an ask
	// below fair) is a stale crossed level to arbitrage away. Comfortably
	// outside the maker touch region so normal near-touch quotes are untouched.
	stabStaleTolPct = 0.004
	// stabTouchOffsetTicks keeps a from-empty ladder a few ticks BEHIND the
	// touch (like the depth keeper's minOff) so its rungs are not first in the
	// taker firing line and instantly eaten.
	stabTouchOffsetTicks = 4
	// per-step op budgets so a burst never blows through the rate governor
	// (excess is retried on the next step; the governor also gates each op).
	stabClearBudget    = 6
	stabBackfillBudget = 14
	stabRetireBudget   = 14
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

	// 2. Backfill a side that has thinned below the depth floor.
	askThin := len(book.Asks) < stabMinSideLevels
	bidThin := len(book.Bids) < stabMinSideLevels
	placed := 0
	if askThin {
		placed += s.backfill(ctx, "SELL", fair, book)
	}
	if bidThin {
		placed += s.backfill(ctx, "BUY", fair, book)
	}

	// 3. Retire our rungs on TTL only: they age out on their own, so when the
	//    organic depth has taken over the side simply stays full without them.
	//    (Cancel-on-"healthy" would flap: our own rungs make the side healthy,
	//    we cancel them, the side drops, we refill.)
	s.retire(ctx, now, false)

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

// backfill tops a thin side up to the target level count by adding DISTINCT
// rungs just BEYOND the current book edge (so it never over-stacks existing
// levels), stepping away from the touch. From an empty side it starts a few
// ticks behind the touch so its near rungs are not instantly eaten.
func (s *Stabilizer) backfill(ctx context.Context, side string, fair oms.Money, book feed.BookView) int {
	var have int
	if side == "SELL" {
		have = len(book.Asks)
	} else {
		have = len(book.Bids)
	}
	need := stabTargetLevels - have
	if need <= 0 {
		return 0
	}

	// spacing in ticks (~0.03% of price), at least 1 — same convention as Depth.
	spacingTicks := int(fair.Float() * 0.0003 / s.Params.Tick.Float())
	if spacingTicks < 1 {
		spacingTicks = 1
	}

	// edge = the worst existing level on this side (so new rungs extend the
	// book rather than duplicate it); from empty, a few ticks behind the touch.
	edge := fair
	if side == "SELL" {
		if have > 0 {
			edge = oms.MoneyFromFloat(book.Asks[have-1].Price)
		} else {
			if book.BestBid > 0 {
				if floor := oms.MoneyFromFloat(book.BestBid) + s.Params.Tick; floor > edge {
					edge = floor
				}
			}
			edge = s.Params.offsetTicks(edge, stabTouchOffsetTicks)
		}
	} else {
		if have > 0 {
			edge = oms.MoneyFromFloat(book.Bids[have-1].Price)
		} else {
			if book.BestAsk > 0 {
				if ceil := oms.MoneyFromFloat(book.BestAsk) - s.Params.Tick; ceil < edge {
					edge = ceil
				}
			}
			edge = s.Params.offsetTicks(edge, -stabTouchOffsetTicks)
		}
	}

	budget := stabBackfillBudget
	if budget > need {
		budget = need
	}
	placed := 0
	for i := 1; i <= need && budget > 0; i++ {
		ticks := i * spacingTicks
		if side == "BUY" {
			ticks = -ticks
		}
		price := s.Params.offsetTicks(edge, ticks)
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

// retire cancels our resting rungs: those aged past their TTL, or (force=true,
// on a halted market or shutdown) all of them. TTL-only aging lets our rungs
// hand off to the organic depth without flapping.
func (s *Stabilizer) retire(ctx context.Context, now time.Time, force bool) {
	budget := stabRetireBudget
	for id, o := range s.orders {
		if budget == 0 {
			break
		}
		if !force && now.Sub(o.placedAt) <= o.ttl {
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
