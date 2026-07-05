// Package feed consumes the match-gateway market-data plane (:8081) to give
// agents a view of the REAL exchange book — the closed loop binance-replay
// never had. The feed is lossy under backpressure (match#37 conflation), so
// this view is eventually consistent: deltas are applied optimistically and
// any doubt is resolved by requesting a fresh snapshot, never by trusting
// accumulated state.
package feed

import (
	"sort"
	"sync"
	"time"
)

// Level is one observed price level (display-grade floats; the gateway plane
// serializes numbers, authoritative money lives on the OMS plane).
type Level struct {
	Price    float64
	Quantity float64
}

// BookView is an immutable snapshot handed to agents.
type BookView struct {
	MarketID   int
	BestBid    float64 // 0 = empty side
	BestAsk    float64
	Bids       []Level // sorted best-first, top N
	Asks       []Level
	Imbalance  float64 // (bidQty-askQty)/(bidQty+askQty) over top N, -1..+1
	LastTrade  float64
	LastMsgAt  time.Time
	BidVersion int64
	AskVersion int64
}

const topN = 20 // matches the gateway broadcast cap (GatewayOrderBook.MAX_LEVELS)

// book is the mutable per-market state maintained by the WS client.
type book struct {
	mu         sync.RWMutex
	marketID   int
	bids       map[float64]float64 // price -> qty
	asks       map[float64]float64
	bidVersion int64
	askVersion int64
	lastTrade  float64
	lastMsgAt  time.Time
}

func newBook(marketID int) *book {
	return &book{marketID: marketID, bids: map[float64]float64{}, asks: map[float64]float64{}}
}

func (b *book) replace(bids, asks []Level, bidV, askV int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bids = map[float64]float64{}
	b.asks = map[float64]float64{}
	for _, l := range bids {
		b.bids[l.Price] = l.Quantity
	}
	for _, l := range asks {
		b.asks[l.Price] = l.Quantity
	}
	b.bidVersion, b.askVersion = bidV, askV
	b.lastMsgAt = time.Now()
}

// applyDelta returns false when versions regressed unexpectedly and the
// caller should resync via a fresh snapshot.
func (b *book) applyDelta(side, updateType string, price, qty float64, bidV, askV int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Versions are strictly monotonic per side server-side; a regression
	// here means we saw messages out of order (conflation seam).
	if bidV < b.bidVersion || askV < b.askVersion {
		return false
	}
	m := b.bids
	if side == "ASK" {
		m = b.asks
	}
	if updateType == "DELETE_LEVEL" || qty <= 0 {
		delete(m, price)
	} else {
		m[price] = qty
	}
	b.bidVersion, b.askVersion = bidV, askV
	b.lastMsgAt = time.Now()
	return true
}

func (b *book) recordTrade(price float64) {
	b.mu.Lock()
	b.lastTrade = price
	b.lastMsgAt = time.Now()
	b.mu.Unlock()
}

func (b *book) touch() {
	b.mu.Lock()
	b.lastMsgAt = time.Now()
	b.mu.Unlock()
}

// View builds the agent-facing snapshot.
func (b *book) View() BookView {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v := BookView{
		MarketID:   b.marketID,
		LastTrade:  b.lastTrade,
		LastMsgAt:  b.lastMsgAt,
		BidVersion: b.bidVersion,
		AskVersion: b.askVersion,
	}
	v.Bids = topLevels(b.bids, true)
	v.Asks = topLevels(b.asks, false)
	if len(v.Bids) > 0 {
		v.BestBid = v.Bids[0].Price
	}
	if len(v.Asks) > 0 {
		v.BestAsk = v.Asks[0].Price
	}
	var bidQty, askQty float64
	for _, l := range v.Bids {
		bidQty += l.Quantity
	}
	for _, l := range v.Asks {
		askQty += l.Quantity
	}
	if bidQty+askQty > 0 {
		v.Imbalance = (bidQty - askQty) / (bidQty + askQty)
	}
	return v
}

func topLevels(m map[float64]float64, descending bool) []Level {
	out := make([]Level, 0, len(m))
	for p, q := range m {
		out = append(out, Level{p, q})
	}
	sort.Slice(out, func(i, j int) bool {
		if descending {
			return out[i].Price > out[j].Price
		}
		return out[i].Price < out[j].Price
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}
