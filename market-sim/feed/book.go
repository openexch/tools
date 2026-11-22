// Package feed consumes the market-data service WebSocket (/ws) to give
// agents a view of the REAL exchange book, which closes the loop. The feed is lossy under backpressure (match#37 conflation), so
// this view is eventually consistent: deltas are applied optimistically and
// any doubt is resolved by requesting a fresh snapshot, never by trusting
// accumulated state.
package feed

import (
	"sort"
	"sync"
	"time"
)

// BookView is an immutable snapshot handed to agents.
type BookView struct {
	MarketID    int
	BestBid     float64 // 0 = empty side
	BestAsk     float64
	Bids        []Level // sorted best-first, top N
	Asks        []Level
	Imbalance   float64 // (bidQty-askQty)/(bidQty+askQty) over top N, -1..+1
	LastTrade   float64
	LastMsgAt   time.Time
	BidVersion  int64
	AskVersion  int64
	BookVersion int64
	Stale       bool   // the last snapshot was sent with "stale":true
	Problem     string // the last frame this market could not decode ("" = none)
}

const topN = 20 // matches the gateway broadcast cap (GatewayOrderBook.MAX_LEVELS)

// book is the mutable per-market state maintained by the WS client.
type book struct {
	mu          sync.RWMutex
	marketID    int
	bids        map[float64]float64 // price -> qty
	asks        map[float64]float64
	bidVersion  int64
	askVersion  int64
	bookVersion int64
	stale       bool
	problem     string
	lastTrade   float64
	lastMsgAt   time.Time
}

func newBook(marketID int) *book {
	return &book{marketID: marketID, bids: map[float64]float64{}, asks: map[float64]float64{}}
}

// replace installs a snapshot. A stale snapshot (the service says the book is
// broken or old) replaces the content but is not a sign of a live feed: it
// does not move the last-message time.
func (b *book) replace(bids, asks []Level, bidV, askV, bookV int64, stale bool) {
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
	b.bidVersion, b.askVersion, b.bookVersion = bidV, askV, bookV
	b.stale = stale
	if !stale {
		b.problem = ""
		b.lastMsgAt = time.Now()
	}
}

// applyDelta applies one BOOK_DELTA atomically. It returns false, applying
// nothing, when the delta does not continue this book (its fromVersion is not
// the book's version, or a side version went backwards): the caller asks for a
// fresh snapshot instead of trusting accumulated state.
func (b *book) applyDelta(changes []Change, bidV, askV, bookV, fromV int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if fromV != b.bookVersion || bidV < b.bidVersion || askV < b.askVersion {
		return false
	}
	for _, ch := range changes {
		m := b.bids
		if ch.Side == "ASK" {
			m = b.asks
		}
		if ch.UpdateType == "DELETE_LEVEL" || ch.Quantity <= 0 {
			delete(m, ch.Price)
		} else {
			m[ch.Price] = ch.Quantity
		}
	}
	b.bidVersion, b.askVersion, b.bookVersion = bidV, askV, bookV
	b.lastMsgAt = time.Now()
	return true
}

func (b *book) setProblem(s string) {
	b.mu.Lock()
	b.problem = s
	b.mu.Unlock()
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
		MarketID:    b.marketID,
		LastTrade:   b.lastTrade,
		LastMsgAt:   b.lastMsgAt,
		BidVersion:  b.bidVersion,
		AskVersion:  b.askVersion,
		BookVersion: b.bookVersion,
		Stale:       b.stale,
		Problem:     b.problem,
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
