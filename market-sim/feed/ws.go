package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client maintains one WS connection per market (a connection holds one
// subscribed market; a subscribe replaces it) and the observed book for each.
type Client struct {
	wsURL   string
	markets []int // marketIds

	// OnFrameVersion, when set BEFORE Start, fires for every BOOK_DELTA
	// carrying a v4 bookVersion. Two clients on the same clock watching the
	// same market see the same versions, which is what the edge-lag
	// measurement diffs (run.go edgeLagTracker).
	OnFrameVersion func(marketID int, bookVersion int64)

	mu     sync.Mutex
	books  map[int]*book
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewClient(wsURL string, marketIDs []int) *Client {
	books := map[int]*book{}
	for _, id := range marketIDs {
		books[id] = newBook(id)
	}
	return &Client{wsURL: wsURL, markets: marketIDs, books: books}
}

func (c *Client) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	for _, id := range c.markets {
		id := id
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.marketLoop(ctx, id)
		}()
	}
}

func (c *Client) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

// View returns the current observed book for a market.
func (c *Client) View(marketID int) BookView {
	c.mu.Lock()
	b := c.books[marketID]
	c.mu.Unlock()
	if b == nil {
		return BookView{MarketID: marketID}
	}
	return b.View()
}

func (c *Client) marketLoop(ctx context.Context, marketID int) {
	b := c.books[marketID]
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := c.session(ctx, marketID, b); err != nil && ctx.Err() == nil {
			log.Printf("[feed] market %d session error: %v, reconnecting in 2s", marketID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// session runs one connect->subscribe->read cycle. Subscribing triggers an
// initial BOOK_SNAPSHOT server-side; a delta-version regression requests a
// "refresh" (fresh snapshot) instead of trusting accumulated state.
func (c *Client) session(ctx context.Context, marketID int, b *book) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, c.wsURL, nil)
	cancel()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	// Stop must not wait out a read deadline: closing the connection ends it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	sub, _ := json.Marshal(map[string]any{"action": "subscribe", "marketId": marketID})
	if err := conn.WriteMessage(websocket.TextMessage, sub); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		f, err := Decode(data)
		if err != nil {
			b.setProblem(err.Error())
			return err
		}
		if f.MarketID != 0 && f.MarketID != int64(marketID) {
			continue
		}
		switch f.Type {
		case "BOOK_SNAPSHOT":
			b.replace(f.Bids, f.Asks, 0, 0, f.BookVersion, f.Stale)
		case "BOOK_DELTA":
			if c.OnFrameVersion != nil && f.BookVersion > 0 {
				c.OnFrameVersion(marketID, f.BookVersion)
			}
			if !b.applyDelta(f.Changes, f.BidVersion, f.AskVersion, f.BookVersion, f.FromVersion) {
				// Chain break or conflation seam: ask for a fresh snapshot.
				refresh, _ := json.Marshal(map[string]any{"action": "refresh", "marketId": marketID})
				if err := conn.WriteMessage(websocket.TextMessage, refresh); err != nil {
					return fmt.Errorf("refresh: %w", err)
				}
			}
		case "TRADES_BATCH":
			if n := len(f.Trades); n > 0 {
				b.recordTrade(f.Trades[n-1].Price)
			}
		case "ERROR":
			// An error frame is not a sign of a live feed.
			b.setProblem(fmt.Sprintf("%s: %s", f.Code, f.Message))
		default:
			if f.Known {
				b.touch() // ticker stats, confirmations, candles, pong: liveness only
			}
		}
	}
}
