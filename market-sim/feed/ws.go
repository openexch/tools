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

// Client maintains one WS connection per market (the gateway tracks a single
// subscribed market per channel) and the observed book for each.
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

// gateway wire shapes (JSON numbers; see GatewayOrderBook.buildJson,
// GatewayStateManager.buildBookDeltaJson, TradeRingBuffer).
type wsMessage struct {
	Type        string     `json:"type"`
	MarketID    int        `json:"marketId"`
	BidVersion  int64      `json:"bidVersion"`
	AskVersion  int64      `json:"askVersion"`
	BookVersion int64      `json:"bookVersion"` // v4 monotonic chain id
	Bids        []wsLevel  `json:"bids"`
	Asks        []wsLevel  `json:"asks"`
	Changes     []wsChange `json:"changes"`
	Trades      []wsTrade  `json:"trades"`
}

type wsLevel struct {
	Price    float64 `json:"price"`
	Quantity float64 `json:"quantity"`
}

type wsChange struct {
	Price      float64 `json:"price"`
	Quantity   float64 `json:"quantity"`
	Side       string  `json:"side"`       // BID | ASK
	UpdateType string  `json:"updateType"` // NEW_LEVEL | UPDATE_LEVEL | DELETE_LEVEL
}

type wsTrade struct {
	Price     float64 `json:"price"`
	Quantity  float64 `json:"quantity"`
	Timestamp int64   `json:"timestamp"`
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
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.MarketID != 0 && msg.MarketID != marketID {
			continue
		}
		switch msg.Type {
		case "BOOK_SNAPSHOT":
			bids := make([]Level, 0, len(msg.Bids))
			for _, l := range msg.Bids {
				bids = append(bids, Level(l))
			}
			asks := make([]Level, 0, len(msg.Asks))
			for _, l := range msg.Asks {
				asks = append(asks, Level(l))
			}
			b.replace(bids, asks, msg.BidVersion, msg.AskVersion)
		case "BOOK_DELTA":
			if c.OnFrameVersion != nil && msg.BookVersion > 0 {
				c.OnFrameVersion(marketID, msg.BookVersion)
			}
			ok := true
			for _, ch := range msg.Changes {
				if !b.applyDelta(ch.Side, ch.UpdateType, ch.Price, ch.Quantity, msg.BidVersion, msg.AskVersion) {
					ok = false
					break
				}
			}
			if !ok {
				// Conflation seam: ask for a fresh snapshot.
				refresh, _ := json.Marshal(map[string]any{"action": "refresh", "marketId": marketID})
				if err := conn.WriteMessage(websocket.TextMessage, refresh); err != nil {
					return fmt.Errorf("refresh: %w", err)
				}
			}
		case "TRADES_BATCH":
			if n := len(msg.Trades); n > 0 {
				b.recordTrade(msg.Trades[n-1].Price)
			}
		default:
			b.touch() // ticker stats, confirmations, candles: liveness only
		}
	}
}
