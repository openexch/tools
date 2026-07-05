package refprice

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// BinanceSource follows real Binance public streams (@bookTicker for mid
// moves, @trade for taker flow) and converts them to reference returns.
// Ported from tools/binance-replay/websocket.go with the same reconnect
// discipline; drops rather than blocks on a slow consumer.
type BinanceSource struct {
	baseURL string // wss://stream.binance.com:9443/ws
	markets []BinanceMarket

	ticks   chan RefTick
	lastMsg atomic.Int64 // unix nanos of last useful message across markets

	mu      sync.Mutex
	mids    map[string]float64 // binance sym -> last mid
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

type BinanceMarket struct {
	Symbol     string // sim symbol, e.g. "BTC-USD"
	BinanceSym string // e.g. "btcusdt"
}

type binanceTrade struct {
	EventType    string `json:"e"`
	Symbol       string `json:"s"`
	Price        string `json:"p"`
	Quantity     string `json:"q"`
	IsBuyerMaker bool   `json:"m"`
}

type binanceBookTicker struct {
	Symbol   string `json:"s"`
	BidPrice string `json:"b"`
	AskPrice string `json:"a"`
}

func NewBinanceSource(baseURL string, markets []BinanceMarket) *BinanceSource {
	return &BinanceSource{
		baseURL: baseURL,
		markets: markets,
		ticks:   make(chan RefTick, 1024),
		mids:    map[string]float64{},
	}
}

func (b *BinanceSource) Name() string          { return "binance" }
func (b *BinanceSource) Ticks() <-chan RefTick { return b.ticks }

// Healthy is true when any stream delivered a message recently. (Per-market
// staleness is visible to the router through tick absence; source-level
// health gates the failover.)
func (b *BinanceSource) Healthy() bool {
	last := b.lastMsg.Load()
	return last > 0 && time.Since(time.Unix(0, last)) < 10*time.Second
}

func (b *BinanceSource) Start() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.started {
		return
	}
	b.started = true
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	for _, m := range b.markets {
		if m.BinanceSym == "" {
			continue
		}
		m := m
		b.wg.Add(2)
		go func() {
			defer b.wg.Done()
			b.streamLoop(ctx, m, m.BinanceSym+"@bookTicker", b.handleBookTicker)
		}()
		go func() {
			defer b.wg.Done()
			b.streamLoop(ctx, m, m.BinanceSym+"@trade", b.handleTrade)
		}()
	}
}

func (b *BinanceSource) Stop() {
	b.mu.Lock()
	cancel := b.cancel
	b.started = false
	b.cancel = nil
	b.mu.Unlock()
	if cancel != nil {
		cancel()
		b.wg.Wait()
	}
}

func (b *BinanceSource) streamLoop(ctx context.Context, m BinanceMarket, stream string, handle func(BinanceMarket, []byte)) {
	url := b.baseURL + "/" + stream
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, url, nil)
		if err != nil {
			log.Printf("[refprice/binance] %s dial error: %v, retrying in 5s", stream, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		log.Printf("[refprice/binance] connected: %s", stream)
		for {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[refprice/binance] %s read error: %v, reconnecting", stream, err)
				conn.Close()
				break
			}
			handle(m, msg)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (b *BinanceSource) handleBookTicker(m BinanceMarket, msg []byte) {
	var t binanceBookTicker
	if err := json.Unmarshal(msg, &t); err != nil {
		return
	}
	bid, err1 := strconv.ParseFloat(t.BidPrice, 64)
	ask, err2 := strconv.ParseFloat(t.AskPrice, 64)
	if err1 != nil || err2 != nil || bid <= 0 || ask <= 0 {
		return
	}
	mid := (bid + ask) / 2
	b.lastMsg.Store(time.Now().UnixNano())

	b.mu.Lock()
	prev := b.mids[m.BinanceSym]
	b.mids[m.BinanceSym] = mid
	b.mu.Unlock()
	if prev <= 0 || mid == prev {
		return
	}
	b.emit(RefTick{Symbol: m.Symbol, LogReturn: math.Log(mid / prev), At: time.Now()})
}

func (b *BinanceSource) handleTrade(m BinanceMarket, msg []byte) {
	var t binanceTrade
	if err := json.Unmarshal(msg, &t); err != nil || t.EventType != "trade" {
		return
	}
	qty, err := strconv.ParseFloat(t.Quantity, 64)
	if err != nil {
		return
	}
	b.lastMsg.Store(time.Now().UnixNano())
	// m=true means the buyer was the maker, i.e. the taker SOLD.
	side := "BUY"
	if t.IsBuyerMaker {
		side = "SELL"
	}
	b.emit(RefTick{Symbol: m.Symbol, TakerSide: side, Qty: qty, At: time.Now()})
}

func (b *BinanceSource) emit(t RefTick) {
	select {
	case b.ticks <- t:
	default: // slow consumer: drop, never block the read loop
	}
}
