package agents

import (
	"sync"
	"time"
)

// Bucket is a token bucket. Allow is non-blocking: agents SKIP an action
// when throttled (a governor signal, not an error).
type Bucket struct {
	mu     sync.Mutex
	tokens float64
	cap    float64
	rate   float64 // tokens/sec
	last   time.Time
}

func NewBucket(rate, burst float64) *Bucket {
	return &Bucket{tokens: burst, cap: burst, rate: rate, last: time.Now()}
}

func (b *Bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.cap {
		b.tokens = b.cap
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Governor combines the global ops cap with per-bot buckets sized safely
// under the OMS per-user limits (100/s, 1000/min).
type Governor struct {
	global            *Bucket
	mu                sync.Mutex
	bots              map[int64]*Bucket
	botRate, botBurst float64
}

func NewGovernor(globalRate, globalBurst, botRate, botBurst float64) *Governor {
	return &Governor{
		global:   NewBucket(globalRate, globalBurst),
		bots:     map[int64]*Bucket{},
		botRate:  botRate,
		botBurst: botBurst,
	}
}

// Allow returns true when both the global and the bot's budget permit one
// OMS operation now.
func (g *Governor) Allow(bot int64) bool {
	g.mu.Lock()
	b, ok := g.bots[bot]
	if !ok {
		b = NewBucket(g.botRate, g.botBurst)
		g.bots[bot] = b
	}
	g.mu.Unlock()
	if !b.Allow() {
		return false
	}
	return g.global.Allow()
}
