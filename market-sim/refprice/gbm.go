package refprice

import (
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/openexch/tools/market-sim/dist"
)

// GBMSource is the self-contained fallback: geometric Brownian motion with
// occasional Hawkes-flavored jump bursts. It is first-class, not an
// afterthought — the demo must be indefinitely presentable without Binance
// egress.
type GBMSource struct {
	markets []GBMMarket
	step    time.Duration
	ticks   chan RefTick

	mu      sync.Mutex
	started bool
	stop    chan struct{}
	wg      sync.WaitGroup
}

type GBMMarket struct {
	Symbol    string
	VolPerSec float64 // stddev of log-return per second
}

func NewGBMSource(markets []GBMMarket, step time.Duration) *GBMSource {
	if step <= 0 {
		step = 250 * time.Millisecond
	}
	return &GBMSource{
		markets: markets,
		step:    step,
		ticks:   make(chan RefTick, 256),
	}
}

func (g *GBMSource) Name() string          { return "gbm" }
func (g *GBMSource) Ticks() <-chan RefTick { return g.ticks }
func (g *GBMSource) Healthy() bool         { return true }

func (g *GBMSource) Start() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started {
		return
	}
	g.started = true
	g.stop = make(chan struct{})
	g.wg.Add(1)
	go g.run(g.stop)
}

func (g *GBMSource) Stop() {
	g.mu.Lock()
	if !g.started {
		g.mu.Unlock()
		return
	}
	g.started = false
	stop := g.stop
	g.mu.Unlock()
	close(stop)
	g.wg.Wait()
}

func (g *GBMSource) run(stop chan struct{}) {
	defer g.wg.Done()
	ticker := time.NewTicker(g.step)
	defer ticker.Stop()
	dt := g.step.Seconds()
	sqrtDt := math.Sqrt(dt)
	// Per-market burst state: recent jump count feeding self-excitation.
	recentJumps := make([]int, len(g.markets))
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			for i, m := range g.markets {
				r := m.VolPerSec * sqrtDt * rand.NormFloat64()
				// Rare jumps, self-exciting: a jump raises the chance of
				// follow-on jumps for a while (clustered volatility).
				jumpP := dist.BurstProbability(0.0015, float64(recentJumps[i]), 0.01)
				if rand.Float64() < jumpP {
					r += (rand.Float64()*6 + 2) * m.VolPerSec * sqrtDt * sign(rand.Float64()-0.5)
					recentJumps[i] += 10
				}
				if recentJumps[i] > 0 {
					recentJumps[i]--
				}
				select {
				case g.ticks <- RefTick{Symbol: m.Symbol, LogReturn: r, At: now}:
				default:
				}
			}
		}
	}
}

func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}
