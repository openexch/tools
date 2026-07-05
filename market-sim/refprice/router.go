package refprice

import (
	"log"
	"math"
	"sync"
	"time"
)

// Router owns the per-market anchor price. It consumes returns from the
// active source, integrates them onto the anchor, and enforces two guards:
// the anchor stays a margin inside the engine's hard price band, and the
// rolling 60s move stays under the circuit-breaker threshold (5%/60s
// server-side; we cap well below it).
//
// Failover (mode "auto"): live source unhealthy for FailAfter -> fallback;
// back only after the live source has been healthy for RecoverAfter
// (hysteresis). Manual modes pin a source. Switching never moves the anchor.
type Router struct {
	live     Source // may be nil (no Binance configured)
	fallback Source

	// Fail debounce lives in the live source's Healthy() staleness window;
	// RecoverAfter is the router-side hysteresis before switching back.
	RecoverAfter time.Duration
	MaxMove60s   float64 // max abs log-move per rolling 60s (default 0.03)
	MaxTickMove  float64 // max abs log-return applied per tick (default 0.005)

	mu       sync.RWMutex
	mode     string // "auto" | live.Name() | fallback.Name()
	active   string
	statuses map[string]*MarketState
	stop     chan struct{}
	wg       sync.WaitGroup

	healthySince time.Time // live source healthy since (zero = unhealthy)
	graceUntil   time.Time // startup grace: no failover-out before this
}

// MarketState is the router's per-market view agents read every step.
type MarketState struct {
	Symbol    string
	Anchor    float64 // current reference price
	bandLo    float64
	bandHi    float64
	TradeRate float64 // EWMA trades/sec hint from live taker flow
	TakerBias float64 // EWMA of taker direction, -1 (sells) .. +1 (buys)
	// Drift is the current regime trend (log-return/sec; 0 in calm periods).
	// Takers bias their direction with it so volume confirms the move.
	Drift   float64
	history []anchorAt
	regime  *regime
}

type anchorAt struct {
	t   time.Time
	log float64
}

type MarketBand struct {
	Symbol      string
	AnchorStart float64
	BandLo      float64
	BandHi      float64
	MarginPct   float64 // % of band width kept as buffer at each edge
}

func NewRouter(live, fallback Source, bands []MarketBand) *Router {
	r := &Router{
		live:         live,
		fallback:     fallback,
		RecoverAfter: 60 * time.Second,
		MaxMove60s:   0.03,
		MaxTickMove:  0.005,
		mode:         "auto",
		statuses:     map[string]*MarketState{},
		stop:         make(chan struct{}),
	}
	for _, b := range bands {
		width := b.BandHi - b.BandLo
		margin := width * b.MarginPct / 100
		r.statuses[b.Symbol] = &MarketState{
			Symbol: b.Symbol,
			Anchor: b.AnchorStart,
			bandLo: b.BandLo + margin,
			bandHi: b.BandHi - margin,
			regime: newRegime(b.AnchorStart),
		}
	}
	r.active = r.fallback.Name()
	if live != nil {
		r.active = live.Name()
	}
	return r
}

func (r *Router) Start() {
	// Give the live source time to connect before failover can kick in
	// (Healthy() is false until the first message arrives).
	r.graceUntil = time.Now().Add(15 * time.Second)
	if r.live != nil {
		r.live.Start()
	}
	r.fallback.Start()
	r.wg.Add(1)
	go r.run()
}

func (r *Router) Stop() {
	close(r.stop)
	r.wg.Wait()
	if r.live != nil {
		r.live.Stop()
	}
	r.fallback.Stop()
}

// Snapshot returns a copy of the market state for agent decision-making.
func (r *Router) Snapshot(symbol string) (MarketState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.statuses[symbol]
	if !ok {
		return MarketState{}, false
	}
	return MarketState{Symbol: s.Symbol, Anchor: s.Anchor, TradeRate: s.TradeRate,
		TakerBias: s.TakerBias, Drift: s.Drift}, true
}

// Anchors returns the current anchor per market (persistence snapshot).
func (r *Router) Anchors() map[string]float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]float64, len(r.statuses))
	for sym, s := range r.statuses {
		out[sym] = s.Anchor
	}
	return out
}

// SetAnchor overrides a market's anchor (persistence restore), clamped to
// the margin-buffered band. Call before Start.
func (r *Router) SetAnchor(symbol string, anchor float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.statuses[symbol]; ok && anchor > 0 {
		s.Anchor = clampF(anchor, s.bandLo, s.bandHi)
	}
}

// ActiveSource reports which source currently drives anchors.
func (r *Router) ActiveSource() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// SetMode switches routing: "auto", or a source name to pin. Anchors are
// unaffected (returns-only design).
func (r *Router) SetMode(mode string) bool {
	valid := mode == "auto" || mode == r.fallback.Name() || (r.live != nil && mode == r.live.Name())
	if !valid {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
	if mode != "auto" {
		r.active = mode
	}
	log.Printf("[refprice] mode=%s active=%s", r.mode, r.active)
	return true
}

func (r *Router) run() {
	defer r.wg.Done()
	health := time.NewTicker(time.Second)
	defer health.Stop()
	// Regime drift applies on its own clock, ON TOP of the active source's
	// returns, so trends are visible whether binance or gbm drives the price.
	const regimeStep = 250 * time.Millisecond
	regimes := time.NewTicker(regimeStep)
	defer regimes.Stop()
	var liveTicks <-chan RefTick
	if r.live != nil {
		liveTicks = r.live.Ticks()
	}
	for {
		select {
		case <-r.stop:
			return
		case t := <-liveTicks:
			r.consume(r.live.Name(), t)
		case t := <-r.fallback.Ticks():
			r.consume(r.fallback.Name(), t)
		case <-regimes.C:
			r.mu.Lock()
			for _, s := range r.statuses {
				drift := s.regime.step(s.Symbol, s.Anchor)
				s.Drift = drift
				if drift != 0 {
					r.apply(s, drift*regimeStep.Seconds())
				}
			}
			r.mu.Unlock()
		case <-health.C:
			r.checkFailover()
		}
	}
}

func (r *Router) consume(from string, t RefTick) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.statuses[t.Symbol]
	if !ok {
		return
	}
	// Taker-flow hints inform bias regardless of which source drives price.
	if t.TakerSide != "" {
		dir := 1.0
		if t.TakerSide == "SELL" {
			dir = -1
		}
		s.TakerBias = 0.95*s.TakerBias + 0.05*dir
		s.TradeRate = 0.98*s.TradeRate + 0.02 // decayed count; ~trades/sec at steady flow
		return
	}
	if from != r.active || t.LogReturn == 0 {
		return
	}
	r.apply(s, t.LogReturn)
}

func (r *Router) apply(s *MarketState, ret float64) {
	ret = clampF(ret, -r.MaxTickMove, r.MaxTickMove)
	now := time.Now()
	logAnchor := math.Log(s.Anchor)

	// Rolling 60s guard: never move more than MaxMove60s from the oldest
	// anchor in the window (stays clear of the 5%/60s circuit breaker).
	s.history = append(s.history, anchorAt{now, logAnchor})
	for len(s.history) > 1 && now.Sub(s.history[0].t) > 60*time.Second {
		s.history = s.history[1:]
	}
	oldest := s.history[0].log
	next := clampF(logAnchor+ret, oldest-r.MaxMove60s, oldest+r.MaxMove60s)

	anchor := math.Exp(next)
	if anchor < s.bandLo {
		anchor = s.bandLo
	} else if anchor > s.bandHi {
		anchor = s.bandHi
	}
	s.Anchor = anchor
	// Fallback also decays trade rate so bias fades without live flow.
	s.TradeRate *= 0.999
}

func (r *Router) checkFailover() {
	if r.live == nil {
		return
	}
	liveHealthy := r.live.Healthy()
	r.mu.Lock()
	defer r.mu.Unlock()
	if liveHealthy {
		if r.healthySince.IsZero() {
			r.healthySince = time.Now()
		}
	} else {
		r.healthySince = time.Time{}
	}
	if r.mode != "auto" {
		return
	}
	liveName, fbName := r.live.Name(), r.fallback.Name()
	switch r.active {
	case liveName:
		// The source's own staleness window (~10s of silence flips
		// Healthy() to false) provides the fail debounce; the startup
		// grace covers the connect window before the first message.
		if !liveHealthy && time.Now().After(r.graceUntil) {
			r.active = fbName
			log.Printf("[refprice] live source unhealthy -> failover to %s", fbName)
		}
	case fbName:
		if liveHealthy && time.Since(r.healthySince) >= r.RecoverAfter {
			r.active = liveName
			log.Printf("[refprice] live source stable %s -> back to %s", r.RecoverAfter, liveName)
		}
	}
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
