package refprice

import (
	"log"
	"math"
	"math/rand"
	"time"
)

// regime is the per-market trend state machine that gives the demo visible
// price action: real crypto at minute scale is nearly flat, so calm periods
// alternate with randomized pump/dump events whose drift rides ON TOP of
// the active source's returns. All drift still passes the router's guards
// (per-tick cap + rolling-60s cap under the exchange circuit breaker).
type regime struct {
	state      regimeState
	drift      float64 // log-return per second while in PUMP/DUMP
	until      time.Time
	anchorHome float64 // log of AnchorStart: distance biases event direction
}

type regimeState int

const (
	regimeCalm regimeState = iota
	regimePump
	regimeDump
)

func (s regimeState) String() string {
	switch s {
	case regimePump:
		return "pump"
	case regimeDump:
		return "dump"
	}
	return "calm"
}

// Tuning: calm 1-4 min between events; events run 30-120s at 0.02-0.07%/s
// drift, so a typical move is 1-4% (the rolling-60s cap of 3% still binds
// the worst case, staying clear of the server's 5%/60s breaker).
const (
	calmMinSec  = 60
	calmMaxSec  = 240
	eventMinSec = 30
	eventMaxSec = 120
	driftMin    = 0.0002
	driftMax    = 0.0007
)

func newRegime(anchorStart float64) *regime {
	return &regime{
		state:      regimeCalm,
		until:      time.Now().Add(jitterSec(20, calmMaxSec)), // first event comes sooner
		anchorHome: math.Log(anchorStart),
	}
}

// step advances the state machine and returns the current drift (log-return
// per second). anchor is the market's current reference price.
func (r *regime) step(symbol string, anchor float64) float64 {
	now := time.Now()
	if now.Before(r.until) {
		if r.state == regimeCalm {
			return 0
		}
		return r.drift
	}

	// Transition. From an event, always cool down; from calm, start an event.
	if r.state != regimeCalm {
		ended := r.state
		r.state = regimeCalm
		r.drift = 0
		r.until = now.Add(jitterSec(calmMinSec, calmMaxSec))
		log.Printf("[regime %s] %s over, calm until %s", symbol, ended, r.until.Format("15:04:05"))
		return 0
	}

	// Direction: biased back toward home so the price wanders instead of
	// pinning at the band margin (far above home -> dumps more likely).
	excursion := math.Log(anchor) - r.anchorHome // + = above home
	pBuy := 0.5 - clampF(excursion*4, -0.35, 0.35)
	if rand.Float64() < pBuy {
		r.state = regimePump
		r.drift = driftMin + rand.Float64()*(driftMax-driftMin)
	} else {
		r.state = regimeDump
		r.drift = -(driftMin + rand.Float64()*(driftMax-driftMin))
	}
	r.until = now.Add(jitterSec(eventMinSec, eventMaxSec))
	log.Printf("[regime %s] %s begins: drift %+.4f%%/s until %s (excursion %+.2f%%)",
		symbol, r.state, r.drift*100, r.until.Format("15:04:05"), excursion*100)
	return r.drift
}

func jitterSec(lo, hi int) time.Duration {
	return time.Duration(lo+rand.Intn(hi-lo+1)) * time.Second
}
