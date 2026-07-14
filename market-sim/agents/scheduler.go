package agents

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/openexch/tools/market-sim/oms"
)

// Scheduler steps one market's population on a single goroutine (bounded
// concurrency by construction: one scheduler per market, not per agent).
// All agent state is confined to this goroutine; external inputs (user-WS
// order events) arrive through the Fills channel and are drained here.
type Scheduler struct {
	Symbol     string
	Makers     []*Maker
	Takers     []*Taker
	Noise      []*Noise
	Depth      []*Depth
	Stabilizer *Stabilizer // liquidity backstop; nil = disabled

	// Fills receives pushed OrderResponse events for this market's maker
	// bots (fed by oms.UserWS followers in run.go).
	Fills chan oms.OrderResponse

	cancel       context.CancelFunc
	wg           sync.WaitGroup
	nextDepthRec time.Time
}

const tickInterval = 200 * time.Millisecond

func (s *Scheduler) Start() {
	if s.Fills == nil {
		s.Fills = make(chan oms.OrderResponse, 256)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go s.run(ctx)
}

func (s *Scheduler) run(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.drainFills()
			for _, t := range s.Takers {
				t.Tick(ctx, tickInterval)
			}
			for _, n := range s.Noise {
				if n.Due(now) {
					n.Step(ctx)
				}
			}
			for _, d := range s.Depth {
				if d.Due(now) {
					d.Step(ctx)
				}
			}
			for _, m := range s.Makers {
				if m.Due(now) {
					m.Step(ctx)
				}
				if m.ReconcileDue(now) {
					m.Reconcile(ctx)
				}
			}
			if s.Stabilizer != nil && s.Stabilizer.Due(now) {
				s.Stabilizer.Step(ctx)
			}
			if now.After(s.nextDepthRec) {
				s.nextDepthRec = now.Add(45 * time.Second)
				for _, d := range s.Depth {
					d.Reconcile(ctx)
				}
			}
		}
	}
}

// drainFills routes pushed order events to their owning maker or depth
// keeper (same goroutine as the agents, so no locking on their state).
func (s *Scheduler) drainFills() {
	for {
		select {
		case o := <-s.Fills:
			routed := false
			for _, m := range s.Makers {
				if m.Bot == o.UserID {
					m.OnOrderEvent(o)
					routed = true
					break
				}
			}
			if !routed {
				for _, d := range s.Depth {
					if d.Bot == o.UserID {
						d.OnOrderEvent(o)
						routed = true
						break
					}
				}
			}
			if !routed && s.Stabilizer != nil && s.Stabilizer.Bot == o.UserID {
				s.Stabilizer.OnOrderEvent(o)
			}
		default:
			return
		}
	}
}

// Stop halts stepping and best-effort cancels all live sim orders so the
// demo book doesn't strand quotes across restarts.
func (s *Scheduler) Stop(cleanupBudget time.Duration) {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget)
	defer cancel()
	for _, m := range s.Makers {
		m.CancelAll(ctx)
	}
	for _, n := range s.Noise {
		n.CancelAll(ctx)
	}
	for _, d := range s.Depth {
		d.CancelAll(ctx)
	}
	if s.Stabilizer != nil {
		s.Stabilizer.CancelAll(ctx)
	}
	log.Printf("[scheduler %s] stopped, quotes cleared", s.Symbol)
}
