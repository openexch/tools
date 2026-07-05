package agents

import (
	"context"
	"log"
	"sync"
	"time"
)

// Scheduler steps one market's population on a single goroutine (bounded
// concurrency by construction: one scheduler per market, not per agent).
type Scheduler struct {
	Symbol string
	Makers []*Maker
	Takers []*Taker

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

const tickInterval = 200 * time.Millisecond

func (s *Scheduler) Start() {
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
			for _, t := range s.Takers {
				t.Tick(ctx, tickInterval)
			}
			for _, m := range s.Makers {
				if m.Due(now) {
					m.Step(ctx)
				}
			}
		}
	}
}

// Stop halts stepping and best-effort cancels all live maker quotes so the
// demo book doesn't strand sim orders across restarts.
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
	log.Printf("[scheduler %s] stopped, quotes cleared", s.Symbol)
}
