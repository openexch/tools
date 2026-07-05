package agents

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Stats collects sim-wide counters (Phase 3 exports these as Prometheus
// metrics; Phase 1 logs them periodically).
type Stats struct {
	Placed    atomic.Int64
	Cancelled atomic.Int64
	Throttled atomic.Int64
	Errors    atomic.Int64
	Fills     atomic.Int64 // maker fills observed via the OMS user-WS push
	Orphans   atomic.Int64 // server-side orders reconciled away

	mu      sync.Mutex
	rejects map[string]int64
}

func NewStats() *Stats {
	return &Stats{rejects: map[string]int64{}}
}

// Reject counts a risk/engine rejection by reason. Engine-side rejects
// arrive with an empty reason (match#64); those usually mean a tick/band
// bug in the sim itself, so they get their own bucket.
func (s *Stats) Reject(reason string) {
	if reason == "" {
		reason = "engine_empty"
	}
	s.mu.Lock()
	s.rejects[reason]++
	s.mu.Unlock()
}

func (s *Stats) RejectCounts() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.rejects))
	for k, v := range s.rejects {
		out[k] = v
	}
	return out
}

func (s *Stats) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "placed=%d cancelled=%d fills=%d orphans=%d throttled=%d errors=%d",
		s.Placed.Load(), s.Cancelled.Load(), s.Fills.Load(), s.Orphans.Load(),
		s.Throttled.Load(), s.Errors.Load())
	rej := s.RejectCounts()
	keys := make([]string, 0, len(rej))
	for k := range rej {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " reject_%s=%d", k, rej[k])
	}
	return b.String()
}
