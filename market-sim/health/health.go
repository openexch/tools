// Package health makes the demo's health OBSERVABLE — the motivating
// incident was the demo silently broken for a day by a CORS regression
// that only a manual report caught. The sim continuously exercises the
// real user path, and this package turns that into: GET /health (200/503
// + per-check JSON), GET /metrics (Prometheus text), POST /control.
package health

import (
	"sync"
	"time"
)

// CheckState is one named check's latest verdict.
type CheckState struct {
	Name    string    `json:"name"`
	OK      bool      `json:"ok"`
	Detail  string    `json:"detail,omitempty"`
	Since   time.Time `json:"since"`   // when the current OK/not-OK streak began
	Checked time.Time `json:"checked"` // last evaluation
	// Critical checks gate overall health; informational ones don't.
	Critical bool `json:"critical"`
}

// Registry holds current check states (concurrent writers: canary loop,
// CORS prober, feed watcher).
type Registry struct {
	mu     sync.Mutex
	checks map[string]*CheckState
}

func NewRegistry() *Registry {
	return &Registry{checks: map[string]*CheckState{}}
}

// Set records a check outcome.
func (r *Registry) Set(name string, ok bool, detail string, critical bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	c, exists := r.checks[name]
	if !exists {
		c = &CheckState{Name: name, Since: now, Critical: critical}
		r.checks[name] = c
	}
	if c.OK != ok || !exists {
		c.Since = now
	}
	c.OK = ok
	c.Detail = detail
	c.Checked = now
	c.Critical = critical
}

// Snapshot returns all checks plus the overall verdict (every critical
// check must be OK and fresh).
func (r *Registry) Snapshot(staleAfter time.Duration) (bool, []CheckState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	healthy := true
	out := make([]CheckState, 0, len(r.checks))
	now := time.Now()
	for _, c := range r.checks {
		cp := *c
		if c.Critical && (!c.OK || now.Sub(c.Checked) > staleAfter) {
			healthy = false
			if now.Sub(c.Checked) > staleAfter {
				cp.Detail = "stale: last checked " + now.Sub(c.Checked).Truncate(time.Second).String() + " ago"
				cp.OK = false
			}
		}
		out = append(out, cp)
	}
	return healthy, out
}
