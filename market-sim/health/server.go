package health

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/openexch/tools/market-sim/agents"
	"github.com/openexch/tools/market-sim/refprice"
)

// Server exposes the sim's observability surface on its own port:
//
//	GET  /health   200/503 + {"healthy":bool,"checks":[...]}
//	GET  /metrics  Prometheus text (hand-rolled, like OMS/admin)
//	POST /control  {"pause":bool} | {"source":"auto"|"binance"|"gbm"}
type Server struct {
	Addr     string // e.g. 127.0.0.1:8090
	Registry *Registry
	Stats    *agents.Stats
	Router   *refprice.Router
	Canary   *Canary
	// FeedStale returns per-market seconds since the last market-data
	// message (map symbol->seconds).
	FeedStale func() map[string]float64
	// EdgeStale reports seconds since the last frame on the PUBLIC edge WS
	// (market-relay viewer path); negative = check disabled.
	EdgeStale func() float64
	// Pause suspends/resumes all trading agents.
	Pause func(bool)

	StaleAfter time.Duration // a critical check older than this fails closed
}

func (s *Server) Start() *http.Server {
	if s.StaleAfter <= 0 {
		s.StaleAfter = 2 * time.Minute
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/control", s.handleControl)
	srv := &http.Server{Addr: s.Addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[health] server error: %v", err)
		}
	}()
	log.Printf("[health] serving on %s", s.Addr)
	return srv
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	healthy, checks := s.Registry.Snapshot(s.StaleAfter)
	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(map[string]any{"healthy": healthy, "checks": checks})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	healthy, checks := s.Registry.Snapshot(s.StaleAfter)
	b01 := func(ok bool) int {
		if ok {
			return 1
		}
		return 0
	}
	fmt.Fprintf(w, "# HELP sim_healthy Demo end-to-end health (all critical checks pass).\n")
	fmt.Fprintf(w, "# TYPE sim_healthy gauge\nsim_healthy %d\n", b01(healthy))
	fmt.Fprintf(w, "# TYPE sim_check gauge\n")
	for _, c := range checks {
		fmt.Fprintf(w, "sim_check{name=%q,critical=\"%t\"} %d\n", c.Name, c.Critical, b01(c.OK))
	}
	fmt.Fprintf(w, "# TYPE sim_orders_placed_total counter\nsim_orders_placed_total %d\n", s.Stats.Placed.Load())
	fmt.Fprintf(w, "# TYPE sim_orders_cancelled_total counter\nsim_orders_cancelled_total %d\n", s.Stats.Cancelled.Load())
	fmt.Fprintf(w, "# TYPE sim_fills_total counter\nsim_fills_total %d\n", s.Stats.Fills.Load())
	fmt.Fprintf(w, "# TYPE sim_orphans_total counter\nsim_orphans_total %d\n", s.Stats.Orphans.Load())
	fmt.Fprintf(w, "# TYPE sim_throttled_total counter\nsim_throttled_total %d\n", s.Stats.Throttled.Load())
	fmt.Fprintf(w, "# TYPE sim_errors_total counter\nsim_errors_total %d\n", s.Stats.Errors.Load())
	fmt.Fprintf(w, "# TYPE sim_rejects_total counter\n")
	for reason, n := range s.Stats.RejectCounts() {
		fmt.Fprintf(w, "sim_rejects_total{reason=%q} %d\n", reason, n)
	}
	if s.Canary != nil {
		fmt.Fprintf(w, "# TYPE sim_canary_roundtrip_ms gauge\nsim_canary_roundtrip_ms %d\n", s.Canary.RoundtripMs())
	}
	fmt.Fprintf(w, "# TYPE sim_ref_source_info gauge\nsim_ref_source_info{source=%q} 1\n", s.Router.ActiveSource())
	if s.FeedStale != nil {
		fmt.Fprintf(w, "# TYPE sim_feed_stale_seconds gauge\n")
		for sym, sec := range s.FeedStale() {
			fmt.Fprintf(w, "sim_feed_stale_seconds{market=%q} %.1f\n", sym, sec)
		}
	}
	if s.EdgeStale != nil {
		if sec := s.EdgeStale(); sec >= 0 {
			fmt.Fprintf(w, "# HELP sim_edge_feed_stale_seconds Seconds since the last frame on the public edge WS (market-relay viewer path).\n")
			fmt.Fprintf(w, "# TYPE sim_edge_feed_stale_seconds gauge\nsim_edge_feed_stale_seconds %.1f\n", sec)
		}
	}
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Pause  *bool  `json:"pause"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := map[string]any{}
	if req.Pause != nil && s.Pause != nil {
		s.Pause(*req.Pause)
		out["paused"] = *req.Pause
		log.Printf("[control] pause=%v", *req.Pause)
	}
	if req.Source != "" {
		if !s.Router.SetMode(req.Source) {
			http.Error(w, "unknown source "+req.Source, http.StatusBadRequest)
			return
		}
		out["source"] = req.Source
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
