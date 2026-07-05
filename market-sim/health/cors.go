package health

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// CORSProbe replays exactly the class of regression that broke the demo for
// a day (oms#37 default-deny + unset OMS_CORS_ORIGINS): a browser-origin
// preflight plus a real GET, asserting Access-Control-Allow-Origin echoes
// the demo UI's origin. It probes BOTH the local OMS and the public edge —
// the outage lived at the edge, where nobody was looking.
type CORSProbe struct {
	Registry *Registry
	Origin   string   // e.g. https://trade.openexch.io
	Targets  []Target // endpoints to probe
	Interval time.Duration

	client *http.Client
}

type Target struct {
	Name     string // check-name suffix, e.g. "local", "public"
	BaseURL  string // e.g. http://127.0.0.1:8080
	Critical bool
}

func (p *CORSProbe) Run(ctx context.Context) {
	if p.Interval <= 0 {
		p.Interval = 30 * time.Second
	}
	p.client = &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}}
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, t := range p.Targets {
				ok, detail := p.probe(ctx, t.BaseURL)
				p.Registry.Set("cors_"+t.Name, ok, detail, t.Critical)
			}
		}
	}
}

func (p *CORSProbe) probe(ctx context.Context, base string) (bool, string) {
	// 1. Preflight: what the browser sends before POST /orders.
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, base+"/api/v1/orders", nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Origin", p.Origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,authorization")
	resp, err := p.client.Do(req)
	if err != nil {
		return false, "preflight: " + err.Error()
	}
	resp.Body.Close()
	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != p.Origin && acao != "*" {
		return false, fmt.Sprintf("preflight: Access-Control-Allow-Origin=%q for Origin=%q (HTTP %d)",
			acao, p.Origin, resp.StatusCode)
	}

	// 2. Real cross-origin GET (CorsPolicy applies to responses too).
	// /api/v1/health is auth-exempt, so this asserts pure CORS behavior.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/health", nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Origin", p.Origin)
	resp, err = p.client.Do(req)
	if err != nil {
		return false, "get: " + err.Error()
	}
	resp.Body.Close()
	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != p.Origin && acao != "*" {
		return false, fmt.Sprintf("get: Access-Control-Allow-Origin=%q (HTTP %d)", acao, resp.StatusCode)
	}
	return true, ""
}
