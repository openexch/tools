package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// bridgeProgress feeds the check that decides whether settlement is actually
// moving. Misreading it is how a dead money path reads as green, so the
// contract is: parse both counters or admit you could not.
func TestBridgeProgress(t *testing.T) {
	const wedged = `# HELP bridge_epochs_total Bridge epochs started since process start
# TYPE bridge_epochs_total counter
bridge_epochs_total 1891
# HELP bridge_forwarded_trades_total Trades forwarded to the Assets Engine
# TYPE bridge_forwarded_trades_total counter
bridge_forwarded_trades_total 0
bridge_source_stalls_total 1881
`

	tests := []struct {
		name       string
		body       string
		status     int
		wantEpochs int64
		wantTrades int64
		wantOK     bool
	}{
		{"the wedged bridge of 2026-07-25", wedged, 200, 1891, 0, true},
		{"a healthy live-following bridge", "bridge_epochs_total 2\nbridge_forwarded_trades_total 164408\n", 200, 2, 164408, true},
		{"epochs missing is unknown, not zero", "bridge_forwarded_trades_total 5\n", 200, 0, 0, false},
		{"trades missing is unknown, not zero", "bridge_epochs_total 5\n", 200, 0, 0, false},
		{"comments and blank lines only", "# HELP x y\n\n", 200, 0, 0, false},
		{"non-200 is unknown", wedged, 503, 0, 0, false},
		{"unparseable value is unknown", "bridge_epochs_total NaN\nbridge_forwarded_trades_total 1\n", 200, 0, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			epochs, trades, ok := bridgeProgress(context.Background(),
				&http.Client{Timeout: 2 * time.Second}, srv.URL)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if epochs != tc.wantEpochs || trades != tc.wantTrades {
				t.Fatalf("epochs=%d trades=%d, want epochs=%d trades=%d",
					epochs, trades, tc.wantEpochs, tc.wantTrades)
			}
		})
	}
}

// An unreachable bridge must read as unknown rather than as a confident zero.
func TestBridgeProgressUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	if _, _, ok := bridgeProgress(context.Background(),
		&http.Client{Timeout: time.Second}, url); ok {
		t.Fatal("unreachable bridge reported ok=true")
	}
}
