package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openexch/tools/market-sim/oms"
)

func TestParseFaucetMax(t *testing.T) {
	m, err := parseFaucetMax("0:10000, 1:0.5")
	if err != nil || m[0] != oms.MustMoney("10000") || m[1] != oms.MustMoney("0.5") {
		t.Fatalf("%v %v", m, err)
	}
	if m, err := parseFaucetMax(""); err != nil || len(m) != 0 {
		t.Fatalf("empty: %v %v", m, err)
	}
	for _, bad := range []string{"0", "x:1", "0:-1", "0:0", "0:1,0:2"} {
		if _, err := parseFaucetMax(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLoadCredentials(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys")
	os.WriteFile(p, []byte("key-aaaaaaaaaaaaaaaa:1\nkey-bbbbbbbbbbbbbbbb:2\n"), 0o600)
	if c, err := loadCredentials(p, false, []int64{1, 2}); err != nil || c.Mode() != "api-key" {
		t.Fatalf("%v %v", c, err)
	}
	if _, err := loadCredentials(p, false, []int64{1, 2, 3}); err == nil || !strings.Contains(err.Error(), "[3]") {
		t.Fatalf("a bot without a key was accepted: %v", err)
	}
	if _, err := loadCredentials("", false, nil); err == nil {
		t.Fatal("no auth scheme was accepted")
	}
	if _, err := loadCredentials(p, true, nil); err == nil {
		t.Fatal("two auth schemes were accepted")
	}
	if c, err := loadCredentials("", true, nil); err != nil || c.Mode() != "dev" {
		t.Fatalf("%v %v", c, err)
	}
}

func TestConfigUsersIncludeCanary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SelectMarkets("BTC-USD")
	u := cfg.Users()
	if len(u) != cfg.BotsPerMarket+1 || u[len(u)-1] != cfg.CanaryBot {
		t.Fatalf("users %v", u)
	}
}

func TestCheckMarkets(t *testing.T) {
	body := `{"configVersion":1,"markets":[{"marketId":"1","symbol":"BTC-USD","tickSize":"1.00000000","minPrice":"0.00000000","maxPrice":"0.00000000"},{"marketId":"2","symbol":"ETH-USD","tickSize":"0.10000000"}],"assets":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/markets" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	client := oms.NewClient(srv.URL, oms.DevAuth{})
	cfg := DefaultConfig()
	cfg.SelectMarkets("BTC-USD")
	if err := checkMarkets(context.Background(), &cfg, client); err != nil {
		t.Fatalf("matching market refused: %v", err)
	}
	cfg = DefaultConfig()
	cfg.SelectMarkets("ETH-USD,SOL-USD")
	err := checkMarkets(context.Background(), &cfg, client)
	if err == nil || !strings.Contains(err.Error(), "tick") || !strings.Contains(err.Error(), "market 3") {
		t.Fatalf("mismatch not refused: %v", err)
	}
}
