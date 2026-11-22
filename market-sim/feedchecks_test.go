package main

import (
	"strings"
	"testing"
	"time"

	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/health"
)

var testMarkets = []MarketSpec{{ID: 1, Symbol: "AAA-USD"}, {ID: 2, Symbol: "BBB-USD"}}

func levels(n int) []feed.Level { return make([]feed.Level, n) }

func viewsOf(m map[int]feed.BookView) func(int) feed.BookView {
	return func(id int) feed.BookView { return m[id] }
}

func TestMarketDataFresh(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-5 * time.Second)
	ok, d := marketDataFreshState(testMarkets, viewsOf(map[int]feed.BookView{1: {LastMsgAt: fresh}, 2: {LastMsgAt: fresh}}), now)
	if !ok || d != "" {
		t.Fatalf("fresh: %v %q", ok, d)
	}
	ok, d = marketDataFreshState(testMarkets, viewsOf(map[int]feed.BookView{
		1: {LastMsgAt: fresh}, 2: {LastMsgAt: now.Add(-45 * time.Second)}}), now)
	if ok || d != "market feed silent over 30s: BBB-USD(last frame 45s ago)" {
		t.Fatalf("one silent: %v %q", ok, d)
	}
	// The service stopped: nothing ever arrived.
	ok, d = marketDataFreshState(testMarkets, viewsOf(nil), now)
	if ok || d != "market feed silent over 30s: AAA-USD(last frame never) BBB-USD(last frame never)" {
		t.Fatalf("never: %v %q", ok, d)
	}
	ok, d = marketDataFreshState(testMarkets[:1], viewsOf(map[int]feed.BookView{1: {Problem: "simulator cannot decode BOOK_DELTA: x"}}), now)
	if ok || !strings.HasSuffix(d, "[simulator cannot decode BOOK_DELTA: x]") {
		t.Fatalf("problem: %v %q", ok, d)
	}
}

func TestBookDepth(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Second)
	full := feed.BookView{LastMsgAt: fresh, Bids: levels(20), Asks: levels(18)}
	ok, d := bookDepthState(testMarkets, viewsOf(map[int]feed.BookView{1: full, 2: full}), now)
	if !ok || d != "" {
		t.Fatalf("full: %v %q", ok, d)
	}
	thin := feed.BookView{LastMsgAt: fresh, Bids: levels(17), Asks: levels(20)}
	ok, d = bookDepthState(testMarkets, viewsOf(map[int]feed.BookView{1: full, 2: thin}), now)
	if ok || d != "book below 18 levels a side: BBB-USD(17/20)" {
		t.Fatalf("thin: %v %q", ok, d)
	}
	// The levels of a feed that went silent are not evidence of depth.
	old := full
	old.LastMsgAt = now.Add(-2 * time.Minute)
	ok, d = bookDepthState(testMarkets[:1], viewsOf(map[int]feed.BookView{1: old}), now)
	if ok || d != "book below 18 levels a side: AAA-USD(feed silent, last frame 2m0s ago)" {
		t.Fatalf("silent: %v %q", ok, d)
	}
	stale := full
	stale.Stale = true
	ok, d = bookDepthState(testMarkets[:1], viewsOf(map[int]feed.BookView{1: stale}), now)
	if ok || d != "book below 18 levels a side: AAA-USD(book marked stale)" {
		t.Fatalf("stale: %v %q", ok, d)
	}
	ok, d = bookDepthState(testMarkets[:1], viewsOf(nil), now)
	if ok || !strings.Contains(d, "feed silent, last frame never") {
		t.Fatalf("never: %v %q", ok, d)
	}
}

func TestEdgeFeed(t *testing.T) {
	now := time.Now()
	m := testMarkets[0]
	ok, d := edgeFeedState(m, viewsOf(map[int]feed.BookView{1: {LastMsgAt: now.Add(-3 * time.Second)}}), 12.4, now)
	if !ok || d != "AAA-USD last frame 3s ago, relay lag ~12ms" {
		t.Fatalf("fresh: %v %q", ok, d)
	}
	ok, d = edgeFeedState(m, viewsOf(map[int]feed.BookView{1: {LastMsgAt: now.Add(-75 * time.Second)}}), -1, now)
	if ok || d != "edge feed silent over 60s: AAA-USD last frame 1m15s ago" {
		t.Fatalf("silent: %v %q", ok, d)
	}
	ok, d = edgeFeedState(m, viewsOf(nil), -1, now)
	if ok || d != "edge feed silent over 60s: AAA-USD last frame never" {
		t.Fatalf("never: %v %q", ok, d)
	}
}

// With the market feed silent the simulator must not read healthy: all three
// checks fail and each names the feed.
func TestSilentFeedMakesSimulatorUnhealthy(t *testing.T) {
	now := time.Now()
	reg := health.NewRegistry()
	reg.Set("gateway_ready", true, "", true)
	for name, f := range map[string]func() (bool, string){
		"market_data_fresh": func() (bool, string) { return marketDataFreshState(testMarkets, viewsOf(nil), now) },
		"book_depth":        func() (bool, string) { return bookDepthState(testMarkets, viewsOf(nil), now) },
		"edge_feed_fresh":   func() (bool, string) { return edgeFeedState(testMarkets[0], viewsOf(nil), -1, now) },
	} {
		ok, d := f()
		if ok || !strings.Contains(d, "feed") {
			t.Errorf("%s: %v %q", name, ok, d)
		}
		reg.Set(name, ok, d, true)
	}
	healthy, states := reg.Snapshot(2 * time.Minute)
	if healthy {
		t.Fatal("simulator healthy without a market feed")
	}
	failing := 0
	for _, s := range states {
		if !s.OK {
			failing++
		}
	}
	if failing != 3 {
		t.Fatalf("%d failing checks, want 3", failing)
	}
}

func TestEdgeFeedUnsetFailsCritical(t *testing.T) {
	reg := health.NewRegistry()
	registerEdgeFeedUnset(reg)
	healthy, states := reg.Snapshot(2 * time.Minute)
	if healthy || len(states) != 1 || states[0].Name != "edge_feed_fresh" || !states[0].Critical ||
		states[0].Detail != "SIM_EDGE_WS_URL not configured" {
		t.Fatalf("%v %+v", healthy, states)
	}
}
