package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/openexch/tools/market-sim/feed"
	"github.com/openexch/tools/market-sim/health"
)

// The three market checks. Each is a pure function of the feed view and the
// clock, so a test drives them without a socket.
const (
	marketStaleAfter = 30 * time.Second
	edgeStaleAfter   = 60 * time.Second
	minBookLevels    = 18
)

// frameAge renders how long a market has been silent: "never" when no frame
// has arrived since the client started.
func frameAge(last, now time.Time) string {
	if last.IsZero() {
		return "never"
	}
	return now.Sub(last).Truncate(time.Second).String() + " ago"
}

func silent(last, now time.Time, limit time.Duration) bool {
	return last.IsZero() || now.Sub(last) > limit
}

func withProblem(s string, v feed.BookView) string {
	if v.Problem != "" {
		return s + " [" + v.Problem + "]"
	}
	return s
}

// marketDataFreshState: every market of the local market feed delivered a
// frame within 30 s.
func marketDataFreshState(markets []MarketSpec, view func(int) feed.BookView, now time.Time) (bool, string) {
	var bad []string
	for _, m := range markets {
		v := view(m.ID)
		if silent(v.LastMsgAt, now, marketStaleAfter) {
			bad = append(bad, withProblem(fmt.Sprintf("%s(last frame %s)", m.Symbol, frameAge(v.LastMsgAt, now)), v))
		}
	}
	if len(bad) == 0 {
		return true, ""
	}
	return false, "market feed silent over 30s: " + strings.Join(bad, " ")
}

// bookDepthState: every market shows at least 18 levels a side, from a feed
// that is alive. A silent feed fails here as well: the levels it last showed
// are not evidence of depth.
func bookDepthState(markets []MarketSpec, view func(int) feed.BookView, now time.Time) (bool, string) {
	var bad []string
	for _, m := range markets {
		v := view(m.ID)
		switch {
		case silent(v.LastMsgAt, now, marketStaleAfter):
			bad = append(bad, withProblem(fmt.Sprintf("%s(feed silent, last frame %s)", m.Symbol, frameAge(v.LastMsgAt, now)), v))
		case v.Stale:
			bad = append(bad, fmt.Sprintf("%s(book marked stale)", m.Symbol))
		case len(v.Bids) < minBookLevels || len(v.Asks) < minBookLevels:
			bad = append(bad, fmt.Sprintf("%s(%d/%d)", m.Symbol, len(v.Bids), len(v.Asks)))
		}
	}
	if len(bad) == 0 {
		return true, ""
	}
	return false, "book below 18 levels a side: " + strings.Join(bad, " ")
}

// edgeFeedState: the watched market delivered a frame on the public viewer
// path within 60 s. lagMs < 0 means no relay lag sample.
func edgeFeedState(market MarketSpec, view func(int) feed.BookView, lagMs float64, now time.Time) (bool, string) {
	v := view(market.ID)
	if silent(v.LastMsgAt, now, edgeStaleAfter) {
		return false, withProblem(fmt.Sprintf("edge feed silent over 60s: %s last frame %s", market.Symbol, frameAge(v.LastMsgAt, now)), v)
	}
	detail := fmt.Sprintf("%s last frame %s", market.Symbol, frameAge(v.LastMsgAt, now))
	if lagMs >= 0 {
		detail += fmt.Sprintf(", relay lag ~%.0fms", lagMs)
	}
	return true, detail
}

// edgeFeedUnsetText is the detail of the failing critical check registered when
// no public market WebSocket is configured: the key is required, a run
// without it reads unhealthy.
const edgeFeedUnsetText = "SIM_EDGE_WS_URL not configured"

func registerEdgeFeedUnset(registry *health.Registry) {
	registry.Set("edge_feed_fresh", false, edgeFeedUnsetText, true)
}
