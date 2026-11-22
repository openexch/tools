package feed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "marketdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every frame the service sends parses, and its type is the one the file says.
func TestDecodeGoldenFrames(t *testing.T) {
	want := map[string]string{
		"book_delta_80": "BOOK_DELTA", "book_snapshot_20x20": "BOOK_SNAPSHOT", "book_snapshot_base": "BOOK_SNAPSHOT",
		"book_snapshot_empty": "BOOK_SNAPSHOT", "book_snapshot_no_snapshot": "BOOK_SNAPSHOT",
		"candle_history_1m": "CANDLE_HISTORY", "candle_update_new": "CANDLE_UPDATE", "candle_update_open": "CANDLE_UPDATE",
		"error_bad_request": "ERROR", "error_history_unavailable": "ERROR", "pong": "PONG",
		"subscription_confirmed": "SUBSCRIPTION_CONFIRMED", "ticker_stats_flush": "TICKER_STATS",
		"ticker_stats_initial": "TICKER_STATS", "tickers_changed": "TICKERS", "tickers_handshake": "TICKERS",
		"trades_batch_flush": "TRADES_BATCH", "trades_batch_initial": "TRADES_BATCH",
	}
	for name, typ := range want {
		f, err := Decode(golden(t, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if f.Type != typ || !f.Known {
			t.Errorf("%s: type %q known=%v, want %s", name, f.Type, f.Known, typ)
		}
	}
	if err := DecodeCandlesBody(golden(t, "candles_body_5m")); err != nil {
		t.Errorf("candles body: %v", err)
	}
}

func TestDecodeSnapshotAndDeltaValues(t *testing.T) {
	s, err := Decode(golden(t, "book_snapshot_20x20"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Bids) != 20 || len(s.Asks) != 20 || s.MarketID != 3 || s.BookVersion == 0 || s.Stale {
		t.Fatalf("snapshot: %d/%d market %d version %d stale %v", len(s.Bids), len(s.Asks), s.MarketID, s.BookVersion, s.Stale)
	}
	if s.Bids[0].Price != 14.99 || s.Bids[1].Quantity != 1.00000001 {
		t.Fatalf("levels: %+v %+v", s.Bids[0], s.Bids[1])
	}
	st, err := Decode(golden(t, "book_snapshot_no_snapshot"))
	if err != nil || !st.Stale || st.BookVersion != 0 {
		t.Fatalf("stale snapshot: %+v %v", st, err)
	}
	d, err := Decode(golden(t, "book_delta_80"))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changes) != 80 || d.BidVersion != 40 || d.AskVersion != 41 || d.FromVersion == 0 || d.BookVersion <= d.FromVersion {
		t.Fatalf("delta: %d changes %d/%d from %d to %d", len(d.Changes), d.BidVersion, d.AskVersion, d.FromVersion, d.BookVersion)
	}
}

func TestDecodeTrades(t *testing.T) {
	f, err := Decode(golden(t, "trades_batch_flush"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Trades) != 2 || f.Trades[0].TradeID != "105" || f.Trades[0].JournalSeq != 210 ||
		f.Trades[1].Price != 15003 || f.Trades[1].Quantity != 0.075 || f.Trades[1].Side != "SELL" || f.Trades[0].TradeCount != 1 {
		t.Fatalf("trades: %+v", f.Trades)
	}
	e, err := Decode(golden(t, "error_history_unavailable"))
	if err != nil || e.Code != "HISTORY_UNAVAILABLE" || len(e.Parts) != 3 {
		t.Fatalf("error frame: %+v %v", e, err)
	}
}

func replaceOnce(t *testing.T, b []byte, old, new string) []byte {
	t.Helper()
	s := string(b)
	if strings.Count(s, old) == 0 {
		t.Fatalf("fixture has no %q", old)
	}
	return []byte(strings.Replace(s, old, new, 1))
}

func TestDecodeRefusals(t *testing.T) {
	cases := []struct {
		name, fixture, old, new, want string
	}{
		{"number price in a level", "book_snapshot_base", `"price":"13.99"`, `"price":13.99`, "simulator cannot decode BOOK_SNAPSHOT: bids[0].price is not a decimal string"},
		{"number quantity in a change", "book_delta_80", `"quantity":"3"`, `"quantity":3`, "simulator cannot decode BOOK_DELTA: changes[0].quantity is not a decimal string"},
		{"nine fraction digits", "book_snapshot_base", `"13.99"`, `"13.990000001"`, "bids[0].price is not a decimal string"},
		{"renamed updateType", "book_delta_80", `"updateType":"NEW_LEVEL"`, `"updateKind":"NEW_LEVEL"`, "simulator cannot decode BOOK_DELTA: changes[0].updateType is missing"},
		{"unknown updateType", "book_delta_80", `"updateType":"NEW_LEVEL"`, `"updateType":"ADD_LEVEL"`, "simulator cannot decode BOOK_DELTA: changes[0].updateType is"},
		{"string marketId", "book_delta_80", `"marketId":3`, `"marketId":"3"`, "simulator cannot decode BOOK_DELTA: marketId is not a JSON integer"},
		{"missing fromVersion", "book_delta_80", `"fromVersion"`, `"from"`, "simulator cannot decode BOOK_DELTA: fromVersion is missing"},
		{"missing journalSeq", "trades_batch_flush", `"journalSeq":210`, `"seq":210`, "simulator cannot decode TRADES_BATCH: trades[0].journalSeq is missing"},
		{"string journalSeq", "trades_batch_flush", `"journalSeq":210`, `"journalSeq":"210"`, "trades[0].journalSeq is not a JSON integer"},
		{"number tradeId", "trades_batch_flush", `"tradeId":"105"`, `"tradeId":105`, "trades[0].tradeId is not a JSON string"},
		{"number trade price", "trades_batch_flush", `"price":"15002"`, `"price":15002`, "trades[0].price is not a decimal string"},
		{"bad side", "trades_batch_flush", `"side":"BUY"`, `"side":"B"`, "trades[0].side is"},
		{"number lastPrice", "ticker_stats_flush", `"lastPrice":"15003"`, `"lastPrice":15003`, "simulator cannot decode TICKER_STATS: lastPrice is not a decimal string"},
		{"ticker in TICKERS", "tickers_handshake", `"volume24h":"0"`, `"volume24h":0`, "simulator cannot decode TICKERS: tickers[0].volume24h is not a decimal string"},
		{"candle number open", "candle_history_1m", `"open":"15000"`, `"open":15000`, "candles[0].open is not a decimal string"},
		{"stale not true", "book_snapshot_no_snapshot", `"stale":true`, `"stale":false`, "stale is not true"},
		{"missing orderCount", "book_snapshot_base", `"orderCount":2`, `"orders":2`, "bids[0].orderCount is missing"},
	}
	for _, c := range cases {
		_, err := Decode(replaceOnce(t, golden(t, c.fixture), c.old, c.new))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want text %q", c.name, err, c.want)
		}
	}
	if err := DecodeCandlesBody(replaceOnce(t, golden(t, "candles_body_5m"), `"marketId":3`, `"marketId":"3"`)); err == nil ||
		!strings.Contains(err.Error(), "marketId is not a JSON integer") {
		t.Errorf("candles body marketId string: %v", err)
	}
	for _, bad := range []string{`not json`, `[]`, `{"marketId":3}`} {
		if _, err := Decode([]byte(bad)); err == nil || !strings.Contains(err.Error(), "simulator cannot decode frame") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if f, err := Decode([]byte(`{"type":"SOMETHING_NEW"}`)); err != nil || f.Known {
		t.Errorf("unknown type: %+v %v", f, err)
	}
}
