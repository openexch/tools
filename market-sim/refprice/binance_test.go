package refprice

import (
	"encoding/json"
	"testing"
)

// Real captured payloads. encoding/json matches keys case-insensitively, so
// the colliding pairs ("b"/"B", "e"/"E", "t"/"T", "m"/"M") MUST each have an
// explicitly tagged field or the later key in document order silently
// overwrites the earlier one (this shipped quantities as mid prices once).
func TestBookTickerDecodeCollidingKeys(t *testing.T) {
	raw := `{"u":96975234762,"s":"BTCUSDT","b":"62788.56000000","B":"1.85615000","a":"62788.57000000","A":"0.96016000"}`
	var bt binanceBookTicker
	if err := json.Unmarshal([]byte(raw), &bt); err != nil {
		t.Fatal(err)
	}
	if bt.BidPrice != "62788.56000000" {
		t.Errorf("BidPrice = %q, want the PRICE not the quantity", bt.BidPrice)
	}
	if bt.AskPrice != "62788.57000000" {
		t.Errorf("AskPrice = %q, want the PRICE not the quantity", bt.AskPrice)
	}
	if bt.BidQty != "1.85615000" || bt.AskQty != "0.96016000" {
		t.Errorf("quantities misparsed: %q %q", bt.BidQty, bt.AskQty)
	}
}

func TestTradeDecodeCollidingKeys(t *testing.T) {
	raw := `{"e":"trade","E":1783264589022,"s":"BTCUSDT","t":123456789,"p":"62788.56000000","q":"0.00500000","T":1783264589020,"m":true,"M":true}`
	var tr binanceTrade
	if err := json.Unmarshal([]byte(raw), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.EventType != "trade" {
		t.Errorf("EventType = %q (stomped by event time?)", tr.EventType)
	}
	if !tr.IsBuyerMaker {
		t.Error("IsBuyerMaker lost (stomped by the M ignore-flag?)")
	}
	if tr.Price != "62788.56000000" || tr.Quantity != "0.00500000" {
		t.Errorf("price/qty misparsed: %q %q", tr.Price, tr.Quantity)
	}
}
