package feed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

// The market-data frames of the viewer WebSocket and the candles body. Prices,
// quantities and volumes are decimal strings with at most 8 fraction digits;
// ids and times are JSON numbers. The decoder is strict: a missing field, a
// number where a string is due (or the reverse) and an unknown enum value are
// errors that name the frame and the field, never a silent zero.

// Level is one observed price level (display-grade floats: the agents' view;
// the wire value is a decimal string).
type Level struct {
	Price    float64
	Quantity float64
}

// Change is one entry of a BOOK_DELTA.
type Change struct {
	Price      float64
	Quantity   float64
	OrderCount int64
	Side       string // BID | ASK
	UpdateType string // NEW_LEVEL | UPDATE_LEVEL | DELETE_LEVEL
}

// Trade is one entry of a TRADES_BATCH.
type Trade struct {
	TradeID    string
	JournalSeq int64
	Price      float64
	Quantity   float64
	TradeCount int64
	Side       string // BUY | SELL
	Timestamp  int64
}

// Frame is a decoded frame. Only the fields of its Type are set.
type Frame struct {
	Type     string
	Known    bool // false: a type this decoder does not model (ignored by the client)
	MarketID int64
	// BOOK_SNAPSHOT / BOOK_DELTA
	Bids, Asks                                       []Level
	Changes                                          []Change
	BidVersion, AskVersion, BookVersion, FromVersion int64
	Stale                                            bool
	// TRADES_BATCH
	Trades []Trade
	// ERROR
	Code, Message string
	Parts         []string
}

var decimalRe = regexp.MustCompile(`^-?[0-9]+(\.[0-9]{1,8})?$`)

type obj map[string]json.RawMessage

func parseObj(raw []byte, path string) (obj, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%s is not a JSON object", path)
	}
	var o obj
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return o, nil
}

func (o obj) raw(path, key string) (json.RawMessage, error) {
	v, ok := o[key]
	if !ok {
		return nil, fmt.Errorf("%s%s is missing", path, key)
	}
	return v, nil
}

func (o obj) str(path, key string) (string, error) {
	v, err := o.raw(path, key)
	if err != nil {
		return "", err
	}
	if len(v) == 0 || v[0] != '"' {
		return "", fmt.Errorf("%s%s is not a JSON string", path, key)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("%s%s is not a JSON string", path, key)
	}
	return s, nil
}

func (o obj) num(path, key string) (int64, error) {
	v, err := o.raw(path, key)
	if err != nil {
		return 0, err
	}
	n, perr := strconv.ParseInt(string(v), 10, 64)
	if perr != nil {
		return 0, fmt.Errorf("%s%s is not a JSON integer", path, key)
	}
	return n, nil
}

func (o obj) dec(path, key string) (float64, error) {
	s, err := o.str(path, key)
	if err != nil {
		if v, ok := o[key]; ok && len(v) > 0 && v[0] != '"' {
			return 0, fmt.Errorf("%s%s is not a decimal string", path, key)
		}
		return 0, err
	}
	if !decimalRe.MatchString(s) {
		return 0, fmt.Errorf("%s%s is not a decimal string", path, key)
	}
	f, perr := strconv.ParseFloat(s, 64)
	if perr != nil {
		return 0, fmt.Errorf("%s%s is not a decimal string", path, key)
	}
	return f, nil
}

func (o obj) oneOf(path, key string, allowed ...string) (string, error) {
	s, err := o.str(path, key)
	if err != nil {
		return "", err
	}
	for _, a := range allowed {
		if s == a {
			return s, nil
		}
	}
	return "", fmt.Errorf("%s%s is %q, not one of %v", path, key, s, allowed)
}

func (o obj) items(path, key string) ([]obj, error) {
	v, err := o.raw(path, key)
	if err != nil {
		return nil, err
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(v, &parts); err != nil {
		return nil, fmt.Errorf("%s%s is not a JSON array", path, key)
	}
	out := make([]obj, len(parts))
	for i, p := range parts {
		out[i], err = parseObj(p, fmt.Sprintf("%s%s[%d]", path, key, i))
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func decodeLevels(o obj, key string) ([]Level, error) {
	items, err := o.items("", key)
	if err != nil {
		return nil, err
	}
	out := make([]Level, len(items))
	for i, it := range items {
		p := fmt.Sprintf("%s[%d].", key, i)
		if out[i].Price, err = it.dec(p, "price"); err != nil {
			return nil, err
		}
		if out[i].Quantity, err = it.dec(p, "quantity"); err != nil {
			return nil, err
		}
		if _, err = it.num(p, "orderCount"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func decodeCandle(o obj, p string) error {
	if _, err := o.num(p, "time"); err != nil {
		return err
	}
	for _, k := range []string{"open", "high", "low", "close", "volume"} {
		if _, err := o.dec(p, k); err != nil {
			return err
		}
	}
	_, err := o.num(p, "tradeCount")
	return err
}

func decodeTickerFields(o obj, p string) error {
	if _, err := o.num(p, "marketId"); err != nil {
		return err
	}
	for _, k := range []string{"lastPrice", "priceChange", "priceChangePercent", "high24h", "low24h", "volume24h"} {
		if _, err := o.dec(p, k); err != nil {
			return err
		}
	}
	_, err := o.num(p, "timestamp")
	return err
}

// Decode parses one text frame. A frame with no type, or one whose fields do
// not match the schema, is an error "simulator cannot decode <TYPE>: <field>
// <what is wrong>". A type this decoder does not model returns Known=false.
func Decode(data []byte) (Frame, error) {
	o, err := parseObj(data, "frame")
	if err != nil {
		return Frame{}, fmt.Errorf("simulator cannot decode frame: %v", err)
	}
	typ, err := o.str("", "type")
	if err != nil {
		return Frame{}, fmt.Errorf("simulator cannot decode frame: %v", err)
	}
	f := Frame{Type: typ, Known: true}
	fail := func(err error) (Frame, error) {
		return Frame{}, fmt.Errorf("simulator cannot decode %s: %v", typ, err)
	}
	switch typ {
	case "BOOK_SNAPSHOT":
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
		if f.Bids, err = decodeLevels(o, "bids"); err != nil {
			return fail(err)
		}
		if f.Asks, err = decodeLevels(o, "asks"); err != nil {
			return fail(err)
		}
		if f.BookVersion, err = o.num("", "bookVersion"); err != nil {
			return fail(err)
		}
		if _, err = o.num("", "timestamp"); err != nil {
			return fail(err)
		}
		if v, ok := o["stale"]; ok {
			if string(bytes.TrimSpace(v)) != "true" {
				return fail(fmt.Errorf("stale is not true"))
			}
			f.Stale = true
		}
	case "BOOK_DELTA":
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
		items, err := o.items("", "changes")
		if err != nil {
			return fail(err)
		}
		for i, it := range items {
			p := fmt.Sprintf("changes[%d].", i)
			var c Change
			if c.Price, err = it.dec(p, "price"); err != nil {
				return fail(err)
			}
			if c.Quantity, err = it.dec(p, "quantity"); err != nil {
				return fail(err)
			}
			if c.OrderCount, err = it.num(p, "orderCount"); err != nil {
				return fail(err)
			}
			if c.Side, err = it.oneOf(p, "side", "BID", "ASK"); err != nil {
				return fail(err)
			}
			if c.UpdateType, err = it.oneOf(p, "updateType", "NEW_LEVEL", "UPDATE_LEVEL", "DELETE_LEVEL"); err != nil {
				return fail(err)
			}
			f.Changes = append(f.Changes, c)
		}
		for _, k := range []struct {
			key string
			dst *int64
		}{{"bidVersion", &f.BidVersion}, {"askVersion", &f.AskVersion}, {"bookVersion", &f.BookVersion}, {"fromVersion", &f.FromVersion}} {
			if *k.dst, err = o.num("", k.key); err != nil {
				return fail(err)
			}
		}
		if _, err = o.num("", "timestamp"); err != nil {
			return fail(err)
		}
	case "TRADES_BATCH":
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
		items, err := o.items("", "trades")
		if err != nil {
			return fail(err)
		}
		for i, it := range items {
			p := fmt.Sprintf("trades[%d].", i)
			var t Trade
			if t.TradeID, err = it.str(p, "tradeId"); err != nil {
				return fail(err)
			}
			if !decimalRe.MatchString(t.TradeID) {
				return fail(fmt.Errorf("%stradeId is not a decimal string", p))
			}
			if t.JournalSeq, err = it.num(p, "journalSeq"); err != nil {
				return fail(err)
			}
			if t.Price, err = it.dec(p, "price"); err != nil {
				return fail(err)
			}
			if t.Quantity, err = it.dec(p, "quantity"); err != nil {
				return fail(err)
			}
			if t.TradeCount, err = it.num(p, "tradeCount"); err != nil {
				return fail(err)
			}
			if t.Side, err = it.oneOf(p, "side", "BUY", "SELL"); err != nil {
				return fail(err)
			}
			if t.Timestamp, err = it.num(p, "timestamp"); err != nil {
				return fail(err)
			}
			f.Trades = append(f.Trades, t)
		}
		if _, err = o.num("", "timestamp"); err != nil {
			return fail(err)
		}
	case "TICKER_STATS":
		if err = decodeTickerFields(o, ""); err != nil {
			return fail(err)
		}
		f.MarketID, _ = o.num("", "marketId")
	case "TICKERS":
		items, err := o.items("", "tickers")
		if err != nil {
			return fail(err)
		}
		for i, it := range items {
			if err = decodeTickerFields(it, fmt.Sprintf("tickers[%d].", i)); err != nil {
				return fail(err)
			}
		}
		if _, err = o.num("", "timestamp"); err != nil {
			return fail(err)
		}
	case "CANDLE_HISTORY":
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
		if _, err = o.str("", "interval"); err != nil {
			return fail(err)
		}
		items, err := o.items("", "candles")
		if err != nil {
			return fail(err)
		}
		for i, it := range items {
			if err = decodeCandle(it, fmt.Sprintf("candles[%d].", i)); err != nil {
				return fail(err)
			}
		}
	case "CANDLE_UPDATE":
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
		if _, err = o.str("", "interval"); err != nil {
			return fail(err)
		}
		raw, err := o.raw("", "candle")
		if err != nil {
			return fail(err)
		}
		c, err := parseObj(raw, "candle")
		if err != nil {
			return fail(err)
		}
		if err = decodeCandle(c, "candle."); err != nil {
			return fail(err)
		}
	case "SUBSCRIPTION_CONFIRMED":
		if _, err = o.str("", "status"); err != nil {
			return fail(err)
		}
		if f.MarketID, err = o.num("", "marketId"); err != nil {
			return fail(err)
		}
	case "PONG":
		if _, err = o.num("", "timestamp"); err != nil {
			return fail(err)
		}
	case "ERROR":
		if f.Code, err = o.str("", "code"); err != nil {
			return fail(err)
		}
		if f.Message, err = o.str("", "message"); err != nil {
			return fail(err)
		}
		if v, ok := o["parts"]; ok {
			if err = json.Unmarshal(v, &f.Parts); err != nil {
				return fail(fmt.Errorf("parts is not an array of strings"))
			}
		}
	default:
		f.Known = false
	}
	return f, nil
}

// DecodeCandlesBody parses the body of GET /api/candles. marketId is a JSON
// number.
func DecodeCandlesBody(data []byte) error {
	o, err := parseObj(data, "body")
	if err != nil {
		return fmt.Errorf("simulator cannot decode candles body: %v", err)
	}
	fail := func(err error) error { return fmt.Errorf("simulator cannot decode candles body: %v", err) }
	if _, err = o.num("", "marketId"); err != nil {
		return fail(err)
	}
	if _, err = o.str("", "interval"); err != nil {
		return fail(err)
	}
	items, err := o.items("", "candles")
	if err != nil {
		return fail(err)
	}
	for i, it := range items {
		if err = decodeCandle(it, fmt.Sprintf("candles[%d].", i)); err != nil {
			return fail(err)
		}
	}
	return nil
}
