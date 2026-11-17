package oms

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Wire types for the gateway REST API under /api/v2 (oe-gateway). Ids are
// decimal strings on the wire; money is a decimal string with at most 8
// fraction digits. The API refuses unknown fields, so request types carry
// exactly the documented fields.

// ID is an integer id that crosses the wire as a decimal string ("1"). It
// also accepts a bare JSON number when decoding.
type ID int64

func (v ID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatInt(int64(v), 10) + `"`), nil
}

func (v *ID) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		*v = 0
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("id %q: %w", string(b), err)
	}
	*v = ID(n)
	return nil
}

// CreateOrderRequest is POST /api/v2/orders. UserID selects the credential;
// it never goes on the wire (the gateway refuses a userId field).
type CreateOrderRequest struct {
	UserID        int64  `json:"-"`
	MarketID      int    `json:"-"`
	Side          string `json:"side"` // BUY | SELL
	OrderType     string `json:"type"` // LIMIT | MARKET | ...
	TimeInForce   string `json:"timeInForce"`
	Price         *Money `json:"price,omitempty"`
	Quantity      Money  `json:"quantity"`
	ClientOrderID string `json:"clientOrderId,omitempty"` // a UUID; the sim leaves it empty
}

// MarshalJSON writes marketId as an id string next to the other fields.
func (r CreateOrderRequest) MarshalJSON() ([]byte, error) {
	type plain CreateOrderRequest
	return json.Marshal(struct {
		MarketID ID `json:"marketId"`
		plain
	}{ID(r.MarketID), plain(r)})
}

// CreateOrderResponse is the create answer. Accepted, RejectReason and
// KeyFinal are filled by the client: a core reject is an HTTP 4xx/503 with
// the core's reason name, and comes back here as Accepted=false so agents
// treat it as a governor signal, not as a transport failure.
type CreateOrderResponse struct {
	OrderID    string `json:"orderId"`
	Status     string `json:"status"`
	Duplicate  bool   `json:"duplicate"`
	MarketID   ID     `json:"marketId"`
	AcceptedAt int64  `json:"acceptedAt"`
	EventSeq   int64  `json:"eventSeq"`

	Accepted     bool   `json:"-"`
	RejectReason string `json:"-"`
	KeyFinal     bool   `json:"-"`
	HTTP         int    `json:"-"`
}

type AmendResponse struct {
	OrderID   string `json:"orderId"`
	Status    string `json:"status"` // PENDING_REPLACE
	Duplicate bool   `json:"duplicate"`
}

type CancelResponse struct {
	OrderID   string `json:"orderId"`
	Status    string `json:"status"`
	Duplicate bool   `json:"duplicate"`
	Reoffered bool   `json:"reoffered"`
}

// OrderResponse is the API's Order object (open orders, history, stream).
type OrderResponse struct {
	OrderID           string `json:"orderId"`
	ClientOrderID     string `json:"clientOrderId"`
	MarketID          ID     `json:"marketId"`
	Side              string `json:"side"`
	OrderType         string `json:"type"`
	TimeInForce       string `json:"timeInForce"`
	Price             Money  `json:"price"`
	Quantity          Money  `json:"quantity"`
	FilledQuantity    Money  `json:"filledQuantity"`
	RemainingQuantity Money  `json:"remainingQuantity"`
	Status            string `json:"status"`
	Reason            string `json:"reason"`
	MeOrderID         string `json:"meOrderId"`
	CreatedAt         int64  `json:"createdAt"`
	UpdatedAt         int64  `json:"updatedAt"`

	// UserID is the principal the order was read for (set locally: the API
	// never carries a userId).
	UserID int64 `json:"-"`
}

type openOrders struct {
	Orders []OrderResponse `json:"orders"`
}

type AssetBalance struct {
	Asset     string `json:"asset"`
	AssetID   ID     `json:"assetId"`
	Available Money  `json:"available"`
	Locked    Money  `json:"locked"`
	Total     Money  `json:"total"`
}

// Account is GET /api/v2/balances for the principal (UserID filled locally).
type Account struct {
	UserID int64          `json:"-"`
	Assets []AssetBalance `json:"assets"`
}

type DepositResponse struct {
	AssetID   ID    `json:"assetId"`
	Amount    Money `json:"amount"`
	Available Money `json:"available"`
	Duplicate bool  `json:"duplicate"`
}

type MarketInfo struct {
	MarketID    ID     `json:"marketId"`
	Symbol      string `json:"symbol"`
	BaseAsset   string `json:"baseAsset"`
	QuoteAsset  string `json:"quoteAsset"`
	BaseAssetID ID     `json:"baseAssetId"`
	TickSize    Money  `json:"tickSize"`
	LotSize     Money  `json:"lotSize"`
	MinPrice    Money  `json:"minPrice"`
	MaxPrice    Money  `json:"maxPrice"`
	MinQuantity Money  `json:"minQuantity"`
	MaxQuantity Money  `json:"maxQuantity"`
}

type marketsBody struct {
	Markets []MarketInfo `json:"markets"`
}

// Status is the public GET /api/v2/status.
type Status struct {
	Ready               bool   `json:"ready"`
	ConfigVersion       *int64 `json:"configVersion"`
	BehaviorVersion     *int64 `json:"behaviorVersion"`
	IdempotencyWindowMs *int64 `json:"idempotencyWindowMs"`
}

// APIError is the gateway error body {error, code, reason, detail, keyFinal}.
type APIError struct {
	Message    string  `json:"error"`
	Code       string  `json:"code"`
	Reason     *string `json:"reason"`
	Detail     *string `json:"detail"`
	KeyFinal   bool    `json:"keyFinal"`
	HTTP       int     `json:"-"`
	RetryAfter int     `json:"-"` // seconds, from the Retry-After header (0 = none)
}

// ReasonName is the core reason or "" when the gateway answered on its own.
func (e *APIError) ReasonName() string {
	if e.Reason == nil {
		return ""
	}
	return *e.Reason
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("HTTP %d %s (%s)", e.HTTP, e.Code, e.Message)
	if r := e.ReasonName(); r != "" {
		s += " reason " + r
	}
	if e.Detail != nil {
		s += ": " + *e.Detail
	}
	return s
}

// IsTerminalStatus: the core's terminal statuses.
func IsTerminalStatus(s string) bool {
	switch s {
	case "FILLED", "CANCELLED", "REJECTED", "EXPIRED":
		return true
	}
	return false
}

// IsGone reports a cancel or read of an order that is no longer open: 404
// NOT_FOUND (unknown and another user's order answer the same) or 409 with
// the core reason NOT_OPEN.
func IsGone(err error) bool {
	var e *APIError
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == "NOT_FOUND" || (e.Code == "CONFLICT" && e.ReasonName() == "NOT_OPEN")
}
