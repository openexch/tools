package oms

// Wire types for the frozen OMS v1 REST API (order-management/docs/API.md,
// docs/openapi.yaml). Ids are Snowflake strings; money is decimal strings.

type CreateOrderRequest struct {
	UserID        int64  `json:"userId"`
	MarketID      int    `json:"marketId"`
	Side          string `json:"side"`      // BUY | SELL
	OrderType     string `json:"orderType"` // LIMIT | MARKET | ...
	TimeInForce   string `json:"timeInForce,omitempty"`
	Price         *Money `json:"price,omitempty"`
	Quantity      Money  `json:"quantity"`
	ClientOrderID string `json:"clientOrderId,omitempty"`
}

type CreateOrderResponse struct {
	Accepted     bool   `json:"accepted"`
	OmsOrderID   string `json:"omsOrderId"`
	Status       string `json:"status"`
	RejectReason string `json:"rejectReason"`
	Duplicate    bool   `json:"duplicate"`
}

type AmendResponse struct {
	Accepted   bool   `json:"accepted"`
	OmsOrderID string `json:"omsOrderId"`
}

type OrderResponse struct {
	OmsOrderID     string `json:"omsOrderId"`
	ClusterOrderID string `json:"clusterOrderId"`
	ClientOrderID  string `json:"clientOrderId"`
	UserID         int64  `json:"userId"`
	MarketID       int    `json:"marketId"`
	Side           string `json:"side"`
	OrderType      string `json:"orderType"`
	TimeInForce    string `json:"timeInForce"`
	Price          Money  `json:"price"`
	Quantity       Money  `json:"quantity"`
	FilledQty      Money  `json:"filledQty"`
	RemainingQty   Money  `json:"remainingQty"`
	Status         string `json:"status"`
	RejectReason   string `json:"rejectReason"`
	CreatedAtMs    int64  `json:"createdAtMs"`
	UpdatedAtMs    int64  `json:"updatedAtMs"`
}

type AssetBalance struct {
	Asset     string `json:"asset"`
	AssetID   int    `json:"assetId"`
	Available Money  `json:"available"`
	Locked    Money  `json:"locked"`
	Total     Money  `json:"total"`
}

type Account struct {
	UserID int64          `json:"userId"`
	Assets []AssetBalance `json:"assets"`
}

type MarketInfo struct {
	MarketID   int    `json:"marketId"`
	Symbol     string `json:"symbol"`
	BaseAsset  string `json:"baseAsset"`
	QuoteAsset string `json:"quoteAsset"`
}

type APIError struct {
	Message string `json:"error"`
	Code    string `json:"code"`
	HTTP    int    `json:"-"`
}

func (e *APIError) Error() string {
	return e.Code + " (" + e.Message + ")"
}

// Terminal order statuses per API.md.
func IsTerminalStatus(s string) bool {
	switch s {
	case "FILLED", "CANCELLED", "REJECTED", "EXPIRED":
		return true
	}
	return false
}
