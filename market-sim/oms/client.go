package oms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client is a typed client for the frozen OMS v1 REST API. It authenticates
// per-bot via the token template (default dev-mode "dev:<userId>", which
// works under OMS_AUTH_MODE=dev; override -auth-template for api-key setups).
type Client struct {
	BaseURL       string
	TokenTemplate string // fmt template receiving the userId, e.g. "dev:%d"
	HTTP          *http.Client
	transport     *http.Transport
}

func NewClient(baseURL, tokenTemplate string) *Client {
	// Keep-alive is on: oms#93 gave the REST plane real HTTP/1.1 keep-alive, so
	// the sim reuses pooled connections instead of dialing one per request. A
	// single Transport backs every agent/follower/canary, so raise the per-host
	// idle pool well above Go's default of 2 and reap idle conns after 90s.
	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		BaseURL:       baseURL,
		TokenTemplate: tokenTemplate,
		HTTP:          &http.Client{Timeout: 10 * time.Second, Transport: tr},
		transport:     tr,
	}
}

func (c *Client) token(userID int64) string {
	return fmt.Sprintf(c.TokenTemplate, userID)
}

// raw performs the request and returns status + body. Only transport-level
// failures are errors; HTTP status interpretation is the caller's.
// With keep-alive on, a pooled connection can be closed by the server's idle
// timeout in the window between our reuse check and the write; retry once.
// Safe because the ops are idempotent: creates via clientOrderId, cancels and
// amends by nature.
func (c *Client) raw(ctx context.Context, method, path string, asUser int64, body any) (int, []byte, error) {
	status, data, err := c.rawOnce(ctx, method, path, asUser, body)
	if err != nil && ctx.Err() == nil && staleConnErr(err) {
		// A batch of idle conns may have aged out together; flush the pool so
		// the retry dials fresh instead of picking another stale one.
		c.transport.CloseIdleConnections()
		return c.rawOnce(ctx, method, path, asUser, body)
	}
	return status, data, err
}

// staleConnErr matches the reused-keep-alive failure modes (the server
// closed the connection between our reuse check and the write).
func staleConnErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "server closed idle connection") ||
		strings.HasSuffix(s, ": EOF") ||
		strings.Contains(s, "connection reset by peer")
}

func (c *Client) rawOnce(ctx context.Context, method, path string, asUser int64, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if asUser != 0 {
		req.Header.Set("Authorization", "Bearer "+c.token(asUser))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// do wraps raw for the common shape: 2xx decodes into out, non-2xx becomes
// *APIError (when the body has the error shape) or a generic error.
func (c *Client) do(ctx context.Context, method, path string, asUser int64, body any, out any) error {
	status, data, err := c.raw(ctx, method, path, asUser, body)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("decode %s %s: %w", method, path, err)
			}
		}
		return nil
	}
	return errorFrom(method, path, status, data)
}

func errorFrom(method, path string, status int, data []byte) error {
	var apiErr APIError
	if json.Unmarshal(data, &apiErr) == nil && apiErr.Code != "" {
		apiErr.HTTP = status
		return &apiErr
	}
	return fmt.Errorf("%s %s: HTTP %d: %s", method, path, status, truncate(data, 200))
}

// CreateOrder submits an order. Risk rejections are NOT Go errors: the API
// returns 400 with a CreateOrderResponse body (accepted=false, rejectReason
// from the fixed vocabulary); those come back as (resp, nil) so callers
// treat them as governor signals. 200 duplicate:true (clientOrderId replay)
// also comes back as a normal response.
func (c *Client) CreateOrder(ctx context.Context, req CreateOrderRequest) (*CreateOrderResponse, error) {
	status, data, err := c.raw(ctx, http.MethodPost, "/api/v1/orders", req.UserID, req)
	if err != nil {
		return nil, err
	}
	if (status >= 200 && status < 300) || status == http.StatusBadRequest {
		var out CreateOrderResponse
		if err := json.Unmarshal(data, &out); err == nil && (out.Accepted || out.RejectReason != "" || out.OmsOrderID != "") {
			return &out, nil
		}
		if status != http.StatusBadRequest {
			return nil, fmt.Errorf("POST /api/v1/orders: HTTP %d: undecodable body %s", status, truncate(data, 200))
		}
	}
	return nil, errorFrom(http.MethodPost, "/api/v1/orders", status, data)
}

// CancelOrder cancels by omsOrderId. 404 comes back as *APIError NOT_FOUND;
// callers may treat it as convergence (already terminal/unknown).
func (c *Client) CancelOrder(ctx context.Context, userID int64, omsOrderID string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/orders/"+omsOrderID, userID, nil, nil)
}

// AmendOrder cancel-and-replaces price and/or quantity (nil = keep).
func (c *Client) AmendOrder(ctx context.Context, userID int64, omsOrderID string, price, quantity *Money) (*AmendResponse, error) {
	body := map[string]*Money{}
	if price != nil {
		body["price"] = price
	}
	if quantity != nil {
		body["quantity"] = quantity
	}
	var out AmendResponse
	if err := c.do(ctx, http.MethodPut, "/api/v1/orders/"+omsOrderID, userID, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrder fetches one order (terminal orders served from persistence).
func (c *Client) GetOrder(ctx context.Context, userID int64, omsOrderID string) (*OrderResponse, error) {
	var out OrderResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/orders/"+omsOrderID, userID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActiveOrders lists the principal's ACTIVE orders.
func (c *Client) ActiveOrders(ctx context.Context, userID int64) ([]OrderResponse, error) {
	var out []OrderResponse
	if err := c.do(ctx, http.MethodGet, "/api/v1/orders", userID, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetAccount returns balances for userID.
func (c *Client) GetAccount(ctx context.Context, userID int64) (*Account, error) {
	var out Account
	if err := c.do(ctx, http.MethodGet, "/api/v1/accounts/"+strconv.FormatInt(userID, 10), userID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Deposit credits a balance. assetId 0 (USD) is accepted by the server even
// though openapi.yaml claims minimum:1 (existing seeders rely on it).
func (c *Client) Deposit(ctx context.Context, userID int64, assetID int, amount Money) error {
	body := map[string]any{"assetId": assetID, "amount": amount}
	return c.do(ctx, http.MethodPost, "/api/v1/accounts/"+strconv.FormatInt(userID, 10)+"/deposit", userID, body, nil)
}

// Markets lists markets (no tick/band info yet, match#64; see config.Markets).
func (c *Client) Markets(ctx context.Context, asUser int64) ([]MarketInfo, error) {
	var out []MarketInfo
	if err := c.do(ctx, http.MethodGet, "/api/v1/markets", asUser, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Health probes GET /api/v1/health (auth-exempt).
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/api/v1/health", 0, nil, nil)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
