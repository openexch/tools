package oms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// APIPrefix is the gateway REST base path.
const APIPrefix = "/api/v2"

// RetryPolicy bounds the resends of one logical request. A keyed request
// (create, amend, keyed cancel, deposit, withdraw) is resent with the SAME
// Idempotency-Key, so the core answers a resend with the decision it stored
// for the first send; that holds only inside the idempotency window, so a
// keyed resend never starts later than MaxElapsed after the first send.
type RetryPolicy struct {
	Attempts   int           // sends per logical request, the first included (0 = 4)
	Backoff    time.Duration // first wait when no Retry-After is given (0 = 200ms); doubles
	MaxBackoff time.Duration // cap of the doubled wait (0 = 2s)
	// MaxElapsed is the latest a keyed resend may start, measured from the
	// first send. 0 = half the gateway's idempotencyWindowMs from /status;
	// with neither known a keyed request is not resent at all.
	MaxElapsed time.Duration
}

func (p RetryPolicy) attempts() int {
	if p.Attempts <= 0 {
		return 4
	}
	return p.Attempts
}

func (p RetryPolicy) backoff(n int) time.Duration {
	b, max := p.Backoff, p.MaxBackoff
	if b <= 0 {
		b = 200 * time.Millisecond
	}
	if max <= 0 {
		max = 2 * time.Second
	}
	for i := 1; i < n && b < max; i++ {
		b *= 2
	}
	if b > max {
		b = max
	}
	return b
}

// Client is a typed client of the gateway REST API (/api/v2). Every bot user
// authenticates with its own credential (Credentials, normally the user's
// API key); no request names a user.
type Client struct {
	BaseURL string // scheme://host:port of oe-gateway, without the /api/v2 path
	Creds   Credentials
	HTTP    *http.Client
	Retry   RetryPolicy
	// Keyed counts the keyed requests per user (nil = not counted).
	Keyed *KeyedCounter
	// KeyedCancels sends an Idempotency-Key on single cancels. Off, a cancel
	// is unkeyed: it takes no request-table entry and the gateway answers a
	// resent cancel of an order that is no longer open with 404/409 or 200
	// reoffered.
	KeyedCancels bool

	transport *http.Transport
	windowMs  atomic.Int64

	// test hooks
	newKey func() string
	sleep  func(ctx context.Context, d time.Duration) error
	clock  func() time.Time
}

func NewClient(baseURL string, creds Credentials) *Client {
	// Keep-alive on: a single Transport backs every agent, follower and the
	// canary, so the per-host idle pool is well above Go's default of 2.
	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Creds:     creds,
		HTTP:      &http.Client{Timeout: 10 * time.Second, Transport: tr},
		transport: tr,
	}
}

// SetIdempotencyWindow records the gateway's idempotencyWindowMs (Status
// does this on every successful read).
func (c *Client) SetIdempotencyWindow(d time.Duration) { c.windowMs.Store(d.Milliseconds()) }

// IdempotencyWindow is the last idempotencyWindowMs read from /status (0 = unknown).
func (c *Client) IdempotencyWindow() time.Duration {
	return time.Duration(c.windowMs.Load()) * time.Millisecond
}

func (c *Client) key() string {
	if c.newKey != nil {
		return c.newKey()
	}
	return NewIdempotencyKey()
}

func (c *Client) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type reply struct {
	status int
	header http.Header
	data   []byte
}

// once sends one HTTP request. asUser 0 = no credential (public routes);
// key "" = no Idempotency-Key.
func (c *Client) once(ctx context.Context, method, path string, asUser int64, body any, key string) (reply, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return reply{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+APIPrefix+path, rd)
	if err != nil {
		return reply{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if asUser != 0 {
		if c.Creds == nil {
			return reply{}, errors.New("no credentials configured")
		}
		if err := c.Creds.Apply(req.Header, asUser); err != nil {
			return reply{}, err
		}
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return reply{status: resp.StatusCode}, err
	}
	return reply{status: resp.StatusCode, header: resp.Header, data: data}, nil
}

// staleConnErr matches the reused keep-alive failure modes (the server
// closed the connection between our reuse check and the write).
func staleConnErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "server closed idle connection") ||
		strings.HasSuffix(s, ": EOF") ||
		strings.Contains(s, "connection reset by peer")
}

// read is an unkeyed read: one resend on a stale pooled connection (a read
// changes nothing).
func (c *Client) read(ctx context.Context, path string, asUser int64) (reply, error) {
	r, err := c.once(ctx, http.MethodGet, path, asUser, nil, "")
	if err != nil && ctx.Err() == nil && staleConnErr(err) {
		c.transport.CloseIdleConnections()
		return c.once(ctx, http.MethodGet, path, asUser, nil, "")
	}
	return r, err
}

// resendable says whether an answer may be resent with the same key, and
// how long to wait first (0 = the policy's backoff). unknown is true when
// the command may have been applied.
func resendable(r reply, err error) (ok, unknown bool, wait time.Duration) {
	if err != nil {
		return true, true, 0 // transport failure or client timeout: outcome unknown
	}
	if r.status == http.StatusGatewayTimeout {
		return true, true, 0 // OUTCOME_UNKNOWN
	}
	if r.status != http.StatusServiceUnavailable && r.status != http.StatusTooManyRequests {
		return false, false, 0
	}
	e := decodeError(r)
	if e == nil || e.KeyFinal {
		return false, false, 0 // a stored decision (core RATE_LIMIT, CIRCUIT_BREAKER): a resend replays it
	}
	switch e.Code {
	case "CORE_UNAVAILABLE", "OVERLOADED", "RATE_LIMITED":
		return true, false, time.Duration(e.RetryAfter) * time.Second
	}
	return false, false, 0 // ADMISSION_CLOSED (gate) and the rest: the caller decides
}

// send runs one logical request: a keyed one (kind != "") under one fresh
// Idempotency-Key reused on every resend, or an unkeyed cancel (kind "",
// resent as is: a cancel is idempotent by nature).
func (c *Client) send(ctx context.Context, kind KeyedKind, method, path string, asUser int64, body any) (reply, error) {
	r, _, _, err := c.sendAttempt(ctx, kind, method, path, asUser, body, nil)
	return r, err
}

// KeyedAttempt is a keyed request whose outcome stayed unknown: its key and
// the time of its first send. Resending the same request under the same key
// before the idempotency window ends gets the core's decision for the first
// send, never a second application.
type KeyedAttempt struct {
	Key   string
	Since time.Time
}

// ErrWindowPassed: a resend of a KeyedAttempt was not sent because its key
// is past MaxElapsed (the same key could now be a new request to the core).
// The first send was decided long ago, so a fresh read shows its effect.
var ErrWindowPassed = errors.New("the idempotency window of this key has passed: the key is not resent")

// ErrWindowUnknown: a resend of a KeyedAttempt was not sent because neither
// RetryPolicy.MaxElapsed nor the gateway's idempotencyWindowMs is known.
var ErrWindowUnknown = errors.New("the idempotency window is not known: the key is not resent")

// sendAttempt is send with an optional earlier attempt to resend (prev
// non-nil: its key is reused and its first-send time bounds the resends). It
// also returns the attempt and whether the outcome is unknown.
func (c *Client) sendAttempt(ctx context.Context, kind KeyedKind, method, path string, asUser int64, body any, prev *KeyedAttempt) (reply, KeyedAttempt, bool, error) {
	// A request that cannot be sent (no credential for the user) is refused
	// before a key is minted or counted.
	if asUser != 0 {
		if c.Creds == nil {
			return reply{}, KeyedAttempt{}, false, errors.New("no credentials configured")
		}
		if err := c.Creds.Apply(http.Header{}, asUser); err != nil {
			return reply{}, KeyedAttempt{}, false, err
		}
	}
	var att KeyedAttempt
	maxElapsed := time.Duration(0)
	if kind != "" {
		maxElapsed = c.Retry.MaxElapsed
		if maxElapsed <= 0 {
			maxElapsed = c.IdempotencyWindow() / 2
		}
		if prev != nil {
			if maxElapsed <= 0 {
				return reply{}, *prev, true, ErrWindowUnknown
			}
			if c.now().Sub(prev.Since) > maxElapsed {
				return reply{}, *prev, false, ErrWindowPassed
			}
			att = *prev
			c.Keyed.Retry(asUser)
		} else {
			att = KeyedAttempt{Key: c.key(), Since: c.now()}
			c.Keyed.Sent(asUser, kind)
		}
	}
	key := att.Key
	start := c.now()
	if kind != "" {
		start = att.Since
	}
	attempts := c.Retry.attempts()
	for n := 1; ; n++ {
		r, err := c.once(ctx, method, path, asUser, body, key)
		ok, unknown, wait := resendable(r, err)
		if !ok || ctx.Err() != nil || n >= attempts {
			c.done(kind, asUser, r, err, unknown)
			return r, att, unknown, err
		}
		if wait <= 0 {
			wait = c.Retry.backoff(n)
		}
		if kind != "" && c.now().Add(wait).Sub(start) > maxElapsed {
			// past this point the same key could be a new request to the core
			c.done(kind, asUser, r, err, unknown)
			return r, att, unknown, err
		}
		if err != nil && staleConnErr(err) {
			c.transport.CloseIdleConnections()
		}
		if werr := c.wait(ctx, wait); werr != nil {
			c.done(kind, asUser, r, err, unknown)
			return r, att, unknown, err
		}
		if kind != "" {
			c.Keyed.Retry(asUser)
		}
	}
}

func (c *Client) done(kind KeyedKind, user int64, r reply, err error, unknown bool) {
	if kind == "" {
		return
	}
	switch {
	case err != nil || unknown:
		c.Keyed.Done(user, OutcomeUnknown)
	case r.status >= 200 && r.status < 300:
		c.Keyed.Done(user, OutcomeStored)
	default:
		if e := decodeError(r); e != nil && e.KeyFinal {
			c.Keyed.Done(user, OutcomeStored)
		} else {
			c.Keyed.Done(user, OutcomeNotStored)
		}
	}
}

func decodeError(r reply) *APIError {
	var e APIError
	if json.Unmarshal(r.data, &e) != nil || e.Code == "" {
		return nil
	}
	e.HTTP = r.status
	if r.header != nil {
		if s, err := strconv.Atoi(r.header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = s
		}
	}
	return &e
}

func errorFrom(method, path string, r reply) error {
	if e := decodeError(r); e != nil {
		return e
	}
	return fmt.Errorf("%s %s%s: HTTP %d: %s", method, APIPrefix, path, r.status, truncate(r.data, 200))
}

func decodeInto(method, path string, r reply, out any) error {
	if r.status < 200 || r.status >= 300 {
		return errorFrom(method, path, r)
	}
	if out != nil && len(r.data) > 0 {
		if err := json.Unmarshal(r.data, out); err != nil {
			return fmt.Errorf("decode %s %s%s: %w", method, APIPrefix, path, err)
		}
	}
	return nil
}

// isCoreReject: an error body that carries the core's reason for a refused
// command (a business answer, not a transport or gateway failure).
func isCoreReject(e *APIError) bool {
	if e == nil || e.ReasonName() == "" {
		return false
	}
	switch e.HTTP {
	case 404, 409, 422, 429, 503:
		return true
	}
	return false
}

// CreateOrder is POST /orders under a fresh Idempotency-Key. A core reject
// is not a Go error: it comes back as Accepted=false with the core's reason
// name, so callers treat it as a governor signal. 201 = accepted, status
// PENDING_NEW; the matching engine's decision arrives later on the stream.
// 200 duplicate:true is a resend the core had already decided.
func (c *Client) CreateOrder(ctx context.Context, req CreateOrderRequest) (*CreateOrderResponse, error) {
	const path = "/orders"
	r, err := c.send(ctx, KeyedCreate, http.MethodPost, path, req.UserID, req)
	if err != nil {
		return nil, err
	}
	if r.status >= 200 && r.status < 300 {
		var out CreateOrderResponse
		if err := json.Unmarshal(r.data, &out); err != nil || out.OrderID == "" {
			return nil, fmt.Errorf("POST %s%s: HTTP %d: undecodable body %s", APIPrefix, path, r.status, truncate(r.data, 200))
		}
		out.Accepted, out.HTTP = true, r.status
		return &out, nil
	}
	if e := decodeError(r); isCoreReject(e) {
		return &CreateOrderResponse{Accepted: false, RejectReason: e.ReasonName(), KeyFinal: e.KeyFinal, HTTP: r.status}, nil
	}
	return nil, errorFrom(http.MethodPost, path, r)
}

// CancelOrder is DELETE /orders/{orderId}; keyed when KeyedCancels is set.
// An order that is no longer open comes back as an error IsGone accepts;
// 200 with reoffered:true (status NOT_OPEN) is a success.
func (c *Client) CancelOrder(ctx context.Context, userID int64, orderID string) error {
	path := "/orders/" + orderID
	kind := KeyedKind("")
	if c.KeyedCancels {
		kind = KeyedCancel
	}
	r, err := c.send(ctx, kind, http.MethodDelete, path, userID, nil)
	if err != nil {
		return err
	}
	return decodeInto(http.MethodDelete, path, r, nil)
}

// AmendOrder is PUT /orders/{orderId} {price?, quantity?} (quantity is the
// new total) under a fresh Idempotency-Key; nil keeps the value.
func (c *Client) AmendOrder(ctx context.Context, userID int64, orderID string, price, quantity *Money) (*AmendResponse, error) {
	path := "/orders/" + orderID
	body := map[string]*Money{}
	if price != nil {
		body["price"] = price
	}
	if quantity != nil {
		body["quantity"] = quantity
	}
	r, err := c.send(ctx, KeyedAmend, http.MethodPut, path, userID, body)
	if err != nil {
		return nil, err
	}
	var out AmendResponse
	if err := decodeInto(http.MethodPut, path, r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrder is GET /orders/{orderId}: an open order from the core, a closed
// one from history (503 HISTORY_UNAVAILABLE when the gateway has none).
func (c *Client) GetOrder(ctx context.Context, userID int64, orderID string) (*OrderResponse, error) {
	path := "/orders/" + orderID
	r, err := c.read(ctx, path, userID)
	if err != nil {
		return nil, err
	}
	var out OrderResponse
	if err := decodeInto(http.MethodGet, path, r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActiveOrders is GET /orders: the principal's open orders (every market).
func (c *Client) ActiveOrders(ctx context.Context, userID int64) ([]OrderResponse, error) {
	const path = "/orders"
	r, err := c.read(ctx, path, userID)
	if err != nil {
		return nil, err
	}
	var out openOrders
	if err := decodeInto(http.MethodGet, path, r, &out); err != nil {
		return nil, err
	}
	return out.Orders, nil
}

// GetAccount is GET /balances for userID (every asset, zero included).
func (c *Client) GetAccount(ctx context.Context, userID int64) (*Account, error) {
	const path = "/balances"
	r, err := c.read(ctx, path, userID)
	if err != nil {
		return nil, err
	}
	out := Account{UserID: userID}
	if err := decodeInto(http.MethodGet, path, r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Deposit is POST /balances/deposit {assetId, amount} for the user's own
// account under a fresh Idempotency-Key. The gateway serves it only with
// its treasury lane on (404 FEATURE_DISABLED otherwise) and refuses an
// amount above its per-request faucet cap with 422.
func (c *Client) Deposit(ctx context.Context, userID int64, assetID int, amount Money) (*DepositResponse, error) {
	d, _, err := c.DepositKeyed(ctx, userID, assetID, amount, nil)
	return d, err
}

// DepositKeyed is Deposit that can resend an earlier attempt: prev nil sends
// under a fresh key, prev non-nil resends prev's key with the same assetId
// and amount (ErrWindowPassed or ErrWindowUnknown when that is not safe).
// When the outcome stays unknown (transport failure, 504) the returned
// attempt is non-nil: the deposit may have been applied, so the caller
// resends it with that attempt rather than reading the balance and funding
// the shortfall under a new key.
func (c *Client) DepositKeyed(ctx context.Context, userID int64, assetID int, amount Money, prev *KeyedAttempt) (*DepositResponse, *KeyedAttempt, error) {
	const path = "/balances/deposit"
	body := struct {
		AssetID ID    `json:"assetId"`
		Amount  Money `json:"amount"`
	}{ID(assetID), amount}
	r, att, unknown, err := c.sendAttempt(ctx, KeyedDeposit, http.MethodPost, path, userID, body, prev)
	if unknown {
		if err == nil {
			err = errorFrom(http.MethodPost, path, r)
		}
		return nil, &att, err
	}
	if err != nil {
		return nil, nil, err
	}
	var out DepositResponse
	if err := decodeInto(http.MethodPost, path, r, &out); err != nil {
		return nil, nil, err
	}
	return &out, nil, nil
}

// Markets is the public GET /markets (the core config: tick, lot, band).
func (c *Client) Markets(ctx context.Context) ([]MarketInfo, error) {
	const path = "/markets"
	r, err := c.read(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	var out marketsBody
	if err := decodeInto(http.MethodGet, path, r, &out); err != nil {
		return nil, err
	}
	return out.Markets, nil
}

// Status is the public GET /status; it records idempotencyWindowMs.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	const path = "/status"
	r, err := c.read(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	var out Status
	if err := decodeInto(http.MethodGet, path, r, &out); err != nil {
		return nil, err
	}
	if out.IdempotencyWindowMs != nil && *out.IdempotencyWindowMs > 0 {
		c.SetIdempotencyWindow(time.Duration(*out.IdempotencyWindowMs) * time.Millisecond)
	}
	return &out, nil
}

// Health reads /status and fails unless the gateway reports ready (a
// registered session, a loaded config and an open global gate).
func (c *Client) Health(ctx context.Context) error {
	s, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if !s.Ready {
		return errors.New("gateway /status: ready false")
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
