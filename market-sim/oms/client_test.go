package oms

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "k-900001-abcdefghijklmnop"

func testKeys(t *testing.T) *APIKeys {
	t.Helper()
	k, err := ParseAPIKeys(scannerOf(testKey+":900001\nk-900002-abcdefghijklmnop:900002\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type seen struct {
	Method, Path, Query, Key, APIKey, Auth string
	Body                                   map[string]any
	RawBody                                string
}

// recorder answers each request with the next scripted reply and records it.
type recorder struct {
	mu      sync.Mutex
	reqs    []seen
	replies []func(w http.ResponseWriter)
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	s := seen{Method: req.Method, Path: req.URL.Path, Query: req.URL.RawQuery,
		Key: req.Header.Get("Idempotency-Key"), APIKey: req.Header.Get("X-API-Key"),
		Auth: req.Header.Get("Authorization"), RawBody: string(b)}
	if len(b) > 0 {
		json.Unmarshal(b, &s.Body)
	}
	r.mu.Lock()
	n := len(r.reqs)
	r.reqs = append(r.reqs, s)
	var reply func(w http.ResponseWriter)
	if n < len(r.replies) {
		reply = r.replies[n]
	} else if len(r.replies) > 0 {
		reply = r.replies[len(r.replies)-1]
	}
	r.mu.Unlock()
	if reply == nil {
		w.WriteHeader(500)
		return
	}
	reply(w)
}

func (r *recorder) all() []seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]seen(nil), r.reqs...)
}

func status(code int, body string, hdr ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

const created = `{"orderId":"77","status":"PENDING_NEW","duplicate":false,"marketId":"1","hold":{"assetId":"0","amount":"100.00000000"},"acceptedAt":1,"eventSeq":5}`

func outcomeUnknown() func(w http.ResponseWriter) {
	return status(504, `{"error":"the core did not answer in time","code":"OUTCOME_UNKNOWN","reason":null,"detail":"retry with the same key","keyFinal":false}`)
}

// newTestClient: a client on the recorder with a known window and a fake
// sleep that records the waits.
func newTestClient(t *testing.T, rec *recorder) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, testKeys(t))
	c.SetIdempotencyWindow(60 * time.Second)
	c.Keyed = NewKeyedCounter(time.Minute, 0)
	var waits []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	return c, &waits
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func limitBuy() CreateOrderRequest {
	p := MustMoney("50000")
	return CreateOrderRequest{UserID: 900001, MarketID: 1, Side: "BUY", OrderType: "LIMIT",
		TimeInForce: "GTC", Price: &p, Quantity: MustMoney("0.001")}
}

func TestCreateOrderMapsToV2(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(201, created)}}
	c, _ := newTestClient(t, rec)
	resp, err := c.CreateOrder(context.Background(), limitBuy())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Accepted || resp.OrderID != "77" || resp.Status != "PENDING_NEW" || resp.HTTP != 201 {
		t.Fatalf("resp %+v", resp)
	}
	r := rec.all()[0]
	if r.Method != "POST" || r.Path != "/api/v2/orders" || r.Query != "" {
		t.Fatalf("request %s %s?%s", r.Method, r.Path, r.Query)
	}
	if r.APIKey != testKey || r.Auth != "" {
		t.Fatalf("credential X-API-Key=%q Authorization=%q", r.APIKey, r.Auth)
	}
	if !uuidRE.MatchString(r.Key) {
		t.Fatalf("Idempotency-Key %q is not a v4 UUID", r.Key)
	}
	want := map[string]any{"marketId": "1", "side": "BUY", "type": "LIMIT", "timeInForce": "GTC",
		"price": "50000.00000000", "quantity": "0.00100000"}
	if len(r.Body) != len(want) {
		t.Fatalf("body fields %v, want exactly %v", r.Body, want)
	}
	for k, v := range want {
		if r.Body[k] != v {
			t.Fatalf("body[%s] = %v, want %v (body %s)", k, r.Body[k], v, r.RawBody)
		}
	}
	if strings.Contains(r.RawBody, "userId") || strings.Contains(r.RawBody, "orderType") {
		t.Fatalf("body carries a v1 field: %s", r.RawBody)
	}
}

func TestCreateOrderCoreRejectIsNotAnError(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(422,
		`{"error":"rejected by the core","code":"REJECTED","reason":"INSUFFICIENT_FUNDS","detail":null,"keyFinal":true}`)}}
	c, _ := newTestClient(t, rec)
	resp, err := c.CreateOrder(context.Background(), limitBuy())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Accepted || resp.RejectReason != "INSUFFICIENT_FUNDS" || !resp.KeyFinal {
		t.Fatalf("resp %+v", resp)
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("a keyFinal reject was resent: %d sends", n)
	}
	u := c.Keyed.Snapshot().Users["900001"]
	if u.Sent != 1 || u.Stored != 1 || u.Retries != 0 {
		t.Fatalf("counter %+v", u)
	}
}

func TestCreateOrderGatewayValidationIsAnError(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(400,
		`{"error":"invalid field","code":"VALIDATION","reason":null,"detail":"field 'type' is required","keyFinal":false}`)}}
	c, _ := newTestClient(t, rec)
	_, err := c.CreateOrder(context.Background(), limitBuy())
	e, ok := err.(*APIError)
	if !ok || e.Code != "VALIDATION" || e.HTTP != 400 {
		t.Fatalf("err %v", err)
	}
	if u := c.Keyed.Snapshot().Users["900001"]; u.NotStored != 1 {
		t.Fatalf("counter %+v", u)
	}
}

func TestRetryAfterOutcomeUnknownReusesTheKey(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){outcomeUnknown(), outcomeUnknown(), status(200,
		strings.Replace(created, `"duplicate":false`, `"duplicate":true`, 1))}}
	c, waits := newTestClient(t, rec)
	resp, err := c.CreateOrder(context.Background(), limitBuy())
	if err != nil || !resp.Accepted || !resp.Duplicate {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	reqs := rec.all()
	if len(reqs) != 3 {
		t.Fatalf("%d sends, want 3", len(reqs))
	}
	for _, r := range reqs[1:] {
		if r.Key != reqs[0].Key {
			t.Fatalf("resend used key %q, first send %q", r.Key, reqs[0].Key)
		}
	}
	if len(*waits) != 2 || (*waits)[0] != 200*time.Millisecond || (*waits)[1] != 400*time.Millisecond {
		t.Fatalf("waits %v", *waits)
	}
	u := c.Keyed.Snapshot().Users["900001"]
	if u.Sent != 1 || u.Retries != 2 || u.Stored != 1 || u.ByKind[KeyedCreate] != 1 {
		t.Fatalf("counter %+v", u)
	}
}

func TestRetryAfterClientTimeoutReusesTheKey(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		first := len(keys) == 1
		mu.Unlock()
		if first {
			select { // the client gives up first: an unknown outcome
			case <-release:
			case <-time.After(5 * time.Second):
			}
			return
		}
		w.WriteHeader(200)
		io.WriteString(w, strings.Replace(created, `"duplicate":false`, `"duplicate":true`, 1))
	}))
	defer srv.Close()
	defer close(release)
	c := NewClient(srv.URL, testKeys(t))
	c.HTTP.Timeout = 150 * time.Millisecond
	c.SetIdempotencyWindow(60 * time.Second)
	c.Retry = RetryPolicy{Attempts: 3, Backoff: 10 * time.Millisecond}
	c.Keyed = NewKeyedCounter(time.Minute, 0)
	resp, err := c.CreateOrder(context.Background(), limitBuy())
	if err != nil || !resp.Duplicate {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("keys %q: the resend after a timeout must reuse the key", keys)
	}
}

func TestTwoLogicalRequestsGetTwoKeys(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(201, created)}}
	c, _ := newTestClient(t, rec)
	c.CreateOrder(context.Background(), limitBuy())
	c.CreateOrder(context.Background(), limitBuy())
	r := rec.all()
	if r[0].Key == r[1].Key {
		t.Fatalf("two creates shared key %q", r[0].Key)
	}
	if u := c.Keyed.Snapshot().Users["900001"]; u.Sent != 2 || u.Retries != 0 {
		t.Fatalf("counter %+v", u)
	}
}

func TestNoKeyedResendWithoutAWindow(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){outcomeUnknown(), status(201, created)}}
	c, _ := newTestClient(t, rec)
	c.SetIdempotencyWindow(0)
	_, err := c.CreateOrder(context.Background(), limitBuy())
	if e, ok := err.(*APIError); !ok || e.Code != "OUTCOME_UNKNOWN" {
		t.Fatalf("err %v", err)
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("%d sends: with no idempotency window known a keyed request must not be resent", n)
	}
	if u := c.Keyed.Snapshot().Users["900001"]; u.Unknown != 1 {
		t.Fatalf("counter %+v", u)
	}
}

func TestKeyedResendStopsAtMaxElapsed(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){outcomeUnknown()}}
	c, _ := newTestClient(t, rec)
	now := time.Unix(1000, 0)
	c.clock = func() time.Time { return now }
	c.sleep = func(ctx context.Context, d time.Duration) error { now = now.Add(d); return nil }
	c.Retry = RetryPolicy{Attempts: 100, Backoff: time.Second, MaxBackoff: time.Second, MaxElapsed: 3 * time.Second}
	c.CreateOrder(context.Background(), limitBuy())
	// sends at 0s, 1s, 2s, 3s; the next would start at 4s > 3s
	if n := len(rec.all()); n != 4 {
		t.Fatalf("%d sends, want 4 (resends must start inside MaxElapsed)", n)
	}
}

func TestRateLimitedResendHonoursRetryAfterAndKeyFinal(t *testing.T) {
	bucket := status(429, `{"error":"too many requests","code":"RATE_LIMITED","reason":null,"detail":"budget","keyFinal":false}`, "Retry-After", "2")
	rec := &recorder{replies: []func(http.ResponseWriter){bucket, status(201, created)}}
	c, waits := newTestClient(t, rec)
	if _, err := c.CreateOrder(context.Background(), limitBuy()); err != nil {
		t.Fatal(err)
	}
	if len(*waits) != 1 || (*waits)[0] != 2*time.Second {
		t.Fatalf("waits %v, want [2s] from Retry-After", *waits)
	}
	r := rec.all()
	if len(r) != 2 || r[0].Key != r[1].Key {
		t.Fatalf("sends %d, keys %q %q", len(r), r[0].Key, r[len(r)-1].Key)
	}

	core := status(429, `{"error":"too many requests","code":"RATE_LIMITED","reason":"RATE_LIMIT","detail":null,"keyFinal":true}`, "Retry-After", "1")
	rec2 := &recorder{replies: []func(http.ResponseWriter){core, status(201, created)}}
	c2, _ := newTestClient(t, rec2)
	resp, err := c2.CreateOrder(context.Background(), limitBuy())
	if err != nil || resp.Accepted || resp.RejectReason != "RATE_LIMIT" {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	if n := len(rec2.all()); n != 1 {
		t.Fatalf("a stored core RATE_LIMIT was resent (%d sends)", n)
	}
}

func TestCancelUnkeyedByDefaultKeyedOnRequest(t *testing.T) {
	ok := status(200, `{"orderId":"42","status":"PENDING_CANCEL","duplicate":false}`)
	rec := &recorder{replies: []func(http.ResponseWriter){ok}}
	c, _ := newTestClient(t, rec)
	if err := c.CancelOrder(context.Background(), 900001, "42"); err != nil {
		t.Fatal(err)
	}
	c.KeyedCancels = true
	if err := c.CancelOrder(context.Background(), 900001, "42"); err != nil {
		t.Fatal(err)
	}
	r := rec.all()
	if r[0].Method != "DELETE" || r[0].Path != "/api/v2/orders/42" || r[0].RawBody != "" || r[0].Key != "" {
		t.Fatalf("unkeyed cancel %+v", r[0])
	}
	if !uuidRE.MatchString(r[1].Key) {
		t.Fatalf("keyed cancel key %q", r[1].Key)
	}
	u := c.Keyed.Snapshot().Users["900001"]
	if u.Sent != 1 || u.ByKind[KeyedCancel] != 1 {
		t.Fatalf("only the keyed cancel counts: %+v", u)
	}
}

func TestCancelGoneAnswers(t *testing.T) {
	for _, body := range []struct {
		code int
		body string
		gone bool
	}{
		{404, `{"error":"not found","code":"NOT_FOUND","reason":"UNKNOWN_ORDER","detail":null,"keyFinal":false}`, true},
		{409, `{"error":"conflict","code":"CONFLICT","reason":"NOT_OPEN","detail":null,"keyFinal":false}`, true},
		{409, `{"error":"conflict","code":"CONFLICT","reason":"AMEND_PENDING","detail":null,"keyFinal":false}`, false},
	} {
		rec := &recorder{replies: []func(http.ResponseWriter){status(body.code, body.body)}}
		c, _ := newTestClient(t, rec)
		err := c.CancelOrder(context.Background(), 900001, "42")
		if IsGone(err) != body.gone {
			t.Fatalf("%s: IsGone=%v", body.body, IsGone(err))
		}
	}
}

func TestUnkeyedCancelResentAfterOutcomeUnknown(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){outcomeUnknown(),
		status(200, `{"orderId":"42","status":"NOT_OPEN","duplicate":true,"reoffered":true}`)}}
	c, _ := newTestClient(t, rec)
	if err := c.CancelOrder(context.Background(), 900001, "42"); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.all()); n != 2 {
		t.Fatalf("%d sends", n)
	}
	if len(c.Keyed.Snapshot().Users) != 0 {
		t.Fatal("an unkeyed cancel was counted as keyed")
	}
}

func TestAmendDepositReadsMapToV2(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){
		status(200, `{"orderId":"42","status":"PENDING_REPLACE","duplicate":false}`),
		status(200, `{"assetId":"0","amount":"1000.00000000","available":"1000.00000000","duplicate":false}`),
		status(200, `{"asOf":{"logPosition":9},"assets":[{"assetId":"0","asset":"USD","available":"5.00000000","locked":"1.00000000","total":"6.00000000"},{"assetId":"1","asset":"BTC","available":"0.00000000","locked":"0.00000000","total":"0.00000000"}]}`),
		status(200, `{"asOf":{"logPosition":9},"orders":[{"orderId":"42","clientOrderId":null,"marketId":"1","side":"BUY","type":"LIMIT","timeInForce":"GTC","price":"1.00000000","stopPrice":null,"quantity":"2.00000000","filledQuantity":"0.00000000","remainingQuantity":"2.00000000","status":"NEW","reason":null,"meReason":null,"meOrderId":"7","hold":{"assetId":"0","amount":"2.00000000"},"createdAt":1,"updatedAt":2,"displayQuantity":null,"expiresAt":null,"budget":null}]}`),
		status(200, `{"orderId":"42","clientOrderId":null,"marketId":"1","side":"BUY","type":"LIMIT","timeInForce":"GTC","price":"1.00000000","quantity":"2.00000000","filledQuantity":"2.00000000","remainingQuantity":"0.00000000","status":"FILLED","reason":null}`),
	}}
	c, _ := newTestClient(t, rec)
	ctx := context.Background()
	price := MustMoney("1.5")
	if a, err := c.AmendOrder(ctx, 900001, "42", &price, nil); err != nil || a.Status != "PENDING_REPLACE" {
		t.Fatalf("amend %+v %v", a, err)
	}
	if d, err := c.Deposit(ctx, 900001, 0, MustMoney("1000")); err != nil || d.Amount != MustMoney("1000") {
		t.Fatalf("deposit %+v %v", d, err)
	}
	acct, err := c.GetAccount(ctx, 900001)
	if err != nil || len(acct.Assets) != 2 || acct.Assets[0].AssetID != 0 || acct.Assets[0].Total != MustMoney("6") || acct.Assets[1].AssetID != 1 {
		t.Fatalf("balances %+v %v", acct, err)
	}
	open, err := c.ActiveOrders(ctx, 900001)
	if err != nil || len(open) != 1 || open[0].OrderID != "42" || open[0].MarketID != 1 || open[0].OrderType != "LIMIT" {
		t.Fatalf("open %+v %v", open, err)
	}
	o, err := c.GetOrder(ctx, 900001, "42")
	if err != nil || o.Status != "FILLED" || o.FilledQuantity != MustMoney("2") {
		t.Fatalf("order %+v %v", o, err)
	}
	r := rec.all()
	if r[0].Method != "PUT" || r[0].Path != "/api/v2/orders/42" || len(r[0].Body) != 1 || r[0].Body["price"] != "1.50000000" || !uuidRE.MatchString(r[0].Key) {
		t.Fatalf("amend request %+v", r[0])
	}
	if r[1].Method != "POST" || r[1].Path != "/api/v2/balances/deposit" || r[1].Body["assetId"] != "0" ||
		r[1].Body["amount"] != "1000.00000000" || len(r[1].Body) != 2 || !uuidRE.MatchString(r[1].Key) {
		t.Fatalf("deposit request %+v", r[1])
	}
	for i, want := range []string{"/api/v2/balances", "/api/v2/orders", "/api/v2/orders/42"} {
		got := r[2+i]
		if got.Method != "GET" || got.Path != want || got.Key != "" || got.Query != "" || got.APIKey != testKey {
			t.Fatalf("read %d: %+v, want GET %s", i, got, want)
		}
	}
	u := c.Keyed.Snapshot().Users["900001"]
	if u.Sent != 2 || u.ByKind[KeyedAmend] != 1 || u.ByKind[KeyedDeposit] != 1 {
		t.Fatalf("counter %+v", u)
	}
}

func TestPublicRoutesAndStatusWindow(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){
		status(200, `{"ready":true,"configVersion":3,"behaviorVersion":4,"idempotencyWindowMs":86400000,"admission":[]}`),
		status(200, `{"configVersion":3,"markets":[{"marketId":"1","symbol":"BTC-USD","baseAsset":"BTC","quoteAsset":"USD","baseAssetId":"1","quoteAssetId":"0","tickSize":"1.00000000","lotSize":"0.00000001","minPrice":"1.00000000","maxPrice":"1000000.00000000","minQuantity":"0.00000001","maxQuantity":"100.00000000","minNotional":"0.00000000","maxNotional":"0.00000000"}],"assets":[]}`),
		status(200, `{"ready":false,"configVersion":null,"behaviorVersion":null,"idempotencyWindowMs":null,"admission":[]}`),
	}}
	c, _ := newTestClient(t, rec)
	c.SetIdempotencyWindow(0)
	if err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.IdempotencyWindow() != 24*time.Hour {
		t.Fatalf("window %s", c.IdempotencyWindow())
	}
	m, err := c.Markets(context.Background())
	if err != nil || len(m) != 1 || m[0].MarketID != 1 || m[0].TickSize != MustMoney("1") {
		t.Fatalf("markets %+v %v", m, err)
	}
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("ready:false must fail the health check")
	}
	for _, r := range rec.all() {
		if r.APIKey != "" || r.Auth != "" {
			t.Fatalf("a public route carried a credential: %+v", r)
		}
	}
	if r := rec.all(); r[0].Path != "/api/v2/status" || r[1].Path != "/api/v2/markets" {
		t.Fatalf("paths %s %s", r[0].Path, r[1].Path)
	}
}

func TestDevAuthHeader(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(201, created)}}
	c, _ := newTestClient(t, rec)
	c.Creds = DevAuth{}
	c.CreateOrder(context.Background(), limitBuy())
	r := rec.all()[0]
	if r.Auth != "Bearer dev:900001" || r.APIKey != "" {
		t.Fatalf("dev credential %+v", r)
	}
}

func TestMissingKeyIsRefusedBeforeSending(t *testing.T) {
	rec := &recorder{replies: []func(http.ResponseWriter){status(201, created)}}
	c, _ := newTestClient(t, rec)
	req := limitBuy()
	req.UserID = 123
	if _, err := c.CreateOrder(context.Background(), req); err == nil || !strings.Contains(err.Error(), "no API key for user 123") {
		t.Fatalf("err %v", err)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("%d sends without a credential", n)
	}
}
