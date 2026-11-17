package oms

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestUserWSFrames(t *testing.T) {
	u := NewUserWS("ws://x/ws/v2", DevAuth{}, 900001, 4)
	if f := string(u.subscribeFrame()); f != `{"channels":["orders"],"op":"subscribe"}` {
		t.Fatalf("first subscribe %s", f)
	}
	if _, ok := u.handle([]byte(`{"type":"snapshot","channel":"orders","asOf":{"eventSeq":10},"orders":[]}`)); ok || u.lastSeq != 10 {
		t.Fatalf("snapshot: seq %d", u.lastSeq)
	}
	o, ok := u.handle([]byte(`{"type":"order","eventSeq":12,"event":"FILL","order":{"orderId":"5","marketId":"1","status":"FILLED","filledQuantity":"1.00000000"}}`))
	if !ok || o.OrderID != "5" || o.Status != "FILLED" || o.UserID != 900001 || o.MarketID != 1 || u.lastSeq != 12 {
		t.Fatalf("order %+v seq %d", o, u.lastSeq)
	}
	if _, ok := u.handle([]byte(`{"type":"heartbeat","eventSeq":15}`)); ok || u.lastSeq != 15 {
		t.Fatalf("heartbeat seq %d", u.lastSeq)
	}
	if _, ok := u.handle([]byte(`{"type":"fill","eventSeq":16,"fill":{"tradeId":"1"}}`)); ok {
		t.Fatal("a fill frame is not an order")
	}
	var sub map[string]any
	json.Unmarshal(u.subscribeFrame(), &sub)
	if r, _ := sub["resume"].(map[string]any); r == nil || r["eventSeq"] != float64(16) {
		t.Fatalf("resubscribe %v", sub)
	}
	if _, has := sub["userId"]; has {
		t.Fatal("a userId in a frame closes the connection")
	}
}

func TestUserWSHeaderCredentialNoQuery(t *testing.T) {
	got := make(chan *http.Request, 1)
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		c.ReadMessage() // subscribe
		c.WriteMessage(websocket.TextMessage, []byte(`{"type":"subscribed","channels":["orders"]}`))
		c.WriteMessage(websocket.TextMessage, []byte(`{"type":"order","eventSeq":1,"event":"ACK_NEW","order":{"orderId":"9","marketId":"2","status":"NEW"}}`))
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	u := NewUserWS("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/v2", testKeys(t), 900001, 4)
	u.Start()
	defer u.Stop()
	select {
	case o := <-u.Out:
		if o.OrderID != "9" || o.UserID != 900001 {
			t.Fatalf("order %+v", o)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no order frame delivered")
	}
	r := <-got
	if r.URL.RawQuery != "" || r.URL.Path != "/ws/v2" || r.Header.Get("X-API-Key") != testKey {
		t.Fatalf("dial %s?%s key %q", r.URL.Path, r.URL.RawQuery, r.Header.Get("X-API-Key"))
	}
}
