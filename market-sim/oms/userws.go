package oms

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// UserWS follows one bot user's order events over the gateway user stream
// (oe-stream, `/ws/v2`). The credential is a header (X-API-Key, or the dev
// bearer), never a query string; the subscribe frame names channels only,
// never a user. Each `order` frame's order is delivered on Out with
// drop-on-full semantics (the agents' reconcile pass covers drops). The last
// eventSeq of any frame is kept and offered as resume on reconnect.
type UserWS struct {
	url    string
	creds  Credentials
	userID int64
	Out    chan OrderResponse

	// Reconnect is the wait between sessions (0 = 3s); ReadIdle the read
	// deadline (0 = 90s, the stream sends heartbeats well inside it).
	Reconnect time.Duration
	ReadIdle  time.Duration

	lastSeq int64
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewUserWS builds a follower. wsURL example: ws://127.0.0.1:8081/ws/v2.
func NewUserWS(wsURL string, creds Credentials, userID int64, buf int) *UserWS {
	if buf <= 0 {
		buf = 128
	}
	return &UserWS{url: wsURL, creds: creds, userID: userID, Out: make(chan OrderResponse, buf), lastSeq: -1}
}

func (u *UserWS) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.run(ctx)
	}()
}

func (u *UserWS) Stop() {
	if u.cancel != nil {
		u.cancel()
	}
	u.wg.Wait()
	close(u.Out) // no sender remains; lets range-consumers exit
}

func (u *UserWS) run(ctx context.Context) {
	wait := u.Reconnect
	if wait <= 0 {
		wait = 3 * time.Second
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := u.session(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[userws %d] session: %v, reconnecting in %s", u.userID, err, wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// streamFrame is the union of the server frames this follower reads.
type streamFrame struct {
	Type     string         `json:"type"`
	EventSeq *int64         `json:"eventSeq"`
	Order    *OrderResponse `json:"order"`
	Code     string         `json:"code"`
	Reason   string         `json:"reason"`
	Error    string         `json:"error"`
	AsOf     *struct {
		EventSeq int64 `json:"eventSeq"`
	} `json:"asOf"`
}

// subscribeFrame is the client's subscribe; resume only after a first frame.
func (u *UserWS) subscribeFrame() []byte {
	sub := map[string]any{"op": "subscribe", "channels": []string{"orders"}}
	if u.lastSeq >= 0 {
		sub["resume"] = map[string]int64{"eventSeq": u.lastSeq}
	}
	b, _ := json.Marshal(sub)
	return b
}

// handle applies one server frame; it returns the order to deliver, if any.
// Only live `order` frames are delivered to the agents. The rows of an
// orders snapshot (on subscribe and after a resync) only move the resume
// position: after a resync an agent learns its open orders from its
// periodic reconcile read (GET /orders), not from the snapshot.
func (u *UserWS) handle(data []byte) (OrderResponse, bool) {
	var f streamFrame
	if json.Unmarshal(data, &f) != nil {
		return OrderResponse{}, false
	}
	if f.EventSeq != nil {
		u.lastSeq = *f.EventSeq
	} else if f.Type == "snapshot" && f.AsOf != nil {
		u.lastSeq = f.AsOf.EventSeq
	}
	switch f.Type {
	case "order":
		if f.Order != nil && f.Order.OrderID != "" {
			o := *f.Order
			o.UserID = u.userID
			return o, true
		}
	case "resync":
		log.Printf("[userws %d] resync %s: open orders re-sent as a snapshot; reconcile covers the gap", u.userID, f.Reason)
	case "error":
		log.Printf("[userws %d] stream error %s: %s", u.userID, f.Code, f.Error)
	}
	return OrderResponse{}, false
}

func (u *UserWS) session(ctx context.Context) error {
	hdr := http.Header{}
	if err := u.creds.Apply(hdr, u.userID); err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, _, err := websocket.DefaultDialer.DialContext(dialCtx, u.url, hdr)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := conn.WriteMessage(websocket.TextMessage, u.subscribeFrame()); err != nil {
		return err
	}
	idle := u.ReadIdle
	if idle <= 0 {
		idle = 90 * time.Second
	}
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		_, data, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		o, ok := u.handle(data)
		if !ok {
			continue
		}
		select {
		case u.Out <- o:
		default: // slow consumer: reconcile covers what we drop
		}
	}
}
