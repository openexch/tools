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

// UserWS follows one user's order updates over the OMS WebSocket
// (`/ws/v1` on :8080; one userId per connection server-side). Each status
// transition arrives as a bare OrderResponse frame; events are delivered on
// Out with drop-on-full semantics. Auth rides both the Authorization header
// and the browser-style ["bearer", <token>] subprotocol offer.
type UserWS struct {
	url    string
	token  string
	userID int64
	Out    chan OrderResponse

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewUserWS builds a follower for one bot. wsURL example: ws://127.0.0.1:8080/ws.
func NewUserWS(wsURL, token string, userID int64, buf int) *UserWS {
	if buf <= 0 {
		buf = 128
	}
	return &UserWS{url: wsURL, token: token, userID: userID, Out: make(chan OrderResponse, buf)}
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := u.session(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[userws %d] session: %v, reconnecting in 3s", u.userID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (u *UserWS) session(ctx context.Context) error {
	hdr := http.Header{"Authorization": []string{"Bearer " + u.token}}
	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{"bearer", u.token}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, _, err := dialer.DialContext(dialCtx, u.url, hdr)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()

	sub, _ := json.Marshal(map[string]any{
		"op": "subscribe", "channels": []string{"orders"}, "userId": u.userID,
	})
	if err := conn.WriteMessage(websocket.TextMessage, sub); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		// Frames are either the SUBSCRIBED ack / errors ({"type":...}) or a
		// bare OrderResponse; order frames are the ones with an omsOrderId.
		var o OrderResponse
		if json.Unmarshal(data, &o) != nil || o.OmsOrderID == "" {
			continue
		}
		select {
		case u.Out <- o:
		default: // slow consumer: reconcile covers what we drop
		}
	}
}
