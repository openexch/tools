package feed

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeService serves the viewer protocol for one market: after the subscribe
// it sends the scripted frames and then records the client's later actions.
type fakeService struct {
	srv     *httptest.Server
	actions chan string
}

func newFakeService(t *testing.T, frames func(t *testing.T) [][]byte) *fakeService {
	t.Helper()
	fs := &fakeService{actions: make(chan string, 16)}
	up := websocket.Upgrader{}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		fs.actions <- string(msg)
		for _, f := range frames(t) {
			if err := c.WriteMessage(websocket.TextMessage, f); err != nil {
				return
			}
		}
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			fs.actions <- string(msg)
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fakeService) url() string { return "ws" + strings.TrimPrefix(fs.srv.URL, "http") }

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func TestClientFollowsSnapshotAndDeltaChain(t *testing.T) {
	fs := newFakeService(t, func(t *testing.T) [][]byte {
		return [][]byte{golden(t, "subscription_confirmed"), golden(t, "book_snapshot_base"), golden(t, "book_delta_80"), golden(t, "trades_batch_flush")}
	})
	c := NewClient(fs.url(), []int{3})
	var versions []int64
	c.OnFrameVersion = func(_ int, v int64) { versions = append(versions, v) }
	c.Start()
	defer c.Stop()
	var sub map[string]any
	if err := json.Unmarshal([]byte(<-fs.actions), &sub); err != nil || sub["action"] != "subscribe" || sub["marketId"] != float64(3) {
		t.Fatalf("first action: %v %v", sub, err)
	}
	waitFor(t, "last trade", func() bool { return c.View(3).LastTrade == 15003 })
	v := c.View(3)
	if v.BookVersion != 2199023255632 || v.Stale || v.Problem != "" || len(v.Bids) == 0 || len(v.Asks) == 0 {
		t.Fatalf("view: version %d stale %v problem %q bids %d asks %d", v.BookVersion, v.Stale, v.Problem, len(v.Bids), len(v.Asks))
	}
	if len(versions) != 1 || versions[0] != 2199023255632 {
		t.Fatalf("frame versions: %v", versions)
	}
	if v.LastMsgAt.IsZero() {
		t.Fatal("no last message time")
	}
}

func TestClientAsksRefreshOnChainBreak(t *testing.T) {
	// The delta continues from version ...553; this snapshot is version 777.
	fs := newFakeService(t, func(t *testing.T) [][]byte {
		return [][]byte{golden(t, "book_snapshot_empty"), golden(t, "book_delta_80")}
	})
	c := NewClient(fs.url(), []int{3})
	c.Start()
	defer c.Stop()
	<-fs.actions // subscribe
	select {
	case a := <-fs.actions:
		if !strings.Contains(a, `"refresh"`) {
			t.Fatalf("second action %s", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no refresh requested")
	}
	if v := c.View(3); len(v.Bids) != 0 || v.BookVersion != 777 {
		t.Fatalf("a broken chain must not change the book: %d bids, version %d", len(v.Bids), v.BookVersion)
	}
}

func TestClientStaleSnapshotIsNotLiveness(t *testing.T) {
	fs := newFakeService(t, func(t *testing.T) [][]byte { return [][]byte{golden(t, "book_snapshot_no_snapshot")} })
	c := NewClient(fs.url(), []int{3})
	c.Start()
	defer c.Stop()
	<-fs.actions
	time.Sleep(200 * time.Millisecond)
	v := c.View(3)
	if !v.Stale || !v.LastMsgAt.IsZero() {
		t.Fatalf("stale %v last message %v", v.Stale, v.LastMsgAt)
	}
}

func TestClientUndecodableFrameNamesTheProblem(t *testing.T) {
	fs := newFakeService(t, func(t *testing.T) [][]byte {
		return [][]byte{replaceOnce(t, golden(t, "book_snapshot_base"), `"price":"13.99"`, `"price":13.99`)}
	})
	c := NewClient(fs.url(), []int{3})
	c.Start()
	defer c.Stop()
	<-fs.actions
	waitFor(t, "problem", func() bool { return c.View(3).Problem != "" })
	v := c.View(3)
	if !strings.Contains(v.Problem, "simulator cannot decode BOOK_SNAPSHOT") || !v.LastMsgAt.IsZero() || len(v.Bids) != 0 {
		t.Fatalf("problem %q last %v bids %d", v.Problem, v.LastMsgAt, len(v.Bids))
	}
}

func TestClientIgnoresOtherMarketAndErrorIsNotLiveness(t *testing.T) {
	fs := newFakeService(t, func(t *testing.T) [][]byte {
		return [][]byte{replaceOnce(t, golden(t, "book_snapshot_base"), `"marketId":3`, `"marketId":4`), golden(t, "error_history_unavailable")}
	})
	c := NewClient(fs.url(), []int{3})
	c.Start()
	defer c.Stop()
	<-fs.actions
	waitFor(t, "error text", func() bool { return strings.HasPrefix(c.View(3).Problem, "HISTORY_UNAVAILABLE") })
	if v := c.View(3); !v.LastMsgAt.IsZero() || len(v.Bids) != 0 {
		t.Fatalf("last %v bids %d", v.LastMsgAt, len(v.Bids))
	}
}
