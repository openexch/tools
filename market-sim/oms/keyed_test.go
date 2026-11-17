package oms

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time      { return f.t }
func (f *fakeClock) add(d time.Duration) { f.t = f.t.Add(d) }
func newFakeCounter(w time.Duration) (*KeyedCounter, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	return newKeyedCounter(w, 4, clk.now), clk
}

func TestKeyedSlidingPeakPerUser(t *testing.T) {
	k, clk := newFakeCounter(10 * time.Second)
	// user 1 sends at 0s, 1s, 2s, 10s and 11s. A send leaves the window once
	// it is a full window old, so the most inside any 10s span is 3.
	for _, at := range []time.Duration{0, time.Second, 2 * time.Second} {
		clk.t = time.Unix(1_000_000, 0).Add(at)
		k.Sent(1, KeyedCreate)
	}
	clk.t = time.Unix(1_000_000, 0).Add(10 * time.Second)
	k.Sent(1, KeyedCreate) // window (0s,10s]: 1s, 2s, 10s
	clk.t = time.Unix(1_000_000, 0).Add(11 * time.Second)
	k.Sent(1, KeyedCancel) // (1s,11s]: 2s, 10s, 11s
	k.Sent(2, KeyedDeposit)
	s := k.Snapshot()
	u1 := s.Users["1"]
	if u1.Sent != 5 || u1.PeakInWindow != 3 || u1.InWindow != 3 || u1.ByKind[KeyedCreate] != 4 || u1.ByKind[KeyedCancel] != 1 {
		t.Fatalf("user 1 %+v", u1)
	}
	if s.PeakInWindow != 3 || s.PeakUser != 1 || s.WindowMs != 10000 {
		t.Fatalf("snapshot peak %d user %d window %d", s.PeakInWindow, s.PeakUser, s.WindowMs)
	}
	clk.add(30 * time.Second)
	if u := k.Snapshot().Users["1"]; u.InWindow != 0 || u.PeakInWindow != 3 {
		t.Fatalf("after the window: %+v", u)
	}
}

func TestKeyedTumblingWindows(t *testing.T) {
	k, clk := newFakeCounter(10 * time.Second)
	for i := 0; i < 5; i++ {
		k.Sent(1, KeyedCreate)
	}
	k.Sent(2, KeyedCreate)
	clk.add(10 * time.Second) // closes window 1
	k.Sent(2, KeyedCreate)
	clk.add(25 * time.Second) // closes window 2 and an empty window 3
	s := k.Snapshot()
	if len(s.Windows) != 3 {
		t.Fatalf("%d windows: %+v", len(s.Windows), s.Windows)
	}
	w := s.Windows[0]
	if w.Users != 2 || w.Total != 6 || w.PerUserMax != 5 || w.MaxUser != 1 || w.PerUserP50 != 1 || w.PerUserP99 != 5 {
		t.Fatalf("window 1 %+v", w)
	}
	if s.Windows[1].Total != 1 || s.Windows[1].MaxUser != 2 || s.Windows[2].Users != 0 {
		t.Fatalf("windows %+v", s.Windows)
	}
	for i := 0; i < 10; i++ { // keep = 4
		clk.add(10 * time.Second)
		k.Sent(3, KeyedAmend)
	}
	if n := len(k.Snapshot().Windows); n != 4 {
		t.Fatalf("kept %d windows, want 4", n)
	}
}

func TestKeyedOutcomesAndFile(t *testing.T) {
	k, _ := newFakeCounter(time.Minute)
	k.Sent(9, KeyedCreate)
	k.Retry(9)
	k.Done(9, OutcomeStored)
	k.Sent(9, KeyedCreate)
	k.Done(9, OutcomeNotStored)
	k.Sent(9, KeyedCreate)
	k.Done(9, OutcomeUnknown)
	s := k.Snapshot()
	u := s.Users["9"]
	if u.Sent != 3 || u.Retries != 1 || u.Stored != 1 || u.NotStored != 1 || u.Unknown != 1 || u.StoredPeakWindow != 1 {
		t.Fatalf("%+v", u)
	}
	p := filepath.Join(t.TempDir(), "keyed.json")
	if err := s.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var back KeyedSnapshot
	if err := json.Unmarshal(b, &back); err != nil || back.Users["9"].Sent != 3 || back.WindowMs != 60000 {
		t.Fatalf("file %s: %v", b, err)
	}
	if line := s.Line(); line == "" {
		t.Fatal("empty line")
	}
	var nilCounter *KeyedCounter
	nilCounter.Sent(1, KeyedCreate) // a client without a counter
}
