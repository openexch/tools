package accounts

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openexch/tools/market-sim/oms"
)

func TestChunks(t *testing.T) {
	m := oms.MustMoney
	for _, c := range []struct {
		amount, max oms.Money
		want        []oms.Money
	}{
		{m("10"), 0, []oms.Money{m("10")}},
		{m("10"), m("20"), []oms.Money{m("10")}},
		{m("10"), m("4"), []oms.Money{m("4"), m("4"), m("2")}},
		{m("8"), m("4"), []oms.Money{m("4"), m("4")}},
		{0, m("4"), nil},
	} {
		got := Chunks(c.amount, c.max)
		if len(got) != len(c.want) {
			t.Fatalf("Chunks(%s,%s) = %v", c.amount, c.max, got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("Chunks(%s,%s) = %v", c.amount, c.max, got)
			}
		}
	}
}

// fakeFaucet is a gateway with one user and one asset. A deposit whose
// reply is held back (the 504 case) is applied only when release is called,
// as a command still in flight inside the core would be.
type fakeFaucet struct {
	mu       sync.Mutex
	balance  oms.Money
	applied  map[string]bool // keys the core decided
	inFlight map[string]oms.Money
	keys     []string
	answer   []int // per deposit request: 200 or 504 (last one repeats)
}

func (f *fakeFaucet) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, a := range f.inFlight {
		f.balance += a
		f.applied[k] = true
	}
	f.inFlight = map[string]oms.Money{}
}

func (f *fakeFaucet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/api/v2/balances":
		fmt.Fprintf(w, `{"asOf":{"logPosition":1},"assets":[{"assetId":"0","asset":"USD","available":"%s","locked":"0","total":"%s"}]}`, f.balance, f.balance)
	case "/api/v2/balances/deposit":
		var body struct{ Amount oms.Money }
		json.NewDecoder(r.Body).Decode(&body)
		key := r.Header.Get("Idempotency-Key")
		f.keys = append(f.keys, key)
		code := f.answer[len(f.answer)-1]
		if n := len(f.keys) - 1; n < len(f.answer) {
			code = f.answer[n]
		}
		if f.applied[key] {
			fmt.Fprintf(w, `{"assetId":"0","amount":"%s","available":"%s","duplicate":true}`, body.Amount, f.balance)
			return
		}
		if code == 504 {
			if _, ok := f.inFlight[key]; !ok {
				f.inFlight[key] = body.Amount
			}
			w.WriteHeader(504)
			fmt.Fprint(w, `{"error":"the core did not answer in time","code":"OUTCOME_UNKNOWN","reason":null,"detail":null,"keyFinal":false}`)
			return
		}
		delete(f.inFlight, key)
		f.balance += body.Amount
		f.applied[key] = true
		fmt.Fprintf(w, `{"assetId":"0","amount":"%s","available":"%s","duplicate":false}`, body.Amount, f.balance)
	default:
		w.WriteHeader(404)
	}
}

func faucetClient(t *testing.T, f *fakeFaucet) *oms.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	keys, err := oms.ParseAPIKeys(bufio.NewScanner(strings.NewReader("k-900001-abcdefghijklmnop:900001\n")), "test")
	if err != nil {
		t.Fatal(err)
	}
	c := oms.NewClient(srv.URL, keys)
	c.Retry = oms.RetryPolicy{Attempts: 1, MaxElapsed: time.Minute}
	return c
}

// An unknown deposit that lands after the pass that sent it must not be
// funded a second time: the next pass resends it under its own key and the
// balance read that follows shows it applied.
func TestSeedResendsUnknownDepositWithItsKey(t *testing.T) {
	f := &fakeFaucet{applied: map[string]bool{}, inFlight: map[string]oms.Money{}, answer: []int{504, 200}}
	s := &Seeder{Client: faucetClient(t, f)}
	target := []Target{{UserID: 900001, USD: oms.MustMoney("1000")}}
	ctx := context.Background()

	if _, err := s.Seed(ctx, target); err == nil {
		t.Fatal("pass 1: a 504 deposit must fail the pass")
	}
	f.release() // the first deposit lands after its 504, before pass 2 reads
	n, err := s.Seed(ctx, target)
	if err != nil || n != 0 {
		t.Fatalf("pass 2: n=%d err=%v, want no new deposit", n, err)
	}
	if f.balance != oms.MustMoney("1000") {
		t.Fatalf("balance %s, want 1000 (funded once)", f.balance)
	}
	if len(f.keys) != 2 || f.keys[0] != f.keys[1] {
		t.Fatalf("deposit keys %v, want the first key resent once", f.keys)
	}
}

// While the resend stays unknown, the asset is not funded under a new key.
func TestSeedHoldsAssetWhileDepositUnknown(t *testing.T) {
	f := &fakeFaucet{applied: map[string]bool{}, inFlight: map[string]oms.Money{}, answer: []int{504}}
	s := &Seeder{Client: faucetClient(t, f)}
	target := []Target{{UserID: 900001, USD: oms.MustMoney("1000")}}
	ctx := context.Background()
	for pass := 1; pass <= 3; pass++ {
		if _, err := s.Seed(ctx, target); err == nil {
			t.Fatalf("pass %d: want an error while the deposit is unknown", pass)
		}
	}
	for _, k := range f.keys {
		if k != f.keys[0] {
			t.Fatalf("a new key was used while a deposit was unknown: %v", f.keys)
		}
	}
	if pass2 := len(f.keys); pass2 != 3 {
		t.Fatalf("deposit requests %d, want 3 (one send, two resends)", pass2)
	}
	f.release()
	f.answer = []int{200}
	if n, err := s.Seed(ctx, target); err != nil || n != 0 || f.balance != oms.MustMoney("1000") {
		t.Fatalf("after release: n=%d err=%v balance %s", n, err, f.balance)
	}
}

// Past the window the key is not resent; the balance read decides.
func TestSeedDropsPendingPastWindow(t *testing.T) {
	f := &fakeFaucet{applied: map[string]bool{}, inFlight: map[string]oms.Money{}, answer: []int{504, 200}}
	c := faucetClient(t, f)
	c.Retry.MaxElapsed = time.Nanosecond
	s := &Seeder{Client: c}
	target := []Target{{UserID: 900001, USD: oms.MustMoney("1000")}}
	ctx := context.Background()
	if _, err := s.Seed(ctx, target); err == nil {
		t.Fatal("pass 1 must fail")
	}
	f.release()
	time.Sleep(time.Millisecond)
	n, err := s.Seed(ctx, target)
	if err != nil || n != 0 || len(f.keys) != 1 || f.balance != oms.MustMoney("1000") {
		t.Fatalf("n=%d err=%v keys=%v balance %s", n, err, f.keys, f.balance)
	}
}
