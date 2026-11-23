package accounts

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openexch/tools/market-sim/oms"
)

// rateFaucet is a gateway with many users and one asset (USD), with the
// gateway's per-user faucet bucket: one deposit per interval, burst one. A
// deposit inside the interval is refused 429 RATE_LIMITED before the core.
type rateFaucet struct {
	interval time.Duration
	delay    time.Duration // service time of a deposit, so overlap is visible

	mu       sync.Mutex
	balance  map[int64]oms.Money
	applied  map[string]bool
	held     map[string]heldDeposit // answered 504, applied on release
	lastTake map[int64]time.Time
	sends    map[int64][]faucetSend
	active   map[int64]int
	inFlight int
	maxIn    int
	overlap  bool
	refused  int
	// per user: how many of the next deposit requests to refuse (429 no
	// core reason), refuse as a stored core RATE_LIMIT, or answer 504
	refuseNext map[int64]int
	coreRefuse map[int64]bool
	unknownN   map[int64]int
}

type faucetSend struct {
	key    string
	amount oms.Money
	at     time.Time
	code   int
}

type heldDeposit struct {
	user   int64
	amount oms.Money
}

func newRateFaucet(interval, delay time.Duration) *rateFaucet {
	return &rateFaucet{
		interval: interval, delay: delay,
		balance: map[int64]oms.Money{}, applied: map[string]bool{}, held: map[string]heldDeposit{},
		lastTake: map[int64]time.Time{}, sends: map[int64][]faucetSend{}, active: map[int64]int{},
		refuseNext: map[int64]int{}, coreRefuse: map[int64]bool{}, unknownN: map[int64]int{},
	}
}

func (f *rateFaucet) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, h := range f.held {
		f.balance[h.user] += h.amount
		f.applied[k] = true
	}
	f.held = map[string]heldDeposit{}
}

func userOf(r *http.Request) int64 {
	k := strings.Split(r.Header.Get("X-API-Key"), "-") // k-<user>-<secret>
	if len(k) < 2 {
		return 0
	}
	u, _ := strconv.ParseInt(k[1], 10, 64)
	return u
}

func (f *rateFaucet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user := userOf(r)
	switch r.URL.Path {
	case "/api/v2/balances":
		f.mu.Lock()
		b := f.balance[user]
		f.mu.Unlock()
		fmt.Fprintf(w, `{"asOf":{"logPosition":1},"assets":[{"assetId":"0","asset":"USD","available":"%s","locked":"0","total":"%s"}]}`, b, b)
	case "/api/v2/balances/deposit":
		var body struct{ Amount oms.Money }
		json.NewDecoder(r.Body).Decode(&body)
		key := r.Header.Get("Idempotency-Key")
		now := time.Now()

		f.mu.Lock()
		f.active[user]++
		if f.active[user] > 1 {
			f.overlap = true
		}
		f.inFlight++
		if f.inFlight > f.maxIn {
			f.maxIn = f.inFlight
		}
		f.mu.Unlock()
		time.Sleep(f.delay)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.active[user]--
		f.inFlight--

		code := 200
		switch {
		case f.refuseNext[user] > 0:
			f.refuseNext[user]--
			code = 429
		case f.coreRefuse[user]:
			code = 4290
		case !f.lastTake[user].IsZero() && now.Sub(f.lastTake[user]) < f.interval:
			code = 429
		}
		if code == 200 {
			f.lastTake[user] = now
			if f.unknownN[user] > 0 {
				f.unknownN[user]--
				code = 504
			}
		}
		f.sends[user] = append(f.sends[user], faucetSend{key: key, amount: body.Amount, at: now, code: code})
		switch code {
		case 429:
			f.refused++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"too many requests","code":"RATE_LIMITED","reason":null,"detail":"the faucet rate is spent","keyFinal":false}`)
			return
		case 4290:
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":"too many requests","code":"RATE_LIMITED","reason":"RATE_LIMIT","detail":null,"keyFinal":true}`)
			return
		}
		if f.applied[key] {
			fmt.Fprintf(w, `{"assetId":"0","amount":"%s","available":"%s","duplicate":true}`, body.Amount, f.balance[user])
			return
		}
		if code == 504 {
			if _, ok := f.held[key]; !ok {
				f.held[key] = heldDeposit{user, body.Amount}
			}
			w.WriteHeader(504)
			fmt.Fprint(w, `{"error":"the core did not answer in time","code":"OUTCOME_UNKNOWN","reason":null,"detail":null,"keyFinal":false}`)
			return
		}
		if _, ok := f.held[key]; ok {
			delete(f.held, key)
		}
		f.balance[user] += body.Amount
		f.applied[key] = true
		fmt.Fprintf(w, `{"assetId":"0","amount":"%s","available":"%s","duplicate":false}`, body.Amount, f.balance[user])
	default:
		w.WriteHeader(404)
	}
}

func (f *rateFaucet) okSends() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, list := range f.sends {
		for _, s := range list {
			if s.code == 200 {
				n++
			}
		}
	}
	return n
}

const firstUser = 900001

func manyClient(t *testing.T, f http.Handler, users int) *oms.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var b strings.Builder
	for i := 0; i < users; i++ {
		u := firstUser + i
		fmt.Fprintf(&b, "k-%d-abcdefghijklmnop:%d\n", u, u)
	}
	keys, err := oms.ParseAPIKeys(bufio.NewScanner(strings.NewReader(b.String())), "test")
	if err != nil {
		t.Fatal(err)
	}
	c := oms.NewClient(srv.URL, keys)
	c.Retry = oms.RetryPolicy{Attempts: 1, MaxElapsed: time.Minute}
	return c
}

func usdTargets(users int, usd string) []Target {
	out := make([]Target, users)
	for i := range out {
		out[i] = Target{UserID: int64(firstUser + i), USD: oms.MustMoney(usd)}
	}
	return out
}

// At most Workers users are funded at once, one user's deposits never
// overlap, come in chunk order and are spaced by the faucet interval, and the
// returned count is every deposit made.
func TestSeedBoundsConcurrencyAndPacesEachUser(t *testing.T) {
	const users, workers = 24, 4
	interval := 10 * time.Millisecond
	f := newRateFaucet(interval, 3*time.Millisecond)
	s := &Seeder{Client: manyClient(t, f, users), FaucetMax: map[int]oms.Money{0: oms.MustMoney("1000")},
		Workers: workers, FaucetInterval: interval}
	n, err := s.Seed(context.Background(), usdTargets(users, "2500"))
	if err != nil {
		t.Fatal(err)
	}
	if n != users*3 || f.okSends() != n {
		t.Fatalf("n=%d deposits applied %d, want %d", n, f.okSends(), users*3)
	}
	if f.maxIn > workers || f.maxIn < 2 {
		t.Fatalf("at most %d deposits in flight, want 2..%d", f.maxIn, workers)
	}
	if f.overlap || f.refused != 0 {
		t.Fatalf("overlap=%v refused=%d: one user's deposits must be sequential and paced", f.overlap, f.refused)
	}
	for u, list := range f.sends {
		want := []string{"1000", "1000", "500"}
		for i, sd := range list {
			if sd.amount != oms.MustMoney(want[i]) {
				t.Fatalf("user %d deposit %d is %s, want %s", u, i, sd.amount, want[i])
			}
			if i > 0 && sd.at.Sub(list[i-1].at) < interval {
				t.Fatalf("user %d deposits %d and %d are %s apart, under %s", u, i-1, i, sd.at.Sub(list[i-1].at), interval)
			}
		}
		if f.balance[u] != oms.MustMoney("2500") {
			t.Fatalf("user %d balance %s", u, f.balance[u])
		}
	}
	// funded: a second pass sends nothing
	if n, err := s.Seed(context.Background(), usdTargets(users, "2500")); err != nil || n != 0 {
		t.Fatalf("second pass n=%d err=%v", n, err)
	}
}

// The default population shape (51 users of 100 deposits each against a
// per-user rate limit) takes about one user's time, not the sum.
func TestSeedWallTimeIsPerUserNotTheSum(t *testing.T) {
	const users, perUser = 51, 100
	interval := 5 * time.Millisecond
	f := newRateFaucet(interval, 0)
	s := &Seeder{Client: manyClient(t, f, users), FaucetMax: map[int]oms.Money{0: oms.MustMoney("10000")},
		Workers: 64, FaucetInterval: interval}
	start := time.Now()
	n, err := s.Seed(context.Background(), usdTargets(users, "1000000"))
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if n != users*perUser || f.refused != 0 {
		t.Fatalf("n=%d refused=%d, want %d deposits and no 429", n, f.refused, users*perUser)
	}
	perUserMin := time.Duration(perUser-1) * interval
	sum := time.Duration(users) * perUserMin
	t.Logf("%d users x %d deposits took %s (one user at least %s, sequential at least %s)", users, perUser, took, perUserMin, sum)
	if took < perUserMin || took > sum/4 {
		t.Fatalf("took %s, want between %s and %s", took, perUserMin, sum/4)
	}
}

// A gateway rate refusal (429 without a core reason) is resent under the
// same key after the back-off; the user is funded exactly once.
func TestSeedRateRefusalResendsTheSameKey(t *testing.T) {
	f := newRateFaucet(time.Millisecond, 0)
	f.refuseNext[firstUser] = 2
	s := &Seeder{Client: manyClient(t, f, 3), Workers: 3, FaucetInterval: time.Millisecond}
	n, err := s.Seed(context.Background(), usdTargets(3, "1000"))
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	list := f.sends[firstUser]
	if len(list) != 3 || list[0].key != list[1].key || list[1].key != list[2].key {
		t.Fatalf("sends %+v, want one key sent three times", list)
	}
	if list[0].code != 429 || list[1].code != 429 || list[2].code != 200 {
		t.Fatalf("codes %d %d %d", list[0].code, list[1].code, list[2].code)
	}
	if f.balance[firstUser] != oms.MustMoney("1000") {
		t.Fatalf("balance %s, want 1000 (funded once)", f.balance[firstUser])
	}
}

// A stored core RATE_LIMIT is a decision: it is not resent, the pass fails.
func TestSeedCoreRateLimitIsNotResent(t *testing.T) {
	f := newRateFaucet(time.Millisecond, 0)
	f.coreRefuse[firstUser] = true
	s := &Seeder{Client: manyClient(t, f, 1), FaucetInterval: time.Millisecond}
	if _, err := s.Seed(context.Background(), usdTargets(1, "1000")); err == nil {
		t.Fatal("want the core reject to fail the pass")
	}
	if len(f.sends[firstUser]) != 1 {
		t.Fatalf("%d sends, want 1", len(f.sends[firstUser]))
	}
}

// Under concurrency an unknown deposit is still resent under its own key
// before the balance is read, no other key funds that user's asset while it
// is unknown, and the other users are funded exactly once.
func TestSeedUnknownDepositUnderConcurrency(t *testing.T) {
	const users = 20
	unknownUser := int64(firstUser + 7)
	f := newRateFaucet(time.Millisecond, time.Millisecond)
	f.unknownN[unknownUser] = 3 // the send and its first two resends stay unknown
	s := &Seeder{Client: manyClient(t, f, users), FaucetMax: map[int]oms.Money{0: oms.MustMoney("1000")},
		Workers: 6, FaucetInterval: time.Millisecond}
	targets := usdTargets(users, "3000")
	ctx := context.Background()

	total := 0
	for pass := 1; pass <= 2; pass++ {
		n, err := s.Seed(ctx, targets)
		total += n
		if err == nil {
			t.Fatalf("pass %d: want an error while the deposit is unknown", pass)
		}
	}
	// pass 3: the resend stays unknown once more; the asset is held, every
	// other user is funded
	n, err := s.Seed(ctx, targets)
	total += n
	if !errors.Is(err, ErrDepositPending) {
		t.Fatalf("pass 3: err %v, want ErrDepositPending", err)
	}
	f.mu.Lock()
	first := f.sends[unknownUser][0].key
	for _, sd := range f.sends[unknownUser] {
		if sd.key != first {
			f.mu.Unlock()
			t.Fatalf("a new key funded user %d while a deposit was unknown: %+v", unknownUser, f.sends[unknownUser])
		}
	}
	f.mu.Unlock()

	f.release() // the unknown deposit lands
	n, err = s.Seed(ctx, targets)
	total += n
	if err != nil {
		t.Fatalf("pass 4: %v", err)
	}
	for i := 0; i < users; i++ {
		u := int64(firstUser + i)
		if f.balance[u] != oms.MustMoney("3000") {
			t.Fatalf("user %d balance %s, want 3000 (funded once)", u, f.balance[u])
		}
	}
	// every 200 is a first application or a duplicate resend; count the
	// applied deposits: 3 per user, the held one included
	applied := len(f.applied)
	if applied != users*3 {
		t.Fatalf("applied keys %d, want %d", applied, users*3)
	}
	// the returned counts are the new-key deposits: all but the user's
	// unknown first send that pass 1 counted as not made
	if total != users*3-1 {
		t.Fatalf("deposits counted %d, want %d", total, users*3-1)
	}
}
