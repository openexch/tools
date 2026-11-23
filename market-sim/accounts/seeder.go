// Package accounts owns the bot population's funding. Seeding is idempotent:
// it deposits only the shortfall between the bot's current TOTAL balance
// (available+locked) and the configured float, so re-running on every boot
// is a no-op while balances persist and a full re-fund after a wipe.
//
// Funding goes through the gateway's demo faucet (POST /api/v2/balances/
// deposit, the treasury lane), each bot crediting its own account with its
// own API key. Every deposit is a keyed money command and takes one entry of
// the user's request cap and one token of the user's faucet bucket
// (GATEWAY_FAUCET_RATE, 1/s by default, burst one period's count).
//
// The faucet bucket is per user and the gateway has no faucet limit across
// users, so users are funded in parallel by a bounded pool of workers. One
// user's deposits stay sequential and are spaced by FaucetInterval, so they
// do not run into the bucket's 429.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/openexch/tools/market-sim/oms"
)

const usdAssetID = 0

// DefaultWorkers is the number of users funded at once when Seeder.Workers is
// 0. The gateway's faucet bucket is per user, so this bounds only the load on
// the gateway and the core: 16 users at one deposit a second each is 16
// money commands a second, far inside the gateway's in-flight and
// per-principal limits.
const DefaultWorkers = 16

// DefaultFaucetInterval is the spacing of one user's deposits when
// Seeder.FaucetInterval is 0: the gateway's default GATEWAY_FAUCET_RATE 1/s.
const DefaultFaucetInterval = time.Second

// maxRefusals bounds the resends of one deposit that the gateway refused for
// its rate before the core saw it (429 RATE_LIMITED without a core reason).
const maxRefusals = 20

// Target is one bot's funding goal.
type Target struct {
	UserID    int64
	USD       oms.Money
	BaseAsset int       // asset id of the market's base (0 = none)
	BaseFloat oms.Money // target base-asset float
}

// Seeder funds bots. Seed may be called again on the same Seeder (the
// whole-pass retry does), but not concurrently with itself.
type Seeder struct {
	Client *oms.Client
	// TopUpFloorPct: deposit only when total < this % of target (default 90).
	// Small drift from trading is normal and must not trigger deposits, or
	// the sim would mask insolvency bugs.
	TopUpFloorPct int
	// FaucetMax is the per-request amount cap per asset id, the gateway's
	// GATEWAY_FAUCET_MAX_AMOUNT. A shortfall above it is sent as several
	// deposits of at most the cap. An asset without an entry is sent whole.
	FaucetMax map[int]oms.Money
	// Workers is the number of users funded at once (0 = DefaultWorkers).
	Workers int
	// FaucetInterval is the least time between the end of one deposit
	// request of a user and the start of the next one of the same user: the
	// period of the gateway's GATEWAY_FAUCET_RATE (0 = DefaultFaucetInterval,
	// negative = no spacing).
	FaucetInterval time.Duration

	// pending holds the deposits whose outcome stayed unknown (transport
	// failure, 504), per user and asset. A balance read cannot tell an
	// unknown deposit that is still in flight from one that was never
	// applied, so a pending deposit is resent under its own key first, and
	// the asset's shortfall is computed only once nothing is pending.
	mu      sync.Mutex
	pending map[userAsset][]pendingDeposit
}

type userAsset struct {
	user  int64
	asset int
}

type pendingDeposit struct {
	amount  oms.Money
	attempt oms.KeyedAttempt
}

// ErrDepositPending: an asset was left unfunded in this pass because an
// earlier deposit of it is still unknown. The next pass resends it.
var ErrDepositPending = errors.New("a deposit with an unknown outcome is pending")

type assetGoal struct {
	id   int
	want oms.Money
}

func (t Target) goals() []assetGoal {
	g := []assetGoal{{usdAssetID, t.USD}}
	if t.BaseAsset != 0 && t.BaseFloat > 0 {
		g = append(g, assetGoal{t.BaseAsset, t.BaseFloat})
	}
	return g
}

// Seed brings every bot to its target float. Returns the number of deposit
// requests made (0 = everything already funded).
//
// Up to Workers users are funded at once, each by one worker from its first
// read to its last deposit. A failure stops handing out further users; the
// users already started finish their own deposits (cancelling them would
// turn deposits in flight into unknown outcomes), and the first failure is
// returned. The caller retries the whole pass.
func (s *Seeder) Seed(ctx context.Context, targets []Target) (int, error) {
	floor := s.TopUpFloorPct
	if floor <= 0 {
		floor = 90
	}
	workers := s.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	var (
		mu       sync.Mutex
		deposits int
		failed   error
		blocked  error
	)
	work := make(chan Target)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				n, b, err := s.seedOne(ctx, t, floor)
				mu.Lock()
				deposits += n
				if err != nil && failed == nil {
					failed = err
				}
				if b != nil && blocked == nil {
					blocked = b
				}
				mu.Unlock()
			}
		}()
	}
dispatch:
	for _, t := range s.longestFirst(targets) {
		mu.Lock()
		stop := failed != nil
		mu.Unlock()
		if stop {
			break
		}
		select {
		case work <- t:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(work)
	wg.Wait()

	switch {
	case failed != nil:
		return deposits, failed
	case ctx.Err() != nil:
		return deposits, ctx.Err()
	}
	return deposits, blocked
}

// longestFirst orders the targets by the number of deposits a full funding
// takes, largest first, so the users that take longest start first and the
// pass ends close to the longest single user.
func (s *Seeder) longestFirst(targets []Target) []Target {
	out := append([]Target(nil), targets...)
	cost := func(t Target) int {
		n := 0
		for _, g := range t.goals() {
			n += len(Chunks(g.want, s.FaucetMax[g.id]))
		}
		return n
	}
	sort.SliceStable(out, func(i, j int) bool { return cost(out[i]) > cost(out[j]) })
	return out
}

// seedOne funds one user. blocked is set when an asset was left unfunded
// because a deposit of it is still unknown; err stops the pass.
func (s *Seeder) seedOne(ctx context.Context, t Target, floor int) (deposits int, blocked, err error) {
	p := s.newPacer()
	assets := t.goals()
	// Settle the unknown deposits first: the balance read below is only
	// a safe basis for a shortfall once none of them can still land.
	open := map[int]bool{}
	for _, a := range assets {
		if s.settle(ctx, p, t.UserID, a.id) {
			open[a.id] = true
		}
	}
	if ctx.Err() != nil {
		return 0, nil, ctx.Err()
	}
	acct, err := s.Client.GetAccount(ctx, t.UserID)
	if err != nil {
		return 0, nil, fmt.Errorf("get account %d: %w", t.UserID, err)
	}
	totals := map[int]oms.Money{}
	for _, a := range acct.Assets {
		totals[int(a.AssetID)] = a.Total
	}
	for _, a := range assets {
		if open[a.id] {
			blocked = fmt.Errorf("bot %d asset %d: %w", t.UserID, a.id, ErrDepositPending)
			continue
		}
		n, err := s.topUp(ctx, p, t.UserID, a.id, totals[a.id], a.want, floor)
		deposits += n
		if err != nil {
			return deposits, blocked, err
		}
	}
	return deposits, blocked, nil
}

// pacer spaces one user's deposit requests: the next one starts no earlier
// than its interval after the previous one ended. Measured from the end of
// the previous request, the gap at the gateway (which takes the token when
// the request arrives) is never shorter than the interval.
type pacer struct {
	interval time.Duration
	next     time.Time
}

func (s *Seeder) newPacer() *pacer {
	d := s.FaucetInterval
	if d == 0 {
		d = DefaultFaucetInterval
	}
	return &pacer{interval: d}
}

func (p *pacer) wait(ctx context.Context) error {
	d := time.Until(p.next)
	if d <= 0 {
		return ctx.Err()
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

// sent records the end of a request; atLeast is a longer wait the gateway
// asked for (Retry-After).
func (p *pacer) sent(atLeast time.Duration) {
	d := p.interval
	if atLeast > d {
		d = atLeast
	}
	if d > 0 {
		p.next = time.Now().Add(d)
	}
}

// rateRefused: the gateway refused the request for the user's rate before
// the core saw it (429 RATE_LIMITED, no core reason, not final). Nothing was
// applied, so the same key may be resent after the Retry-After.
func rateRefused(err error) (bool, time.Duration) {
	var e *oms.APIError
	if !errors.As(err, &e) || e.HTTP != 429 || e.Code != "RATE_LIMITED" || e.KeyFinal || e.ReasonName() != "" {
		return false, 0
	}
	return true, time.Duration(e.RetryAfter) * time.Second
}

// deposit sends one deposit, paced to the user's faucet rate (prev non-nil:
// a resend of that attempt under its key). A gateway rate refusal is resent
// under the SAME key after its Retry-After, at most maxRefusals times; the
// key is never replaced here. Returns the attempt and whether its outcome
// is unknown.
func (s *Seeder) deposit(ctx context.Context, p *pacer, userID int64, assetID int, amount oms.Money, prev *oms.KeyedAttempt) (oms.KeyedAttempt, bool, error) {
	att := prev
	for refusals := 0; ; refusals++ {
		if err := p.wait(ctx); err != nil {
			// nothing sent in this call: an earlier attempt keeps its state
			if att != nil {
				return *att, prev != nil, err
			}
			return oms.KeyedAttempt{}, false, err
		}
		_, a, unknown, err := s.Client.DepositAttempt(ctx, userID, assetID, amount, att)
		refused, after := rateRefused(err)
		p.sent(after)
		if err == nil || unknown || !refused || refusals >= maxRefusals || ctx.Err() != nil {
			return a, unknown, err
		}
		log.Printf("[accounts] bot %d: deposit of asset %d refused for the faucet rate; resending the same key", userID, assetID)
		att = &a
	}
}

// settle resends the user's pending deposits of assetID under their own
// keys. It reports whether one is still pending (its outcome still unknown,
// or the resend refused by the gateway before the core decided it).
func (s *Seeder) settle(ctx context.Context, p *pacer, userID int64, assetID int) bool {
	k := userAsset{userID, assetID}
	s.mu.Lock()
	list := s.pending[k]
	delete(s.pending, k)
	s.mu.Unlock()
	var keep []pendingDeposit
	for _, d := range list {
		att := d.attempt
		_, unknown, err := s.deposit(ctx, p, userID, assetID, d.amount, &att)
		switch {
		case err == nil:
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d settled by its resend", userID, d.amount, assetID)
		case errors.Is(err, oms.ErrWindowPassed):
			// decided long ago: the balance read shows whether it applied
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d is past its window; the balance decides", userID, d.amount, assetID)
		case unknown || !decidedNot(err):
			log.Printf("[accounts] bot %d: deposit %s of asset %d still unknown: %v", userID, d.amount, assetID, err)
			keep = append(keep, d)
		default:
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d decided: %v", userID, d.amount, assetID, err)
		}
	}
	if len(keep) > 0 {
		s.remember(k, keep...)
	}
	return len(keep) > 0
}

// decidedNot: the resend reached the core and the core decided it (a stored
// reject, or a core reason outside the transient 429 and 503 answers), so the
// key is settled. A gateway-side refusal (no core reason) leaves the first
// send unknown.
func decidedNot(err error) bool {
	var e *oms.APIError
	if !errors.As(err, &e) {
		return false
	}
	if e.KeyFinal {
		return true
	}
	return e.ReasonName() != "" && e.HTTP != 429 && e.HTTP != 503
}

func (s *Seeder) remember(k userAsset, p ...pendingDeposit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[userAsset][]pendingDeposit{}
	}
	s.pending[k] = append(s.pending[k], p...)
}

func (s *Seeder) topUp(ctx context.Context, p *pacer, userID int64, assetID int, have, want oms.Money, floorPct int) (int, error) {
	if want <= 0 || have >= want*oms.Money(floorPct)/100 {
		return 0, nil
	}
	shortfall := want - have
	chunks := Chunks(shortfall, s.FaucetMax[assetID])
	for i, amount := range chunks {
		if att, unknown, err := s.deposit(ctx, p, userID, assetID, amount, nil); err != nil {
			if unknown {
				s.remember(userAsset{userID, assetID}, pendingDeposit{amount: amount, attempt: att})
			}
			return i, fmt.Errorf("deposit %s of asset %d to %d (%d of %d): %w", amount, assetID, userID, i+1, len(chunks), err)
		}
	}
	log.Printf("[accounts] bot %d: deposited %s of asset %d in %d request(s) (had %s, target %s)",
		userID, shortfall, assetID, len(chunks), have, want)
	return len(chunks), nil
}

// Chunks splits amount into parts of at most max (max <= 0: one part).
func Chunks(amount, max oms.Money) []oms.Money {
	if amount <= 0 {
		return nil
	}
	if max <= 0 || amount <= max {
		return []oms.Money{amount}
	}
	var out []oms.Money
	for amount > 0 {
		part := max
		if amount < max {
			part = amount
		}
		out = append(out, part)
		amount -= part
	}
	return out
}
