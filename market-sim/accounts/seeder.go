// Package accounts owns the bot population's funding. Seeding is idempotent:
// it deposits only the shortfall between the bot's current TOTAL balance
// (available+locked) and the configured float, so re-running on every boot
// is a no-op while balances persist and a full re-fund after a wipe.
//
// Funding goes through the gateway's demo faucet (POST /api/v2/balances/
// deposit, the treasury lane), each bot crediting its own account with its
// own API key. Every deposit is a keyed money command and takes one entry of
// the user's request cap.
package accounts

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/openexch/tools/market-sim/oms"
)

const usdAssetID = 0

// Target is one bot's funding goal.
type Target struct {
	UserID    int64
	USD       oms.Money
	BaseAsset int       // asset id of the market's base (0 = none)
	BaseFloat oms.Money // target base-asset float
}

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

// Seed brings every bot to its target float. Returns the number of deposit
// requests made (0 = everything already funded).
func (s *Seeder) Seed(ctx context.Context, targets []Target) (int, error) {
	floor := s.TopUpFloorPct
	if floor <= 0 {
		floor = 90
	}
	deposits := 0
	var blocked error
	for _, t := range targets {
		assets := []struct {
			id   int
			want oms.Money
		}{{usdAssetID, t.USD}}
		if t.BaseAsset != 0 && t.BaseFloat > 0 {
			assets = append(assets, struct {
				id   int
				want oms.Money
			}{t.BaseAsset, t.BaseFloat})
		}
		// Settle the unknown deposits first: the balance read below is only
		// a safe basis for a shortfall once none of them can still land.
		open := map[int]bool{}
		for _, a := range assets {
			if s.settle(ctx, t.UserID, a.id) {
				open[a.id] = true
			}
		}
		if ctx.Err() != nil {
			return deposits, ctx.Err()
		}
		acct, err := s.Client.GetAccount(ctx, t.UserID)
		if err != nil {
			return deposits, fmt.Errorf("get account %d: %w", t.UserID, err)
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
			n, err := s.topUp(ctx, t.UserID, a.id, totals[a.id], a.want, floor)
			deposits += n
			if err != nil {
				return deposits, err
			}
		}
	}
	return deposits, blocked
}

// settle resends the user's pending deposits of assetID under their own
// keys. It reports whether one is still pending (its outcome still unknown,
// or the resend refused by the gateway before the core decided it).
func (s *Seeder) settle(ctx context.Context, userID int64, assetID int) bool {
	k := userAsset{userID, assetID}
	s.mu.Lock()
	list := s.pending[k]
	delete(s.pending, k)
	s.mu.Unlock()
	var keep []pendingDeposit
	for _, p := range list {
		att := p.attempt
		_, again, err := s.Client.DepositKeyed(ctx, userID, assetID, p.amount, &att)
		switch {
		case err == nil:
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d settled by its resend", userID, p.amount, assetID)
		case errors.Is(err, oms.ErrWindowPassed):
			// decided long ago: the balance read shows whether it applied
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d is past its window; the balance decides", userID, p.amount, assetID)
		case again != nil || !decidedNot(err):
			log.Printf("[accounts] bot %d: deposit %s of asset %d still unknown: %v", userID, p.amount, assetID, err)
			keep = append(keep, p)
		default:
			log.Printf("[accounts] bot %d: unknown deposit %s of asset %d decided: %v", userID, p.amount, assetID, err)
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

func (s *Seeder) topUp(ctx context.Context, userID int64, assetID int, have, want oms.Money, floorPct int) (int, error) {
	if want <= 0 || have >= want*oms.Money(floorPct)/100 {
		return 0, nil
	}
	shortfall := want - have
	chunks := Chunks(shortfall, s.FaucetMax[assetID])
	for i, amount := range chunks {
		if _, att, err := s.Client.DepositKeyed(ctx, userID, assetID, amount, nil); err != nil {
			if att != nil {
				s.remember(userAsset{userID, assetID}, pendingDeposit{amount: amount, attempt: *att})
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
