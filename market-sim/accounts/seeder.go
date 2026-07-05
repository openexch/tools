// Package accounts owns the bot population's funding. Seeding is idempotent:
// it deposits only the shortfall between the bot's current TOTAL balance
// (available+locked) and the configured float, so re-running on every boot
// is a no-op while balances persist (Redis/Postgres) and a full re-fund
// after a wipe.
package accounts

import (
	"context"
	"fmt"
	"log"

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
}

// Seed brings every bot to its target float. Returns the number of deposits
// made (0 = everything already funded).
func (s *Seeder) Seed(ctx context.Context, targets []Target) (int, error) {
	floor := s.TopUpFloorPct
	if floor <= 0 {
		floor = 90
	}
	deposits := 0
	for _, t := range targets {
		acct, err := s.Client.GetAccount(ctx, t.UserID)
		if err != nil {
			return deposits, fmt.Errorf("get account %d: %w", t.UserID, err)
		}
		totals := map[int]oms.Money{}
		for _, a := range acct.Assets {
			totals[a.AssetID] = a.Total
		}
		n, err := s.topUp(ctx, t.UserID, usdAssetID, totals[usdAssetID], t.USD, floor)
		if err != nil {
			return deposits, err
		}
		deposits += n
		if t.BaseAsset != 0 && t.BaseFloat > 0 {
			n, err := s.topUp(ctx, t.UserID, t.BaseAsset, totals[t.BaseAsset], t.BaseFloat, floor)
			if err != nil {
				return deposits, err
			}
			deposits += n
		}
	}
	return deposits, nil
}

func (s *Seeder) topUp(ctx context.Context, userID int64, assetID int, have, want oms.Money, floorPct int) (int, error) {
	if want <= 0 || have >= want*oms.Money(floorPct)/100 {
		return 0, nil
	}
	shortfall := want - have
	if err := s.Client.Deposit(ctx, userID, assetID, shortfall); err != nil {
		return 0, fmt.Errorf("deposit asset %d to %d: %w", assetID, userID, err)
	}
	log.Printf("[accounts] bot %d: deposited %s of asset %d (had %s, target %s)",
		userID, shortfall, assetID, have, want)
	return 1, nil
}
