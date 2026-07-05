package dist

import (
	"math"
	"testing"
)

func TestParetoQuantityHeavyTail(t *testing.T) {
	const n = 100_000
	minQty := 0.001
	small, whale := 0, 0
	for i := 0; i < n; i++ {
		q := ParetoQuantity(minQty, 1.5)
		if q < minQty {
			t.Fatalf("quantity %v below floor %v", q, minQty)
		}
		if q < 5*minQty {
			small++
		}
		// The u >= 0.001 clamp caps the tail at exactly 100x minQty.
		if q > 100*minQty {
			t.Fatalf("quantity %v above the clamped tail cap", q)
		}
		if q > 50*minQty {
			whale++
		}
	}
	if float64(small)/n < 0.5 {
		t.Errorf("expected most orders small, got %d/%d", small, n)
	}
	if whale == 0 {
		t.Error("expected occasional whale orders, got none")
	}
}

func TestExponentialLevelClustersNearSpread(t *testing.T) {
	const n = 100_000
	within5 := 0
	for i := 0; i < n; i++ {
		l := ExponentialLevel(0.3)
		if l < 1 {
			t.Fatalf("level %d < 1", l)
		}
		if l <= 5 {
			within5++
		}
	}
	frac := float64(within5) / n
	if frac < 0.6 || frac > 0.9 {
		t.Errorf("expected ~70%% within 5 levels, got %.1f%%", frac*100)
	}
}

func TestImbalanceSkewCountersImbalance(t *testing.T) {
	if s := ImbalanceSkew(1.0, 0.2); s >= 0 {
		t.Errorf("bid-heavy book should skew toward asks, got %v", s)
	}
	if s := ImbalanceSkew(-1.0, 0.2); s <= 0 {
		t.Errorf("ask-heavy book should skew toward bids, got %v", s)
	}
}

func TestBurstProbabilityCapped(t *testing.T) {
	if p := BurstProbability(0.5, 1000, 1); p != 1.0 {
		t.Errorf("burst probability must cap at 1.0, got %v", p)
	}
}

func TestHawkesIntensityDecays(t *testing.T) {
	base := HawkesIntensity(10, 2, 0, 0.5)
	excited := HawkesIntensity(10, 2, 5, 0.5)
	if base != 10 {
		t.Errorf("no events should give base rate, got %v", base)
	}
	if excited <= base {
		t.Errorf("recent events should raise intensity: %v <= %v", excited, base)
	}
	if math.IsInf(excited, 1) || excited > 100 {
		t.Errorf("intensity should stay bounded, got %v", excited)
	}
}

func TestClampQuantity(t *testing.T) {
	if q := ClampQuantity(0.0001, 0.001, 1); q != 0.001 {
		t.Errorf("clamp low: %v", q)
	}
	if q := ClampQuantity(5, 0.001, 1); q != 1.0 {
		t.Errorf("clamp high: %v", q)
	}
}
