package oms

import (
	"fmt"
	"math"
	"strings"
)

// Money is an 8-dp fixed-point amount (scaled int64), mirroring the OMS wire
// contract: every money value crosses the wire as a decimal string with at
// most 8 fractional digits (order-management/docs/API.md).
type Money int64

const MoneyScale = 100_000_000 // 1e8

// ParseMoney parses a wire decimal string ("110224.00000000", "0.1", "101997").
// Rejects exponent notation, signs, and more than 8 fractional digits, same
// as the server-side validation.
func ParseMoney(s string) (Money, error) {
	if s == "" {
		return 0, fmt.Errorf("empty money string")
	}
	neg := false
	if s[0] == '-' {
		// Positions come back signed; order fields never do. Accept and let
		// callers decide.
		neg = true
		s = s[1:]
	}
	intPart, fracPart, _ := strings.Cut(s, ".")
	if intPart == "" && fracPart == "" {
		return 0, fmt.Errorf("malformed money %q", s)
	}
	if intPart == "" {
		intPart = "0"
	}
	if len(fracPart) > 8 {
		return 0, fmt.Errorf("money %q has more than 8 fractional digits", s)
	}
	var v int64
	for _, c := range []byte(intPart) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("malformed money %q", s)
		}
		d := int64(c - '0')
		if v > (math.MaxInt64-d)/10 {
			return 0, fmt.Errorf("money %q out of range", s)
		}
		v = v*10 + d
	}
	if v > math.MaxInt64/MoneyScale {
		return 0, fmt.Errorf("money %q out of range", s)
	}
	v *= MoneyScale
	scale := int64(MoneyScale / 10)
	for _, c := range []byte(fracPart) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("malformed money %q", s)
		}
		v += int64(c-'0') * scale
		scale /= 10
	}
	if neg {
		v = -v
	}
	return Money(v), nil
}

// MustMoney is ParseMoney for constants in config/tests.
func MustMoney(s string) Money {
	m, err := ParseMoney(s)
	if err != nil {
		panic(err)
	}
	return m
}

// MoneyFromFloat rounds a float to the nearest 8-dp fixed-point value. Only
// for internal agent math (anchors, skews); wire values must round-trip
// through Money itself.
func MoneyFromFloat(f float64) Money {
	return Money(math.Round(f * MoneyScale))
}

// String renders the wire form with exactly 8 fractional digits, matching
// server responses.
func (m Money) String() string {
	v := int64(m)
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	return fmt.Sprintf("%s%d.%08d", sign, v/MoneyScale, v%MoneyScale)
}

// Float returns a display-grade float. Never feed it back onto the wire.
func (m Money) Float() float64 {
	return float64(m) / MoneyScale
}

// RoundToTick rounds to the nearest multiple of tick (tick > 0).
func (m Money) RoundToTick(tick Money) Money {
	if tick <= 0 {
		return m
	}
	half := tick / 2
	if m >= 0 {
		return ((m + half) / tick) * tick
	}
	return -(((-m + half) / tick) * tick)
}

// Clamp bounds m to [lo, hi].
func (m Money) Clamp(lo, hi Money) Money {
	if m < lo {
		return lo
	}
	if m > hi {
		return hi
	}
	return m
}

// MarshalJSON emits the wire string form.
func (m Money) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.String() + `"`), nil
}

// UnmarshalJSON accepts the wire string form (and tolerates bare numbers,
// which the API emits only on the deprecated input path but never in
// responses; being liberal here is harmless).
func (m *Money) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "null" {
		*m = 0
		return nil
	}
	v, err := ParseMoney(s)
	if err != nil {
		return err
	}
	*m = v
	return nil
}
