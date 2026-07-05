package oms

import "testing"

func TestParseMoneyRoundTrip(t *testing.T) {
	cases := map[string]string{
		"110224.00000000": "110224.00000000",
		"0.1":             "0.10000000",
		"101997":          "101997.00000000",
		"0.10000001":      "0.10000001",
		"0":               "0.00000000",
		".5":              "0.50000000",
		"-3.25":           "-3.25000000", // signed positions
	}
	for in, want := range cases {
		m, err := ParseMoney(in)
		if err != nil {
			t.Fatalf("ParseMoney(%q): %v", in, err)
		}
		if got := m.String(); got != want {
			t.Errorf("ParseMoney(%q).String() = %q, want %q", in, got, want)
		}
	}
}

func TestParseMoneyRejects(t *testing.T) {
	for _, in := range []string{"", "1e5", "0.123456789", "abc", "1.2.3", "1,5"} {
		if _, err := ParseMoney(in); err == nil {
			t.Errorf("ParseMoney(%q) succeeded, want error", in)
		}
	}
}

func TestRoundToTick(t *testing.T) {
	cases := []struct{ price, tick, want string }{
		{"100123.49", "1", "100123.00000000"},
		{"100123.50", "1", "100124.00000000"},
		{"2001.26", "0.5", "2001.50000000"},
		{"0.12344", "0.0001", "0.12340000"},
		{"0.12345", "0.0001", "0.12350000"}, // ties round up
	}
	for _, c := range cases {
		got := MustMoney(c.price).RoundToTick(MustMoney(c.tick)).String()
		if got != c.want {
			t.Errorf("RoundToTick(%s, %s) = %s, want %s", c.price, c.tick, got, c.want)
		}
	}
}

func TestMoneyJSON(t *testing.T) {
	m := MustMoney("42.5")
	b, err := m.MarshalJSON()
	if err != nil || string(b) != `"42.50000000"` {
		t.Fatalf("MarshalJSON = %s, %v", b, err)
	}
	var back Money
	if err := back.UnmarshalJSON([]byte(`"0.00000001"`)); err != nil || back != 1 {
		t.Fatalf("UnmarshalJSON = %d, %v", back, err)
	}
}
