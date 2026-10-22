package phpver

import "testing"

func TestAssess(t *testing.T) {
	cases := []struct {
		in    string
		state State
	}{
		{"8.3.35", StateVulnerable},
		{"8.3.36", StatePatched},
		{"8.4.26", StateVulnerable},
		{"8.4.27", StatePatched},
		{"8.2.34", StateVulnerable},
		{"8.2.35", StatePatched},
		{"8.5.11", StateVulnerable},
		{"8.5.12", StatePatched},
		{"8.1.29", StateEOL},
		{"7.4.33", StateEOL},
		{"8.6.0", StateUnknown},
	}
	for _, c := range cases {
		v, ok := Parse(c.in)
		if !ok {
			t.Fatalf("parse %q failed", c.in)
		}
		got := Assess(v)
		if got.State != c.state {
			t.Errorf("%s: got %s want %s", c.in, got.State, c.state)
		}
	}
}

func TestParseFromBanner(t *testing.T) {
	v, ok := Parse("PHP 8.3.35 (fpm-fcgi) (built: Oct 1 2026 12:00:00)")
	if !ok || v.String() != "8.3.35" {
		t.Fatalf("got %v ok=%v", v, ok)
	}
}
