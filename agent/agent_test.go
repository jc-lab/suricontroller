package agent

import "testing"

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{
		{"7.0.3", "8.0.5", true},
		{"8.0.4", "8.0.5", true},
		{"8.0.5", "8.0.5", false},
		{"8.0.10", "8.0.5", false},
		{"8.1.0-dev", "8.0.5", false},
		{"9.0.0", "8.0.5", false},
	} {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
