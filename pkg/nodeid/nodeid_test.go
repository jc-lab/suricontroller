package nodeid

import "testing"

func TestValidate(t *testing.T) {
	for _, id := range []string{"router-01", "a", "edge.gw_1", "0abc"} {
		if err := Validate(id); err != nil {
			t.Errorf("%q: unexpected error %v", id, err)
		}
	}
	for _, id := range []string{"", "Router", "-a", ".a", "a/b", "../x", "a..b", "common", "a b", string(make([]byte, 64))} {
		if err := Validate(id); err == nil {
			t.Errorf("%q: expected error", id)
		}
	}
}
