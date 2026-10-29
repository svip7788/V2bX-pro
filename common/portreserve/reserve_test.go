package portreserve

import "testing"

func TestContains(t *testing.T) {
	cases := []struct {
		list string
		port int
		want bool
	}{
		{"", 50444, false},
		{"50443-50446", 50444, true},
		{"50443-50446", 50447, false},
		{"22,8080,50443-50446", 8080, true},
		{"22, 50444", 50444, true},
		{"bad,50444", 50444, true},
	}
	for _, c := range cases {
		if got := contains(c.list, c.port); got != c.want {
			t.Errorf("contains(%q, %d) = %v, want %v", c.list, c.port, got, c.want)
		}
	}
}
