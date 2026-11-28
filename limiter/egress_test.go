package limiter

import (
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
)

func TestUserEgress(t *testing.T) {
	Init()
	lim := AddLimiter("egress", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1"},
		{Id: 2, Uuid: "u2"},
		{Id: 3, Uuid: "u3"},
	}, map[int]int{})
	defer DeleteLimiter("egress")

	lim.SetUserEgress("egress", &panel.UserEgress{
		Outbounds: []panel.EgressOutbound{
			{Id: 7, Outbound: "bind:1.2.3.4"},
			{Id: 8, Outbound: "IPv4_out"},
			{Id: 9, Outbound: "bad://x"},
		},
		Users: map[string]int{"1": 7, "2": 8, "3": 9},
	})
	for email, want := range map[string]string{
		"egress|u1": "egress|egress|7",
		"egress|u2": "IPv4_out",
		"egress|u3": "",
		"egress|u4": "",
	} {
		if got := lim.MatchEgress(email); got != want {
			t.Fatalf("%s: got %q want %q", email, got, want)
		}
	}

	lim.SetUserEgress("egress", nil)
	if got := lim.MatchEgress("egress|u1"); got != "" {
		t.Fatalf("cleared egress still matched %q", got)
	}
}
