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
		{Id: 4, Uuid: "u4"},
	}, map[int]int{})
	defer DeleteLimiter("egress")

	type want struct {
		tag     string
		matched bool
	}
	check := func(cases map[string]want) {
		t.Helper()
		for email, w := range cases {
			if tag, matched := lim.MatchEgress(email); tag != w.tag || matched != w.matched {
				t.Fatalf("%s: got (%q, %v) want (%q, %v)", email, tag, matched, w.tag, w.matched)
			}
		}
	}

	e := &panel.UserEgress{
		Outbounds: []panel.EgressOutbound{
			{Id: 7, Outbound: "bind:1.2.3.4"},
			{Id: 8, Outbound: "IPv4_out"},
			{Id: 9, Outbound: "bad://x"},
		},
		Users: map[string]int{"1": 7, "2": 8, "3": 9},
	}
	lim.SetUserEgress("egress", e)
	check(map[string]want{
		"egress|u1": {"egress|egress|7", true},
		"egress|u2": {"IPv4_out", true},
		"egress|u3": {"", true},
		"egress|u4": {"", false},
		"egress|u5": {"", false},
	})

	e.Strict = true
	lim.SetUserEgress("egress", e)
	check(map[string]want{
		"egress|u1": {"egress|egress|7", true},
		"egress|u4": {"", true},
	})

	lim.SetUserEgress("egress", &panel.UserEgress{Strict: true})
	check(map[string]want{"egress|u1": {"", true}})

	lim.SetUserEgress("egress", nil)
	check(map[string]want{"egress|u1": {"", false}})
}
