package limiter

import (
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/conf"
)

func TestCheckLimitRejectsExtraCurrentIP(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{})

	taguuid := format.UserTag("tag", "u1")
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("first ip should pass device limit")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); !reject {
		t.Fatal("second ip in same interval should be rejected")
	}
}

func TestMarkOnlineDeviceReportedAllowsSameIPCarryover(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{})

	taguuid := format.UserTag("tag", "u1")
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("first ip should pass device limit")
	}
	lim.MarkOnlineDeviceReported()
	lim.SetAliveList(map[int]int{1: 1})

	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("same ip should reuse reported slot")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); !reject {
		t.Fatal("new ip should still be rejected while alive count is full")
	}
}

func TestBanBitTorrentRejectsUser(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1"},
		{Id: 2, Uuid: "u2"},
	}, map[int]int{})

	banned := format.UserTag("tag", "u1")
	if newly, _ := lim.BanBitTorrent(banned); !newly {
		t.Fatal("first ban should be reported as new")
	}
	if newly, _ := lim.BanBitTorrent(banned); newly {
		t.Fatal("repeated ban within duration should not be reported as new")
	}
	if _, reject := lim.CheckLimit(banned, "1.1.1.1", true, true); !reject {
		t.Fatal("banned user should be rejected")
	}
	if _, reject := lim.CheckLimit(format.UserTag("tag", "u2"), "1.1.1.1", true, true); reject {
		t.Fatal("other users should not be affected")
	}

	lim.btBanned.Store(banned, int64(0))
	if _, reject := lim.CheckLimit(banned, "1.1.1.1", true, true); reject {
		t.Fatal("expired ban should be lifted")
	}
}
