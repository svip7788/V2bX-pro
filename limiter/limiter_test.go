package limiter

import (
	"testing"
	"time"

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

func TestAliveIPsAllowSameDeviceOnOtherNode(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{1: 1})
	taguuid := format.UserTag("tag", "u1")

	// 只有计数时：全局已满 1 台，本节点不知道是哪个 IP，同一设备也会被拒
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); !reject {
		t.Fatal("count-only alive list cannot tell the same device apart")
	}

	lim.SetAliveIPs(map[int][]string{1: {"1.1.1.1"}}, time.Now())
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("ip already online on another node should pass")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); !reject {
		t.Fatal("new ip should be rejected when global devices are full")
	}
}

func TestAliveIPsUnionCount(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 3},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")

	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("first local ip should pass")
	}
	lim.MarkOnlineDeviceReported()
	// 面板汇总里已含本节点上报的 1.1.1.1，加上别的节点的 2.2.2.2：并集 2 台
	lim.SetAliveIPs(map[int][]string{1: {"1.1.1.1", "2.2.2.2"}}, time.Now())
	if _, reject := lim.CheckLimit(taguuid, "3.3.3.3", true, true); reject {
		t.Fatal("third device should pass, union is 2 of 3")
	}
	if _, reject := lim.CheckLimit(taguuid, "4.4.4.4", true, true); !reject {
		t.Fatal("fourth device should be rejected, union is 3 of 3")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); reject {
		t.Fatal("device online on another node should still pass")
	}
}

func TestAliveIPsOfflineUserAndExpiry(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{1: 1})
	taguuid := format.UserTag("tag", "u1")

	// IP 列表里没有该用户 = 全节点无在线设备，优先于过期的计数
	lim.SetAliveIPs(map[int][]string{}, time.Now())
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("user absent from fresh ip list has no devices online")
	}

	Init()
	lim = AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{1: 1})
	lim.SetAliveIPs(map[int][]string{1: {"1.1.1.1"}}, time.Now().Add(-aliveIPsMaxAge-time.Second))
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); !reject {
		t.Fatal("expired ip list must fall back to count-only check")
	}
}

func TestSpeedShareDividesFixedLimit(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", SpeedLimit: 100},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")
	capacity := func() int64 {
		b, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true)
		if reject || b == nil {
			t.Fatal("user should pass with a bucket")
		}
		return b.Capacity()
	}
	full := int64(100) * 1000000 / 8

	if got := capacity(); got != full {
		t.Fatalf("capacity = %d, want full %d", got, full)
	}
	tightened, err := lim.UpdateSpeedShare("tag", "u1", 3, time.Now().Add(time.Minute))
	if err != nil || !tightened {
		t.Fatalf("split into 3 should tighten, got %v %v", tightened, err)
	}
	if got, want := capacity(), int64(34)*1000000/8; got != want {
		t.Fatalf("capacity = %d, want ceil(100/3) %d", got, want)
	}
	if tightened, _ = lim.UpdateSpeedShare("tag", "u1", 3, time.Now().Add(time.Minute)); tightened {
		t.Fatal("refreshing the same share must not close connections")
	}
	if tightened, _ = lim.UpdateSpeedShare("tag", "u1", 2, time.Now().Add(time.Minute)); tightened {
		t.Fatal("loosening the share must not close connections")
	}

	lim.UpdateSpeedShare("tag", "u1", 2, time.Now().Add(-time.Second))
	if got := capacity(); got != full {
		t.Fatalf("expired share should restore full limit, got %d", got)
	}

	if err := lim.UpdateDynamicSpeedLimit("tag", "u1", 30, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lim.UpdateSpeedShare("tag", "u1", 2, time.Now().Add(time.Minute))
	if got, want := capacity(), int64(30)*1000000/8; got != want {
		t.Fatalf("dynamic limit lower than share should win, got %d want %d", got, want)
	}
}

func TestSpeedShareIgnoresUnlimitedUser(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1"},
	}, map[int]int{})
	if tightened, _ := lim.UpdateSpeedShare("tag", "u1", 2, time.Now().Add(time.Minute)); tightened {
		t.Fatal("user without speed limit is never tightened")
	}
	if b, _ := lim.CheckLimit(format.UserTag("tag", "u1"), "1.1.1.1", true, true); b != nil {
		t.Fatal("user without speed limit should have no bucket")
	}
}

func TestUpdateUserLimitKeepsDynamicAndDevices(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", SpeedLimit: 100, DeviceLimit: 1},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("first ip should pass")
	}
	if err := lim.UpdateDynamicSpeedLimit("tag", "u1", 30, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if got := lim.UpdateUserLimit("tag", []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 50, DeviceLimit: 2}}); len(got) != 0 {
		t.Fatalf("dynamic 30M still wins, nothing tightened, got %v", got)
	}
	if !lim.IsDynamicLimited("tag", "u1") {
		t.Fatal("dynamic limit should survive limit update")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); reject {
		t.Fatal("raised device limit should admit second ip")
	}
	if got := lim.UpdateUserLimit("tag", []panel.UserInfo{{Id: 1, Uuid: "u1", SpeedLimit: 10, DeviceLimit: 2}}); len(got) != 1 {
		t.Fatalf("lower speed should be reported as tightened, got %v", got)
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
