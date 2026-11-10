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

func TestUserConnLimitPanelOverridesNode(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{ConnLimit: 100}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", ConnLimit: 20},
		{Id: 2, Uuid: "u2"},
	}, map[int]int{})

	if got := lim.UserConnLimit(format.UserTag("tag", "u1")); got != 20 {
		t.Fatalf("panel conn_limit should win, got %d", got)
	}
	if got := lim.UserConnLimit(format.UserTag("tag", "u2")); got != 100 {
		t.Fatalf("node ConnLimit should be default, got %d", got)
	}
	lim.UpdateUserLimit("tag", []panel.UserInfo{{Id: 2, Uuid: "u2", ConnLimit: 5}})
	if got := lim.UserConnLimit(format.UserTag("tag", "u2")); got != 5 {
		t.Fatalf("updated conn_limit should apply, got %d", got)
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

func TestExcessRejectsAndFreesSlot(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 2},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")

	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		if _, reject := lim.CheckLimit(taguuid, ip, true, true); reject {
			t.Fatalf("%s should pass", ip)
		}
	}
	// 面板裁决 2.2.2.2 超限（别的节点先占了名额）
	lim.SetExcess(map[int][]string{1: {"2.2.2.2"}}, time.Now())
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); !reject {
		t.Fatal("excess device should be rejected even if known locally")
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", false, false); !reject {
		t.Fatal("excess device udp should be rejected")
	}
	if !lim.IsExcess(1, "2.2.2.2") || lim.IsExcess(1, "1.1.1.1") {
		t.Fatal("IsExcess mismatch")
	}
	// 清出本节点状态后名额释放
	if _, reject := lim.CheckLimit(taguuid, "3.3.3.3", true, true); reject {
		t.Fatal("slot of excess device should be freed")
	}
	// 面板汇总里还留着被踢的 2.2.2.2，不应再占名额
	lim.MarkOnlineDeviceReported()
	lim.MarkOnlineDeviceReported()
	lim.SetAliveIPs(map[int][]string{1: {"1.1.1.1", "2.2.2.2"}}, time.Now())
	if _, reject := lim.CheckLimit(taguuid, "4.4.4.4", true, true); reject {
		t.Fatal("excess device still in alive list should not take a slot")
	}
	if _, reject := lim.CheckLimit(taguuid, "5.5.5.5", true, true); !reject {
		t.Fatal("limit should still apply after excess is excluded")
	}
	lim.SetExcess(map[int][]string{1: {"2.2.2.2"}}, time.Now().Add(-aliveIPsMaxAge-time.Second))
	if lim.IsExcess(1, "2.2.2.2") {
		t.Fatal("stale excess should not apply")
	}
	lim.SetExcess(nil, time.Now())
	if lim.IsExcess(1, "2.2.2.2") {
		t.Fatal("cleared excess should not apply")
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

func TestDeviceKeyMergesIPv6Prefix(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":                  "1.2.3.4",
		"::ffff:1.2.3.4":           "1.2.3.4",
		"2001:db8:1:2:aaaa::1":     "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::9%en0": "2001:db8:1:2::/64",
		"bad":                      "bad",
	}
	for in, want := range cases {
		if got := deviceKey(in); got != want {
			t.Errorf("deviceKey(%q) = %q, want %q", in, got, want)
		}
	}

	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")
	if _, reject := lim.CheckLimit(taguuid, "2001:db8:1:2::1", true, true); reject {
		t.Fatal("first ipv6 should pass")
	}
	if _, reject := lim.CheckLimit(taguuid, "2001:db8:1:2::2", true, true); reject {
		t.Fatal("rotated ipv6 in same /64 is the same device")
	}
}

func TestDeviceKeyMergesIPv4Prefix(t *testing.T) {
	SetIPv4Prefix(24)
	defer SetIPv4Prefix(32)
	cases := map[string]string{
		"112.96.84.14":    "112.96.84.0/24",
		"::ffff:1.2.3.4":  "1.2.3.0/24",
		"112.96.84.0/24":  "112.96.84.0/24",
		"2001:db8:1:2::1": "2001:db8:1:2::/64",
	}
	for in, want := range cases {
		if got := deviceKey(in); got != want {
			t.Errorf("deviceKey(%q) = %q, want %q", in, got, want)
		}
	}

	Init()
	lim := AddLimiter("tag4", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{})
	taguuid := format.UserTag("tag4", "u1")
	if _, reject := lim.CheckLimit(taguuid, "112.96.84.14", true, true); reject {
		t.Fatal("first ipv4 should pass")
	}
	if _, reject := lim.CheckLimit(taguuid, "112.96.84.206", true, true); reject {
		t.Fatal("cgnat ipv4 in same /24 is the same device")
	}
	if _, reject := lim.CheckLimit(taguuid, "112.96.85.1", true, true); !reject {
		t.Fatal("ipv4 in another /24 should count as a new device")
	}
	if got := lim.getOrCreateDeviceState(taguuid, 1).snapshotCurrent(); len(got) != 1 || got[0].IP != "112.96.84.206" {
		t.Fatalf("should report latest raw ip, got %+v", got)
	}

	SetIPv4Prefix(32)
	if got := deviceKey("1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("prefix 32 should not merge, got %q", got)
	}
}

func TestTouchActiveDevicesKeepsLongLivedConn(t *testing.T) {
	Init()
	lim := AddLimiter("tag", &conf.LimitConfig{}, []panel.UserInfo{
		{Id: 1, Uuid: "u1", DeviceLimit: 1},
	}, map[int]int{})
	taguuid := format.UserTag("tag", "u1")
	if _, reject := lim.CheckLimit(taguuid, "1.1.1.1", true, true); reject {
		t.Fatal("first ip should pass")
	}
	for i := 0; i < 3; i++ {
		lim.TouchActiveDevices("tag", map[string][]string{"u1": {"1.1.1.1"}})
		online, _ := lim.GetOnlineDevice()
		if len(online) != 1 || online[0].IP != "1.1.1.1" {
			t.Fatalf("round %d: long-lived conn should stay reported, got %v", i, online)
		}
		lim.MarkOnlineDeviceReported()
	}
	if _, reject := lim.CheckLimit(taguuid, "2.2.2.2", true, true); !reject {
		t.Fatal("slot held by long-lived conn should reject a new ip")
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
