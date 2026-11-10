package node

import (
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/InazumaV/V2bX/limiter"
)

func TestMergeTraffic(t *testing.T) {
	out := mergeTraffic(
		[]panel.UserTraffic{{UID: 1, Upload: 1, Download: 2}, {UID: 2, Upload: 5}},
		[]panel.UserTraffic{{UID: 1, Upload: 10, Download: 20}, {UID: 3, Download: 7}},
	)
	want := map[int][2]int64{1: {11, 22}, 2: {5, 0}, 3: {0, 7}}
	if len(out) != len(want) {
		t.Fatalf("got %d entries, want %d", len(out), len(want))
	}
	for _, u := range out {
		if w := want[u.UID]; u.Upload != w[0] || u.Download != w[1] {
			t.Fatalf("uid %d: got %d/%d, want %d/%d", u.UID, u.Upload, u.Download, w[0], w[1])
		}
	}
}

func TestApplyDynamicSpeedLimitPanelOverridesLocal(t *testing.T) {
	local := &conf.DynamicSpeedLimitConfig{DyLimitSpeed: 10}
	c := &Controller{Options: &conf.Options{LimitConfig: conf.LimitConfig{
		EnableDynamicSpeedLimit: true,
		DynamicSpeedLimitConfig: local,
	}}}

	c.applyDynamicSpeedLimit(&panel.NodeInfo{})
	if !c.LimitConfig.EnableDynamicSpeedLimit || c.LimitConfig.DynamicSpeedLimitConfig != local {
		t.Fatal("local config should be used when panel sends nothing")
	}

	c.applyDynamicSpeedLimit(&panel.NodeInfo{DynamicSpeedLimit: &panel.DynamicSpeedLimit{Enable: true, LimitSpeed: 50}})
	if !c.LimitConfig.EnableDynamicSpeedLimit || c.LimitConfig.DynamicSpeedLimitConfig.DyLimitSpeed != 50 {
		t.Fatal("panel config not applied")
	}

	c.applyDynamicSpeedLimit(&panel.NodeInfo{DynamicSpeedLimit: &panel.DynamicSpeedLimit{Enable: false}})
	if c.LimitConfig.EnableDynamicSpeedLimit {
		t.Fatal("panel should be able to disable")
	}

	c.applyDynamicSpeedLimit(&panel.NodeInfo{})
	if !c.LimitConfig.EnableDynamicSpeedLimit || c.LimitConfig.DynamicSpeedLimitConfig != local {
		t.Fatal("should fall back to local config after panel removes it")
	}
}

func TestApplyConnLimitPanelOverridesLocal(t *testing.T) {
	limiter.Init()
	c := &Controller{tag: "t", Options: &conf.Options{LimitConfig: conf.LimitConfig{ConnLimit: 50}}}
	c.limiter = limiter.AddLimiter("t", &c.LimitConfig, []panel.UserInfo{{Id: 1, Uuid: "u"}}, nil)
	key := "t|u"

	c.applyConnLimit(&panel.NodeInfo{})
	if got := c.limiter.UserConnLimit(key); got != 50 {
		t.Fatalf("local conn limit should be used, got %d", got)
	}
	n := 200
	c.applyConnLimit(&panel.NodeInfo{ConnLimit: &n})
	if got := c.limiter.UserConnLimit(key); got != 200 || c.LimitConfig.ConnLimit != 200 {
		t.Fatalf("panel conn limit not applied, got %d", got)
	}
	zero := 0
	c.applyConnLimit(&panel.NodeInfo{ConnLimit: &zero})
	if got := c.limiter.UserConnLimit(key); got != 0 {
		t.Fatalf("panel should be able to disable, got %d", got)
	}
	c.applyConnLimit(&panel.NodeInfo{})
	if got := c.limiter.UserConnLimit(key); got != 50 {
		t.Fatalf("should fall back to local, got %d", got)
	}
}

func TestCheckDynamicSpeedUsesElapsedTime(t *testing.T) {
	limiter.Init()
	tag := "dy"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1"}, {Id: 2, Uuid: "u2"}}
	cfg := conf.LimitConfig{
		EnableDynamicSpeedLimit: true,
		DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{
			DyLimitTriggerTime:  60,
			DyLimitTriggerSpeed: 100,
			DyLimitSpeed:        30,
			DyLimitTime:         600,
		},
	}
	c := &Controller{
		server:    &fakeCore{},
		tag:       tag,
		limiter:   limiter.AddLimiter(tag, &cfg, users, map[int]int{}),
		info:      &panel.NodeInfo{PushInterval: 120 * time.Second},
		uidToUUID: map[int]string{1: "u1", 2: "u2"},
		Options:   &conf.Options{LimitConfig: cfg},
	}
	c.resetDynamicTraffic()

	// 上报间隔 120s：u1 均速 80Mbps 不应触发（按 60s 算会误判为 160Mbps），u2 均速 160Mbps 应触发
	const mbps = 1000000 / 8
	c.addDynamicTraffic([]panel.UserTraffic{
		{UID: 1, Download: 80 * mbps * 120},
		{UID: 2, Download: 160 * mbps * 120},
	})
	if c.limiter.IsDynamicLimited(tag, "u1") {
		t.Fatal("u1 should not be limited")
	}
	if !c.limiter.IsDynamicLimited(tag, "u2") {
		t.Fatal("u2 should be limited")
	}

	c.limiter.SetDynamicConfig(&cfg)
	if !c.limiter.IsDynamicLimited(tag, "u2") {
		t.Fatal("unchanged config must keep existing limits")
	}
	cfg.DynamicSpeedLimitConfig = &conf.DynamicSpeedLimitConfig{DyLimitSpeed: 50}
	c.limiter.SetDynamicConfig(&cfg)
	if c.limiter.IsDynamicLimited(tag, "u2") {
		t.Fatal("config change should lift existing limits")
	}
}

func TestGlobalDynamicSpeedLimit(t *testing.T) {
	limiter.Init()
	tag := "dyg"
	users := []panel.UserInfo{{Id: 1, Uuid: "u1"}}
	cfg := conf.LimitConfig{
		EnableDynamicSpeedLimit: true,
		DynamicSpeedLimitConfig: &conf.DynamicSpeedLimitConfig{DyLimitTriggerTime: 60, DyLimitTriggerSpeed: 100, DyLimitSpeed: 30, DyLimitTime: 600},
	}
	c := &Controller{
		server:        &fakeCore{},
		tag:           tag,
		limiter:       limiter.AddLimiter(tag, &cfg, users, map[int]int{}),
		info:          &panel.NodeInfo{PushInterval: 60 * time.Second},
		uidToUUID:     map[int]string{1: "u1"},
		Options:       &conf.Options{LimitConfig: cfg},
		dynamicGlobal: true,
		wsConnected:   func() bool { return true },
	}
	c.resetDynamicTraffic()

	const mbps = 1000000 / 8
	c.addDynamicTraffic([]panel.UserTraffic{{UID: 1, Download: 200 * mbps * 60}})
	if c.limiter.IsDynamicLimited(tag, "u1") {
		t.Fatal("global mode with WS online must leave judgement to panel")
	}

	c.processWSEvent(panel.WSEvent{Event: "speed.limit", Data: []byte(`{"users":[{"id":1,"limit_speed":25,"limit_time":600},{"id":9,"limit_speed":25,"limit_time":600}]}`)})
	if !c.limiter.IsDynamicLimited(tag, "u1") {
		t.Fatal("speed.limit event should limit u1")
	}
}
