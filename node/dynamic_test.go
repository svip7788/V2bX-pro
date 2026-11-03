package node

import (
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	"github.com/InazumaV/V2bX/limiter"
)

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
