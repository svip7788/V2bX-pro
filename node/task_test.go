package node

import (
	"testing"
	"time"
)

func TestPeriodicNodeInfoMonitorSkipsWhenWSConnected(t *testing.T) {
	controller := &Controller{
		wsConnected: func() bool {
			return true
		},
	}
	controller.lastPollAt.Store(time.Now().Unix())

	if err := controller.periodicNodeInfoMonitor(); err != nil {
		t.Fatalf("periodicNodeInfoMonitor returned error: %v", err)
	}
}

func TestShouldPollFallbackWhenWSConnected(t *testing.T) {
	ws := true
	c := &Controller{wsConnected: func() bool { return ws }}
	now := time.Now()

	c.lastPollAt.Store(now.Add(-time.Minute).Unix())
	if c.shouldPoll(now) {
		t.Fatal("recent poll with WS connected should skip")
	}
	c.lastPollAt.Store(now.Add(-wsFallbackPollInterval).Unix())
	if !c.shouldPoll(now) {
		t.Fatal("WS connected must still poll after fallback interval")
	}
	ws = false
	c.lastPollAt.Store(now.Unix())
	if !c.shouldPoll(now) {
		t.Fatal("without WS must always poll")
	}
}
