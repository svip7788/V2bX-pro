package node

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
)

func TestKeepRecentWSChanges(t *testing.T) {
	now := time.Now()
	c := &Controller{
		userList: []panel.UserInfo{{Id: 1, Uuid: "a"}, {Id: 3, Uuid: "new"}},
		wsTouched: map[int]time.Time{
			3: now,                        // 刚经 WS 加入，快照里还没有
			2: now,                        // 刚经 WS 移除，快照里还在
			1: now.Add(-10 * time.Minute), // 早于快照，以快照为准
		},
	}
	snapshot := []panel.UserInfo{{Id: 1, Uuid: "a", SpeedLimit: 7}, {Id: 2, Uuid: "old"}}
	got := c.keepRecentWSChanges(snapshot, now.Add(-20*time.Second))

	ids := map[int]panel.UserInfo{}
	for _, u := range got {
		ids[u.Id] = u
	}
	if _, ok := ids[3]; !ok {
		t.Fatal("user just added via WS must be kept")
	}
	if _, ok := ids[2]; ok {
		t.Fatal("user just removed via WS must not come back from stale snapshot")
	}
	if ids[1].SpeedLimit != 7 {
		t.Fatal("changes older than snapshot must follow the snapshot")
	}
	if _, ok := c.wsTouched[1]; ok {
		t.Fatal("entries older than snapshot should be purged")
	}
	if len(snapshot) != 2 || snapshot[1].Id != 2 {
		t.Fatal("input snapshot must not be modified")
	}
}

func TestNodeInfoRefetchedAfterUserListFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"e1"`)
			_, _ = w.Write([]byte(`{"server_port":443,"network":"tcp","base_config":{"push_interval":60,"pull_interval":60},"ip_watch":{"enable":true,"targets":["8.8.8.8"],"threshold":1}}`))
		case "/api/v1/server/UniProxy/user":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	c := newTestController(t, server.URL, &fakeCore{})
	if err := c.nodeInfoMonitor(); err != nil {
		t.Fatalf("nodeInfoMonitor: %v", err)
	}
	n, err := c.apiClient.GetNodeInfo(context.Background())
	if err != nil {
		t.Fatalf("GetNodeInfo: %v", err)
	}
	if n == nil || n.IPWatch == nil || n.IPWatch.Threshold != 1 {
		t.Fatal("config fetched before a failed user list must be refetched, not swallowed by 304")
	}
}

func TestNodeInfoMonitorBacksOffWhenNodeGone(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"fail","message":"Server does not exist"}`))
	}))
	defer server.Close()

	c := newTestController(t, server.URL, &fakeCore{})
	for i := 0; i < 3; i++ {
		if err := c.periodicNodeInfoMonitor(); err != nil {
			t.Fatalf("periodicNodeInfoMonitor: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("deleted node should back off after first 400, got %d requests", got)
	}
	if c.goneBackoff != goneBackoffMin {
		t.Fatalf("backoff = %v, want %v", c.goneBackoff, goneBackoffMin)
	}
	for i := 0; i < 5; i++ {
		c.markGone()
	}
	if c.goneBackoff != goneBackoffMax {
		t.Fatalf("backoff should cap at %v, got %v", goneBackoffMax, c.goneBackoff)
	}
}

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
