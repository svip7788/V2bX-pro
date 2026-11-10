package machine

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(&conf.MachineConfig{APIHost: "http://127.0.0.1:1", MachineID: 1, Token: "t"}, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.cancel)
	return m
}

func TestHandleSyncNodesQueuesPush(t *testing.T) {
	m := newTestManager(t)
	m.handleEvent(panel.WSEvent{Event: "sync.nodes", Data: json.RawMessage(`{"nodes":[]}`)})
	if !m.hasPending || m.pendingNodes == nil || len(m.pendingNodes) != 0 {
		t.Fatalf("empty push must be kept as empty list: has=%v nodes=%v", m.hasPending, m.pendingNodes)
	}
	select {
	case <-m.syncCh:
	default:
		t.Fatal("sync not triggered")
	}

	m.handleEvent(panel.WSEvent{Event: "sync.nodes", Data: json.RawMessage(`{"nodes":[{"id":3,"type":"vless","node_type":"vless"}]}`)})
	m.handleEvent(panel.WSEvent{Event: "sync.nodes", Data: json.RawMessage(`{"nodes":[{"id":4,"type":"trojan","node_type":"trojan"}]}`)})
	if len(m.pendingNodes) != 1 || m.pendingNodes[0].ID != 4 {
		t.Fatalf("latest push should win: %v", m.pendingNodes)
	}
}

func TestHandleUnknownNodeEventIgnored(t *testing.T) {
	m := newTestManager(t)
	m.handleEvent(panel.WSEvent{Event: "sync.users", Data: json.RawMessage(`{"node_id":99,"users":[]}`)})
	select {
	case <-m.syncCh:
		t.Fatal("node event must not trigger node list sync")
	default:
	}
	m.handleEvent(panel.WSEvent{Event: "sync.config"})
	select {
	case <-m.syncCh:
	default:
		t.Fatal("sync.config without node_id should trigger full sync")
	}
}

func TestUpgradeRejectsBadParams(t *testing.T) {
	m := newTestManager(t)
	for _, params := range []string{`{"version":"latest"}`, `{"version":"v1; rm -rf /"}`, `{"version":"v1.0.8","repo":"../x"}`} {
		if _, _, err := m.commands.upgrade(command{ID: "1", Action: "upgrade", Params: json.RawMessage(params)}); err == nil {
			t.Errorf("params %s should be rejected", params)
		}
	}
}

func TestUnzipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "a.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../evil")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()
	if err := unzip(zipPath, filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestTruncateTail(t *testing.T) {
	long := make([]byte, maxCommandOutput+100)
	for i := range long {
		long[i] = 'a'
		if i%50 == 0 {
			long[i] = '\n'
		}
	}
	if got := truncateTail(string(long)); len(got) > maxCommandOutput+32 {
		t.Fatalf("not truncated: %d", len(got))
	}
}
