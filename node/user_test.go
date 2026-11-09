package node

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
)

type fakeCore struct {
	traffic     []panel.UserTraffic
	commitCalls int
}

func (f *fakeCore) Start() error { return nil }

func (f *fakeCore) Close() error { return nil }

func (f *fakeCore) AddNode(string, *panel.NodeInfo, *conf.Options) error { return nil }

func (f *fakeCore) DelNode(string) error { return nil }

func (f *fakeCore) AddUsers(*vCore.AddUsersParams) (int, error) { return 0, nil }

func (f *fakeCore) GetUserTrafficSlice(string, bool) ([]panel.UserTraffic, error) {
	return append([]panel.UserTraffic(nil), f.traffic...), nil
}

func (f *fakeCore) CommitUserTraffic(string, []panel.UserTraffic) error {
	f.commitCalls++
	return nil
}

func (f *fakeCore) RestoreUserTraffic(string, []panel.UserTraffic) error { return nil }

func (f *fakeCore) DelUsers([]panel.UserInfo, string, *panel.NodeInfo) error { return nil }

func (f *fakeCore) CloseUserConns(string, string) int { return 0 }

func (f *fakeCore) ActiveUserIPs(string) map[string][]string { return nil }

func (f *fakeCore) Protocols() []string { return nil }

func (f *fakeCore) Type() string { return "fake" }

func newTestController(t *testing.T, url string, core *fakeCore) *Controller {
	t.Helper()
	limiter.Init()
	client, err := panel.New(&conf.ApiConfig{
		APIHost:  url,
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	tag := "test-tag"
	return &Controller{
		server:   core,
		apiClient: client,
		tag:      tag,
		limiter:  limiter.AddLimiter(tag, &conf.LimitConfig{}, nil, map[int]int{}),
		Options:  &conf.Options{},
	}
}

func TestReportUserTrafficTaskSkipsV1FallbackOnTransientV2Error(t *testing.T) {
	v2Calls := 0
	v1Calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/report":
			v2Calls++
			_, _ = io.ReadAll(r.Body)
			_ = r.Body.Close()
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("response writer does not support hijack")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack failed: %v", err)
			}
			_ = conn.Close()
		case "/api/v1/server/UniProxy/push":
			v1Calls++
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	core := &fakeCore{
		traffic: []panel.UserTraffic{{UID: 1, Upload: 10, Download: 20}},
	}
	controller := newTestController(t, server.URL, core)

	if err := controller.reportUserTrafficTask(); err != nil {
		t.Fatalf("report user traffic task: %v", err)
	}
	if v2Calls != 1 {
		t.Fatalf("expected 1 v2 report call, got %d", v2Calls)
	}
	if v1Calls != 0 {
		t.Fatalf("expected 0 v1 fallback calls, got %d", v1Calls)
	}
	if core.commitCalls != 0 {
		t.Fatalf("expected no traffic commit on transient error, got %d", core.commitCalls)
	}
}

func TestReportUserTrafficTaskFallsBackToV1WhenV2Unsupported(t *testing.T) {
	v2Calls := 0
	v1Calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/report":
			v2Calls++
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/server/UniProxy/push":
			v1Calls++
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	core := &fakeCore{
		traffic: []panel.UserTraffic{{UID: 1, Upload: 10, Download: 20}},
	}
	controller := newTestController(t, server.URL, core)

	if err := controller.reportUserTrafficTask(); err != nil {
		t.Fatalf("report user traffic task: %v", err)
	}
	if v2Calls != 1 {
		t.Fatalf("expected 1 v2 report call, got %d", v2Calls)
	}
	if v1Calls != 1 {
		t.Fatalf("expected 1 v1 fallback call, got %d", v1Calls)
	}
	// One-phase accounting: traffic is cleared inside GetUserTrafficSlice,
	// so CommitUserTraffic is never invoked regardless of report outcome.
	if core.commitCalls != 0 {
		t.Fatalf("expected no explicit traffic commit under one-phase accounting, got %d", core.commitCalls)
	}
}
