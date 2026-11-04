package panel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/conf"
)

func TestGetUserListForcesPeriodicFullRefresh(t *testing.T) {
	var current time.Time
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		switch requests {
		case 1:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Fatalf("first request should not send If-None-Match, got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "etag-1")
			_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"u1"}]}`))
		case 2:
			if got := r.Header.Get("If-None-Match"); got != "etag-1" {
				t.Fatalf("second request should reuse etag, got %q", got)
			}
			w.WriteHeader(http.StatusNotModified)
		case 3:
			if got := r.Header.Get("If-None-Match"); got != "" {
				t.Fatalf("third request should bypass etag after refresh window, got %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "etag-2")
			_, _ = w.Write([]byte(`{"users":[{"id":2,"uuid":"u2"}]}`))
		default:
			t.Fatalf("unexpected request count: %d", requests)
		}
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.nowFunc = func() time.Time { return current }
	client.userListForceRefreshAfter = time.Minute

	current = time.Unix(0, 0)
	users, err := client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("first get user list: %v", err)
	}
	if len(users) != 1 || users[0].Uuid != "u1" {
		t.Fatalf("unexpected first users: %#v", users)
	}

	current = current.Add(30 * time.Second)
	users, err = client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("second get user list: %v", err)
	}
	if users != nil {
		t.Fatalf("second get user list should be not modified, got %#v", users)
	}

	current = current.Add(2 * time.Minute)
	users, err = client.GetUserList(context.Background())
	if err != nil {
		t.Fatalf("third get user list: %v", err)
	}
	if len(users) != 1 || users[0].Uuid != "u2" {
		t.Fatalf("unexpected third users: %#v", users)
	}
}

func TestNewDisablesAutoRetry(t *testing.T) {
	client, err := New(&conf.ApiConfig{
		APIHost:  "http://127.0.0.1",
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client.client.RetryCount != 0 {
		t.Fatalf("expected retry count 0, got %d", client.client.RetryCount)
	}
}

func TestReportReturnsUnsupportedErrorForLegacyPanel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/report" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`not found`))
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = client.Report(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}}, nil)
	if err == nil {
		t.Fatal("expected report error")
	}
	if !IsUnsupportedReportError(err) {
		t.Fatalf("expected unsupported report error, got %T: %v", err, err)
	}
}

func TestReportKeepsServerErrorsOutOfLegacyFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/report" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`server busy`))
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = client.Report(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}}, nil)
	if err == nil {
		t.Fatal("expected report error")
	}
	if IsUnsupportedReportError(err) {
		t.Fatalf("did not expect unsupported report error: %v", err)
	}
}

func TestReportCanFailAfterServerProcessedBody(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/report" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		requests++

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijack")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	client, err := New(&conf.ApiConfig{
		APIHost:  server.URL,
		NodeID:   1,
		Key:      "test",
		NodeType: "vmess",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	err = client.Report(context.Background(), []UserTraffic{{UID: 1, Upload: 10, Download: 20}}, nil)
	if err == nil {
		t.Fatal("expected report error")
	}
	if requests != 1 {
		t.Fatalf("expected server to process exactly 1 request, got %d", requests)
	}
	if IsNotDelivered(err) {
		t.Fatalf("processed request must not be treated as undelivered: %v", err)
	}
}

func TestIsNotDelivered(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := server.URL
	server.Close()

	client, err := New(&conf.ApiConfig{APIHost: addr, NodeID: 1, Key: "test", NodeType: "vmess"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	err = client.Report(context.Background(), []UserTraffic{{UID: 1, Upload: 10}}, nil)
	if !IsNotDelivered(err) {
		t.Fatalf("dial failure should be undelivered: %v", err)
	}
	if !IsNotDelivered(&StatusError{StatusCode: http.StatusBadGateway}) {
		t.Fatal("502 should be undelivered")
	}
	if IsNotDelivered(&StatusError{StatusCode: http.StatusInternalServerError}) {
		t.Fatal("500 may have been processed")
	}
}
