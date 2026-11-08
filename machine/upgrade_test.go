package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRankMirrorsFastestFirst(t *testing.T) {
	chunk := []byte(strings.Repeat("x", 64<<10))
	serve := func(delay time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Range") == "" {
				t.Error("probe must send Range")
			}
			w.WriteHeader(http.StatusPartialContent)
			for i := 0; i < 4; i++ {
				time.Sleep(delay)
				_, _ = w.Write(chunk)
				w.(http.Flusher).Flush()
			}
		}))
	}
	slow, fast := serve(200*time.Millisecond), serve(0)
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer slow.Close()
	defer fast.Close()
	defer broken.Close()

	got := rankMirrors(context.Background(), []string{broken.URL + "/", slow.URL + "/", fast.URL + "/"}, "a.zip")
	want := []string{fast.URL + "/", slow.URL + "/", broken.URL + "/"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rank = %v, want %v", got, want)
		}
	}
}
