//go:build unix

package cmd

import (
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPprofSignalStartsLocalServer(t *testing.T) {
	file := pprofAddrFile(os.Getpid())
	_ = os.Remove(file)
	t.Cleanup(func() { _ = os.Remove(file) })
	watchPprofSignal()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	var addr string
	for i := 0; i < 50 && addr == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		b, _ := os.ReadFile(file)
		addr = strings.TrimSpace(string(b))
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("pprof addr = %q, want loopback", addr)
	}
	resp, err := http.Get("http://" + addr + "/debug/pprof/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
