//go:build unix

package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const pprofOnDemandTTL = 10 * time.Minute

func pprofAddrFile(pid int) string {
	return fmt.Sprintf("/tmp/v2bx-pprof-%d.addr", pid)
}

// watchPprofSignal 收到 SIGUSR1 时在 127.0.0.1 随机端口临时开启 pprof（不用重启、不断连接），
// 地址写入 /tmp/v2bx-pprof-<pid>.addr；10 分钟后自动关闭，期间再发信号会顺延
func watchPprofSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	addrFile := pprofAddrFile(os.Getpid())
	go func() {
		var srv *http.Server
		var stop <-chan time.Time
		for {
			select {
			case <-ch:
				if srv == nil {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						log.WithField("err", err).Error("Start pprof failed")
						continue
					}
					srv = &http.Server{Handler: http.DefaultServeMux, ReadHeaderTimeout: 10 * time.Second}
					go func(s *http.Server) { _ = s.Serve(ln) }(srv)
					_ = os.WriteFile(addrFile, []byte(ln.Addr().String()+"\n"), 0600)
				}
				stop = time.After(pprofOnDemandTTL)
			case <-stop:
				_ = srv.Close()
				srv, stop = nil, nil
				_ = os.Remove(addrFile)
			}
		}
	}()
}
