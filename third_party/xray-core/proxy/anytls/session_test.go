package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

func writeTestFrame(w io.Writer, cmd byte, data string) error {
	hdr := make([]byte, 7, 7+len(data))
	hdr[0] = cmd
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(data)))
	_, err := w.Write(append(hdr, data...))
	return err
}

func readTestFrameCmd(t *testing.T, r io.Reader) byte {
	t.Helper()
	var hdr [7]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint16(hdr[5:7]); n > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
			t.Fatal(err)
		}
	}
	return hdr[0]
}

func TestFallbackRelaysReadBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const req = "GET / HTTP/1.1\r\n\r\n"
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, len(req))
		_, _ = io.ReadFull(c, b)
		got <- string(b)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}()

	srv, cli := net.Pipe()
	s := &Server{fallbackDest: ln.Addr().String()}
	done := make(chan error, 1)
	go func() {
		done <- s.fallback(context.Background(), srv, &buf.BufferedReader{Reader: buf.NewReader(srv)}, []byte(req[:6]), time.Minute)
	}()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write([]byte(req[6:])); err != nil {
		t.Fatal(err)
	}
	if r := <-got; r != req {
		t.Fatalf("fallback received %q, want %q", r, req)
	}
	resp := make([]byte, len("HTTP/1.1 200 OK\r\n\r\n"))
	if _, err := io.ReadFull(cli, resp); err != nil || string(resp) != "HTTP/1.1 200 OK\r\n\r\n" {
		t.Fatalf("client got %q err=%v", resp, err)
	}
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not return after close")
	}
}

func TestServerSettingsOnlyForV2Client(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    byte
	}{
		{"1", cmdHeartResponse},
		{"2", cmdServerSettings},
	} {
		srv, cli := net.Pipe()
		sess := &session{
			conn:        srv,
			br:          &buf.BufferedReader{Reader: buf.NewReader(srv)},
			bw:          buf.NewBufferedWriter(buf.NewWriter(srv)),
			streams:     make(map[uint32]*stream),
			peerVersion: 1,
		}
		sess.fw = newFrameWriter(sess.bw)
		go sess.readLoop(context.Background())

		_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
		go func() {
			// 测试读到首帧即关闭管道，后续写入失败属正常
			if writeTestFrame(cli, cmdSettings, "v="+tc.version+"\nclient=test") == nil {
				_ = writeTestFrame(cli, cmdHeartRequest, "")
			}
		}()
		if got := readTestFrameCmd(t, cli); got != tc.want {
			t.Fatalf("v=%s: first frame cmd=%d, want %d", tc.version, got, tc.want)
		}
		_ = cli.Close()
		_ = srv.Close()
	}
}
