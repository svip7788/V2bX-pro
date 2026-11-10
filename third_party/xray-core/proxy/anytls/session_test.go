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

func writeTestFrame(t *testing.T, w io.Writer, cmd byte, data string) {
	t.Helper()
	hdr := make([]byte, 7, 7+len(data))
	hdr[0] = cmd
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(data)))
	if _, err := w.Write(append(hdr, data...)); err != nil {
		t.Fatal(err)
	}
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
			writeTestFrame(t, cli, cmdSettings, "v="+tc.version+"\nclient=test")
			writeTestFrame(t, cli, cmdHeartRequest, "")
		}()
		if got := readTestFrameCmd(t, cli); got != tc.want {
			t.Fatalf("v=%s: first frame cmd=%d, want %d", tc.version, got, tc.want)
		}
		_ = cli.Close()
		_ = srv.Close()
	}
}
