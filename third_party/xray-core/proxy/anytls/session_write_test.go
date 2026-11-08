package anytls

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type countingWriter struct {
	mu     sync.Mutex
	data   bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	return w.data.Write(p)
}

func TestWriteCoalescedConcurrentFramesIntact(t *testing.T) {
	cw := &countingWriter{}
	s := &session{fw: newFrameWriter(buf.NewBufferedWriterSize(buf.NewWriter(cw), tlsMaxPlaintext))}

	const writers, perWriter = 32, 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(sid uint32) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				payload := bytes.Repeat([]byte{byte(sid)}, 100+j*40)
				if err := s.sendFrame(&frame{cmd: cmdPSH, sid: sid, data: payload}); err != nil {
					t.Error(err)
					return
				}
			}
		}(uint32(i + 1))
	}
	wg.Wait()

	if n := s.pendingWrites.Load(); n != 0 {
		t.Fatalf("pendingWrites = %d, want 0", n)
	}

	out := cw.data.Bytes()
	frames := 0
	for len(out) > 0 {
		if len(out) < 7 {
			t.Fatalf("truncated header")
		}
		sid := binary.BigEndian.Uint32(out[1:5])
		n := int(binary.BigEndian.Uint16(out[5:7]))
		body := out[7 : 7+n]
		if !bytes.Equal(body, bytes.Repeat([]byte{byte(sid)}, n)) {
			t.Fatalf("frame %d of sid %d corrupted", frames, sid)
		}
		out = out[7+n:]
		frames++
	}
	if frames != writers*perWriter {
		t.Fatalf("frames = %d, want %d", frames, writers*perWriter)
	}
	if cw.writes >= frames {
		t.Fatalf("writes = %d, expected coalescing below %d frames", cw.writes, frames)
	}
	t.Logf("%d frames in %d writes", frames, cw.writes)
}

func TestSendFrameFlushesWhenAlone(t *testing.T) {
	cw := &countingWriter{}
	s := &session{fw: newFrameWriter(buf.NewBufferedWriterSize(buf.NewWriter(cw), tlsMaxPlaintext))}
	if err := s.sendFrame(newFrame(cmdHeartRequest, 0)); err != nil {
		t.Fatal(err)
	}
	if cw.data.Len() != 7 || cw.writes != 1 {
		t.Fatalf("got %d bytes in %d writes, want 7 in 1", cw.data.Len(), cw.writes)
	}
}
