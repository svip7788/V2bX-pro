package dispatcher

import (
	"strings"
	"time"

	"github.com/InazumaV/V2bX/common/livelog"
	"github.com/InazumaV/V2bX/limiter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
)

// liveOpen 用户正被后台实时查看时记录这条连接；未查看时只有一次原子读
func liveOpen(in *session.Inbound, l *limiter.Limiter, dest net.Destination, protocol string, h outbound.Handler) *livelog.Conn {
	if !livelog.Enabled() || in == nil || in.User == nil || l == nil {
		return nil
	}
	_, uuid, ok := strings.Cut(in.User.Email, "|")
	if !ok {
		return nil
	}
	uid, ok := l.GetUIDByUUID(uuid)
	if !ok {
		return nil
	}
	host := ""
	if dest.Address.Family().IsDomain() {
		host = dest.Address.Domain()
	} else {
		host = dest.Address.IP().String()
	}
	out := "direct"
	if isBlackhole(h) {
		out = "block"
	} else if strings.Contains(h.Tag(), "|relay|") {
		out = "relay"
	}
	return livelog.Open(in.Tag, uid, dest.Network.SystemString(), host, uint16(dest.Port), protocol, out)
}

type liveReader struct {
	buf.Reader
	c *livelog.Conn
}

func (r *liveReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	r.c.AddUp(int64(mb.Len()))
	return mb, err
}

func (r *liveReader) ReadMultiBufferTimeout(t time.Duration) (buf.MultiBuffer, error) {
	tr, ok := r.Reader.(buf.TimeoutReader)
	if !ok {
		return r.ReadMultiBuffer()
	}
	mb, err := tr.ReadMultiBufferTimeout(t)
	r.c.AddUp(int64(mb.Len()))
	return mb, err
}

func (r *liveReader) Interrupt() { common.Interrupt(r.Reader) }

func (r *liveReader) Close() error { return common.Close(r.Reader) }

type liveWriter struct {
	buf.Writer
	c *livelog.Conn
}

func (w *liveWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.c.AddDown(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *liveWriter) Interrupt() { common.Interrupt(w.Writer) }

func (w *liveWriter) Close() error { return common.Close(w.Writer) }
