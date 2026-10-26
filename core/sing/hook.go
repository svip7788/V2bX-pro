package sing

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/common/probe"
	"github.com/InazumaV/V2bX/common/rate"

	"github.com/InazumaV/V2bX/limiter"

	"github.com/InazumaV/V2bX/common/counter"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	llog "github.com/sirupsen/logrus"
)

var _ adapter.ConnectionTracker = (*HookServer)(nil)

type HookServer struct {
	counter      sync.Map // map[string]*counter.TrafficCounter
	connManagers sync.Map // map[string]*userConnManager
}

func (h *HookServer) ModeList() []string {
	return nil
}

func (h *HookServer) RoutedConnection(ctx context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		conn.Close()
		return conn
	}
	taguuid := format.UserTag(m.Inbound, m.User)
	ip := m.Source.Addr.String()
	if m.Protocol == C.ProtocolBitTorrent {
		h.banBitTorrent(l, taguuid, m)
		conn.Close()
		return conn
	}
	if b, r := l.CheckLimit(taguuid, ip, true, true); r {
		conn.Close()
		log.Info("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		conn = rate.NewConnRateLimiter(conn, b)
	}
	destStr := m.Destination.AddrString()
	if l.CheckDomainRule(destStr) {
		log.Warn("[", m.Inbound, "] User ", m.User, " access domain ", destStr, " reject by rule")
		conn.Close()
		return conn
	}
	if protocol := m.Protocol; len(protocol) != 0 && l.CheckProtocolRule(protocol) {
		log.Warn("[", m.Inbound, "] User ", m.User, " access protocol ", protocol, " reject by rule")
		conn.Close()
		return conn
	}
	if m.Destination.Port == probe.Port {
		var answered bool
		if conn, answered = replyLatencyProbe(conn, m); answered {
			return nil
		}
	}
	t := h.getCounter(m.Inbound)
	conn = counter.NewConnCounter(conn, t.GetCounter(m.User))
	conn = newTrackedConn(conn, h.getConnManager(taguuid))
	// Safety net: untrack and close when the per-connection context is
	// cancelled, in case sing-box ends the connection without calling Close
	// on our wrapper. Close is idempotent (guarded by sync.Once).
	tracked := conn
	context.AfterFunc(ctx, func() { _ = tracked.Close() })
	return conn
}

// replyLatencyProbe 明文测速请求由节点直接应答（keep-alive），结束后关闭连接；不匹配时把已读数据放回连接
func replyLatencyProbe(conn net.Conn, m adapter.InboundContext) (net.Conn, bool) {
	buffer := buf.New()
	deadline := time.Now().Add(probe.PeekTimeout)
	for !probe.RequestLineComplete(buffer.Bytes()) && !buffer.IsFull() {
		if conn.SetReadDeadline(deadline) != nil {
			break
		}
		if _, err := buffer.ReadOnceFrom(conn); err != nil {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	host := m.Destination.Fqdn
	if host == "" {
		host = m.Domain
	}
	if probe.Match(host, buffer.Bytes()) != nil {
		data := append([]byte(nil), buffer.Bytes()...)
		buffer.Release()
		readBuf := make([]byte, 4096)
		probe.Serve(host, data, func(timeout time.Duration) ([]byte, error) {
			if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				return nil, err
			}
			n, err := conn.Read(readBuf)
			return readBuf[:n], err
		}, func(b []byte) error {
			_, err := conn.Write(b)
			return err
		})
		conn.Close()
		log.Debug("[", m.Inbound, "] reply latency probe for ", m.Destination)
		return conn, true
	}
	if buffer.IsEmpty() {
		buffer.Release()
		return conn, false
	}
	return bufio.NewCachedConn(conn, buffer), false
}

func (h *HookServer) banBitTorrent(l *limiter.Limiter, taguuid string, m adapter.InboundContext) {
	newly, d := l.BanBitTorrent(taguuid)
	closed := h.closeUserConnections(taguuid)
	if newly {
		llog.WithFields(llog.Fields{
			"tag":    m.Inbound,
			"user":   m.User,
			"ip":     m.Source.Addr.String(),
			"dest":   m.Destination.String(),
			"ban":    d.String(),
			"closed": closed,
		}).Warn("BitTorrent detected, user banned on this node")
	}
}

func (h *HookServer) getCounter(tag string) *counter.TrafficCounter {
	if c, ok := h.counter.Load(tag); ok {
		return c.(*counter.TrafficCounter)
	}
	c, _ := h.counter.LoadOrStore(tag, counter.NewTrafficCounter())
	return c.(*counter.TrafficCounter)
}

func (h *HookServer) getConnManager(taguuid string) *userConnManager {
	if m, ok := h.connManagers.Load(taguuid); ok {
		return m.(*userConnManager)
	}
	manager := &userConnManager{}
	manager.markOwner(taguuid, &h.connManagers)
	actual, _ := h.connManagers.LoadOrStore(taguuid, manager)
	return actual.(*userConnManager)
}

func (h *HookServer) closeUserConnections(taguuid string) int {
	if m, ok := h.connManagers.Load(taguuid); ok {
		manager := m.(*userConnManager)
		n := manager.CloseAll()
		h.connManagers.Delete(taguuid)
		return n
	}
	return 0
}

func (h *HookServer) closeTagConnections(tag string) {
	prefix := tag + "|"
	h.connManagers.Range(func(key, value interface{}) bool {
		taguuid, ok := key.(string)
		if !ok {
			return true
		}
		if len(taguuid) >= len(prefix) && taguuid[:len(prefix)] == prefix {
			manager := value.(*userConnManager)
			manager.CloseAll()
			h.connManagers.Delete(key)
		}
		return true
	})
}

func (h *HookServer) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		conn.Close()
		return conn
	}
	ip := m.Source.Addr.String()
	taguuid := format.UserTag(m.Inbound, m.User)
	if m.Protocol == C.ProtocolBitTorrent {
		h.banBitTorrent(l, taguuid, m)
		conn.Close()
		return conn
	}
	if b, r := l.CheckLimit(taguuid, ip, false, false); r {
		conn.Close()
		log.Info("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn
	} else if b != nil {
		conn = rate.NewPacketConnRateLimiter(conn, b)
	}
	destStr := m.Destination.AddrString()
	if l.CheckDomainRule(destStr) {
		log.Warn("[", m.Inbound, "] User ", m.User, " access domain ", destStr, " reject by rule")
		conn.Close()
		return conn
	}
	if protocol := m.Destination.Network(); len(protocol) != 0 && l.CheckProtocolRule(protocol) {
		log.Warn("[", m.Inbound, "] User ", m.User, " access protocol ", protocol, " reject by rule")
		conn.Close()
		return conn
	}
	t := h.getCounter(m.Inbound)
	conn = counter.NewPacketConnCounter(conn, t.GetCounter(m.User))
	conn = newTrackedPacketConn(conn, h.getConnManager(taguuid))
	tracked := conn
	context.AfterFunc(ctx, func() { _ = tracked.Close() })
	return conn
}
