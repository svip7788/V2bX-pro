package sing

import (
	"net"
	"sync"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type managedCloser interface {
	Close() error
}

type userConnManager struct {
	mu    sync.Mutex
	conns map[managedCloser]string // 值为做过设备数检查的来源 IP，其余为空
	key   string
	owner *sync.Map
}

func (m *userConnManager) Add(conn managedCloser, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owner != nil && m.key != "" {
		m.owner.Store(m.key, m)
	}
	if m.conns == nil {
		m.conns = make(map[managedCloser]string)
	}
	m.conns[conn] = ip
}

// IPs 返回活跃连接的来源 IP（去重）
func (m *userConnManager) IPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ips []string
	seen := make(map[string]struct{}, 1)
	for _, ip := range m.conns {
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	return ips
}

func (m *userConnManager) Remove(conn managedCloser) {
	m.mu.Lock()
	delete(m.conns, conn)
	empty := len(m.conns) == 0
	m.mu.Unlock()
	if empty && m.owner != nil && m.key != "" {
		m.owner.CompareAndDelete(m.key, m)
	}
}

func (m *userConnManager) markOwner(key string, owner *sync.Map) {
	m.mu.Lock()
	m.key = key
	m.owner = owner
	m.mu.Unlock()
}

func (m *userConnManager) CloseAll() int {
	m.mu.Lock()
	snapshot := make([]managedCloser, 0, len(m.conns))
	for conn := range m.conns {
		snapshot = append(snapshot, conn)
	}
	m.conns = make(map[managedCloser]string)
	m.mu.Unlock()
	for _, conn := range snapshot {
		_ = conn.Close()
	}
	return len(snapshot)
}

type trackedConn struct {
	N.ExtendedConn
	manager *userConnManager
	once    sync.Once
	onClose func()
}

func newTrackedConn(conn net.Conn, manager *userConnManager, ip string, onClose func()) net.Conn {
	extended, ok := conn.(N.ExtendedConn)
	if !ok {
		extended = bufio.NewExtendedConn(conn)
	}
	tracked := &trackedConn{
		ExtendedConn: extended,
		manager:      manager,
		onClose:      onClose,
	}
	manager.Add(tracked, ip)
	return tracked
}

func (c *trackedConn) Close() error {
	err := c.ExtendedConn.Close()
	c.once.Do(func() {
		c.manager.Remove(c)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}

type trackedPacketConn struct {
	N.PacketConn
	manager *userConnManager
	once    sync.Once
	onClose func()
}

func newTrackedPacketConn(conn N.PacketConn, manager *userConnManager, onClose func()) N.PacketConn {
	tracked := &trackedPacketConn{
		PacketConn: conn,
		manager:    manager,
		onClose:    onClose,
	}
	manager.Add(tracked, "")
	return tracked
}

func (c *trackedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(func() {
		c.manager.Remove(c)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return err
}
