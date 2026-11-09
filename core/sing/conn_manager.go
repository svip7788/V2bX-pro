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

type trackedInfo struct {
	ip      string
	counted bool // 做过设备数检查，计入在线设备
}

type userConnManager struct {
	mu    sync.Mutex
	conns map[managedCloser]trackedInfo
	key   string
	owner *sync.Map
}

func (m *userConnManager) Add(conn managedCloser, ip string, counted bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owner != nil && m.key != "" {
		m.owner.Store(m.key, m)
	}
	if m.conns == nil {
		m.conns = make(map[managedCloser]trackedInfo)
	}
	m.conns[conn] = trackedInfo{ip: ip, counted: counted}
}

// IPs 返回计入在线设备的活跃连接来源 IP（去重）
func (m *userConnManager) IPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ips []string
	seen := make(map[string]struct{}, 1)
	for _, info := range m.conns {
		if !info.counted || info.ip == "" {
			continue
		}
		if _, ok := seen[info.ip]; !ok {
			seen[info.ip] = struct{}{}
			ips = append(ips, info.ip)
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
	return m.CloseMatching(func(string) bool { return true })
}

// CloseMatching 断开来源 IP 满足 match 的连接（含 UDP）
func (m *userConnManager) CloseMatching(match func(ip string) bool) int {
	m.mu.Lock()
	snapshot := make([]managedCloser, 0, len(m.conns))
	for conn, info := range m.conns {
		if match(info.ip) {
			snapshot = append(snapshot, conn)
			delete(m.conns, conn)
		}
	}
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
	manager.Add(tracked, ip, true)
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

func newTrackedPacketConn(conn N.PacketConn, manager *userConnManager, ip string, onClose func()) N.PacketConn {
	tracked := &trackedPacketConn{
		PacketConn: conn,
		manager:    manager,
		onClose:    onClose,
	}
	manager.Add(tracked, ip, false)
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
