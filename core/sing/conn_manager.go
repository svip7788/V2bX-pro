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
	conns map[managedCloser]struct{}
	key   string
	owner *sync.Map
}

func (m *userConnManager) Add(conn managedCloser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owner != nil && m.key != "" {
		m.owner.Store(m.key, m)
	}
	if m.conns == nil {
		m.conns = make(map[managedCloser]struct{})
	}
	m.conns[conn] = struct{}{}
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
	m.conns = make(map[managedCloser]struct{})
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

func newTrackedConn(conn net.Conn, manager *userConnManager, onClose func()) net.Conn {
	extended, ok := conn.(N.ExtendedConn)
	if !ok {
		extended = bufio.NewExtendedConn(conn)
	}
	tracked := &trackedConn{
		ExtendedConn: extended,
		manager:      manager,
		onClose:      onClose,
	}
	manager.Add(tracked)
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
	manager.Add(tracked)
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
