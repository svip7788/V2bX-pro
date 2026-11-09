package dispatcher

import (
	"net"
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer  buf.Writer
	manager *LinkManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

type managedLink struct {
	reader buf.Reader
	// DispatchLink（如 VLESS）的读写端直接包着客户端连接，既不可中断也不可关闭，
	// 必须关掉原始连接才能让会话立即结束。
	conn net.Conn
	ip   string // 做过设备数检查的来源 IP，其余为空
}

type LinkManager struct {
	links map[*ManagedWriter]managedLink
	mu    sync.Mutex
	key   string
	owner *sync.Map
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, conn net.Conn, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.owner != nil && len(m.key) > 0 {
		m.owner.Store(m.key, m)
	}
	m.links[writer] = managedLink{reader: reader, conn: conn, ip: ip}
}

// IPs 返回活跃连接的来源 IP（去重）
func (m *LinkManager) IPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ips []string
	seen := make(map[string]struct{}, 1)
	for _, l := range m.links {
		if l.ip == "" {
			continue
		}
		if _, ok := seen[l.ip]; !ok {
			seen[l.ip] = struct{}{}
			ips = append(ips, l.ip)
		}
	}
	return ips
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	delete(m.links, writer)
	empty := len(m.links) == 0
	m.mu.Unlock()
	if empty && m.owner != nil && len(m.key) > 0 {
		m.owner.CompareAndDelete(m.key, m)
	}
}

func (m *LinkManager) markOwner(key string, owner *sync.Map) {
	m.mu.Lock()
	m.key = key
	m.owner = owner
	m.mu.Unlock()
}

func (m *LinkManager) CloseAll() int {
	m.mu.Lock()
	snapshot := m.links
	m.links = make(map[*ManagedWriter]managedLink)
	m.mu.Unlock()
	for w, l := range snapshot {
		common.Close(w)
		common.Interrupt(l.reader)
		if l.conn != nil {
			_ = l.conn.Close()
		}
	}
	return len(snapshot)
}
