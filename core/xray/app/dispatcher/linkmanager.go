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
	conn    net.Conn
	ip      string // 来源 IP，踢超限设备时按它断开
	counted bool   // 做过设备数检查，计入在线设备
}

type LinkManager struct {
	links map[*ManagedWriter]managedLink
	mu    sync.Mutex
	key   string
	owner *sync.Map
}

// AddLink 登记连接；limit > 0 且已有连接数达到 limit 时不登记，返回 false
func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, conn net.Conn, ip string, counted bool, limit int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit > 0 && len(m.links) >= limit {
		return false
	}
	if m.owner != nil && len(m.key) > 0 {
		m.owner.Store(m.key, m)
	}
	m.links[writer] = managedLink{reader: reader, conn: conn, ip: ip, counted: counted}
	return true
}

// IPs 返回计入在线设备的活跃连接来源 IP（去重）
func (m *LinkManager) IPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ips []string
	seen := make(map[string]struct{}, 1)
	for _, l := range m.links {
		if !l.counted || l.ip == "" {
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
	closeLinks(snapshot)
	return len(snapshot)
}

// CloseMatching 断开来源 IP 满足 match 的连接
func (m *LinkManager) CloseMatching(match func(ip string) bool) int {
	m.mu.Lock()
	snapshot := make(map[*ManagedWriter]managedLink)
	for w, l := range m.links {
		if l.ip != "" && match(l.ip) {
			snapshot[w] = l
			delete(m.links, w)
		}
	}
	m.mu.Unlock()
	closeLinks(snapshot)
	return len(snapshot)
}

func closeLinks(links map[*ManagedWriter]managedLink) {
	for w, l := range links {
		common.Close(w)
		common.Interrupt(l.reader)
		if l.conn != nil {
			_ = l.conn.Close()
		}
	}
}
