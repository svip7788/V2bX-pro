// Package livelog 后台「实时连接」：只对正在被管理员查看的用户记录连接的目标与字节数，
// 每秒批量经机器 WS 推给面板，进程内不落盘；无人查看时热路径只有一次原子读。
package livelog

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	flushInterval = time.Second
	maxBatch      = 300
	maxTTL        = 10 * time.Minute

	EventName = "machine.live.event"
)

type Event struct {
	ID    uint64 `json:"id"`
	Kind  string `json:"k"` // open / close
	Time  int64  `json:"t"` // unix ms
	Node  int    `json:"node"`
	Net   string `json:"net"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto,omitempty"`
	Out   string `json:"out,omitempty"`
	Up    int64  `json:"up,omitempty"`
	Down  int64  `json:"down,omitempty"`
	Dur   int64  `json:"dur,omitempty"` // ms
}

type SendFunc func(event string, data any)

type session struct {
	sid     string
	prefix  string
	uid     int
	send    SendFunc
	expires atomic.Int64

	mu      sync.Mutex
	buf     []Event
	dropped int
}

var (
	active   atomic.Int32
	mu       sync.RWMutex
	sessions = map[string]*session{}
	nextID   atomic.Uint64
	loopOnce sync.Once
)

// Enabled 热路径快速判断：没有任何会话时直接返回 false
func Enabled() bool { return active.Load() > 0 }

// Watch 开始或续约一个会话；prefix 是节点 tag 前缀（区分同进程内的多个面板）
func Watch(sid, prefix string, uid int, ttl time.Duration, send SendFunc) {
	if sid == "" || uid <= 0 || send == nil {
		return
	}
	ttl = min(max(ttl, 30*time.Second), maxTTL)
	mu.Lock()
	s, ok := sessions[sid]
	if !ok {
		s = &session{sid: sid, prefix: prefix, uid: uid, send: send}
		sessions[sid] = s
		active.Store(int32(len(sessions)))
	}
	mu.Unlock()
	s.expires.Store(time.Now().Add(ttl).UnixNano())
	loopOnce.Do(func() { go loop() })
}

func Stop(sid string) {
	mu.Lock()
	delete(sessions, sid)
	active.Store(int32(len(sessions)))
	mu.Unlock()
}

func watchers(tag string, uid int) []*session {
	mu.RLock()
	defer mu.RUnlock()
	var out []*session
	for _, s := range sessions {
		if s.uid == uid && strings.HasPrefix(tag, s.prefix) {
			out = append(out, s)
		}
	}
	return out
}

// Conn 一条被记录的连接；nil 安全
type Conn struct {
	sessions []*session
	ev       Event
	start    time.Time
	up, down atomic.Int64
	closed   atomic.Bool
}

// Open 用户被查看时记录连接建立并返回 Conn，否则返回 nil
func Open(tag string, uid int, network, host string, port uint16, proto, out string) *Conn {
	if !Enabled() || uid <= 0 {
		return nil
	}
	ss := watchers(tag, uid)
	if len(ss) == 0 {
		return nil
	}
	now := time.Now()
	c := &Conn{sessions: ss, start: now, ev: Event{
		ID:    nextID.Add(1),
		Kind:  "open",
		Time:  now.UnixMilli(),
		Node:  NodeID(tag),
		Net:   network,
		Host:  host,
		Port:  port,
		Proto: proto,
		Out:   out,
	}}
	c.emit(c.ev)
	return c
}

func (c *Conn) AddUp(n int64) {
	if c != nil && n > 0 {
		c.up.Add(n)
	}
}

func (c *Conn) AddDown(n int64) {
	if c != nil && n > 0 {
		c.down.Add(n)
	}
}

func (c *Conn) Close() {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return
	}
	ev := c.ev
	now := time.Now()
	ev.Kind = "close"
	ev.Time = now.UnixMilli()
	ev.Up = c.up.Load()
	ev.Down = c.down.Load()
	ev.Dur = now.Sub(c.start).Milliseconds()
	c.emit(ev)
}

func (c *Conn) emit(ev Event) {
	for _, s := range c.sessions {
		s.mu.Lock()
		if len(s.buf) < maxBatch*3 {
			s.buf = append(s.buf, ev)
		} else {
			s.dropped++
		}
		s.mu.Unlock()
	}
}

// NodeID 从 "[host]-type:id" 形式的节点 tag 取节点 id
func NodeID(tag string) int {
	i := strings.LastIndexByte(tag, ':')
	if i < 0 {
		return 0
	}
	id, _ := strconv.Atoi(tag[i+1:])
	return id
}

func loop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for range t.C {
		now := time.Now().UnixNano()
		mu.Lock()
		list := make([]*session, 0, len(sessions))
		for sid, s := range sessions {
			if now > s.expires.Load() {
				delete(sessions, sid)
				continue
			}
			list = append(list, s)
		}
		active.Store(int32(len(sessions)))
		mu.Unlock()
		for _, s := range list {
			s.flush()
		}
	}
}

func (s *session) flush() {
	s.mu.Lock()
	if len(s.buf) == 0 && s.dropped == 0 {
		s.mu.Unlock()
		return
	}
	n := min(len(s.buf), maxBatch)
	events := append([]Event(nil), s.buf[:n]...)
	s.buf = append(s.buf[:0], s.buf[n:]...)
	dropped := s.dropped
	s.dropped = 0
	s.mu.Unlock()
	s.send(EventName, map[string]any{"sid": s.sid, "events": events, "dropped": dropped})
}
