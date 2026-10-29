// Package violation 收集节点检测到的用户违规（BT、SSH 爆破）并批量上报面板，面板收到即封号
package violation

import (
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	KindBT  = "bt"
	KindSSH = "ssh"

	flushInterval = 3 * time.Second
	dedupeTTL     = 10 * time.Minute
	maxPending    = 500
)

type Item struct {
	UID    int    `json:"uid"`
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Sink 把一批违规发给面板；返回错误时这批会在下次重试
type Sink func([]Item) error

type queue struct {
	sink    Sink
	pending []Item
}

var (
	mu        sync.Mutex
	queues    = map[string]*queue{}
	seen      = map[string]time.Time{}
	startOnce sync.Once
)

// Register 节点启动后注册其上报通道；重复注册覆盖旧的
func Register(tag string, sink Sink) {
	mu.Lock()
	if q, ok := queues[tag]; ok {
		q.sink = sink
	} else {
		queues[tag] = &queue{sink: sink}
	}
	mu.Unlock()
	startOnce.Do(func() { go loop() })
}

func Unregister(tag string) {
	mu.Lock()
	delete(queues, tag)
	mu.Unlock()
}

// Report 记录一次违规；同一节点同一用户同类违规 10 分钟内只报一次
func Report(tag string, it Item) {
	if it.UID <= 0 {
		return
	}
	key := tag + "|" + strconv.Itoa(it.UID) + "|" + it.Kind
	now := time.Now()
	mu.Lock()
	defer mu.Unlock()
	q, ok := queues[tag]
	if !ok {
		return
	}
	if t, ok := seen[key]; ok && now.Sub(t) < dedupeTTL {
		return
	}
	seen[key] = now
	if len(q.pending) < maxPending {
		q.pending = append(q.pending, it)
	}
}

func loop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for range t.C {
		flush()
	}
}

func flush() {
	type job struct {
		tag   string
		sink  Sink
		items []Item
	}
	var jobs []job
	now := time.Now()
	mu.Lock()
	for tag, q := range queues {
		if len(q.pending) > 0 && q.sink != nil {
			jobs = append(jobs, job{tag, q.sink, q.pending})
			q.pending = nil
		}
	}
	for k, t := range seen {
		if now.Sub(t) >= dedupeTTL {
			delete(seen, k)
		}
	}
	mu.Unlock()

	for _, j := range jobs {
		if err := j.sink(j.items); err != nil {
			log.WithFields(log.Fields{"tag": j.tag, "count": len(j.items), "err": err}).Warn("Report violations failed, will retry")
			mu.Lock()
			if q, ok := queues[j.tag]; ok && len(q.pending)+len(j.items) <= maxPending {
				q.pending = append(j.items, q.pending...)
			}
			mu.Unlock()
			continue
		}
		log.WithFields(log.Fields{"tag": j.tag, "count": len(j.items)}).Info("Reported violations to panel")
	}
}
