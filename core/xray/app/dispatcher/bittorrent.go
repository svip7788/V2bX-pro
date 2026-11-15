package dispatcher

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

const (
	trackerConnectFlag    = 0
	trackerProtocolID     = 0x41727101980
	trackerConnectMinSize = 16

	utpWindow        = time.Minute
	utpConfirmHits   = 3
	utpSweepInterval = 5 * time.Minute
)

// isUDPTrackerConnect UDP Tracker Protocol 的 connect 请求（BEP 15）
func isUDPTrackerConnect(packet []byte) bool {
	return len(packet) >= trackerConnectMinSize &&
		binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerConnectFlag
}

var (
	dhtQueryBody    = []byte("1:ad2:id20:")
	dhtQueryType    = []byte("1:y1:q")
	dhtResponseBody = []byte("1:rd2:id20:")
	dhtResponseType = []byte("1:y1:r")
)

// isDHTMessage Mainline DHT（KRPC，BEP 5）消息，peer 连接走 MSE/PE 加密时它仍是明文
func isDHTMessage(packet []byte) bool {
	if len(packet) < 32 || packet[0] != 'd' || packet[len(packet)-1] != 'e' {
		return false
	}
	if bytes.Contains(packet, dhtQueryBody) && bytes.Contains(packet, dhtQueryType) {
		return true
	}
	return bytes.Contains(packet, dhtResponseBody) && bytes.Contains(packet, dhtResponseType)
}

// isHTTPTrackerRequest 明文 HTTP tracker 的 announce/scrape 请求（BEP 3 / BEP 48）
func isHTTPTrackerRequest(b []byte) (ok bool, needMore bool) {
	const method = "GET "
	if len(b) < len(method) {
		return false, bytes.HasPrefix([]byte(method), b)
	}
	if !bytes.HasPrefix(b, []byte(method)) {
		return false, false
	}
	end := bytes.IndexByte(b, '\n')
	if end < 0 {
		return false, len(b) < 4096
	}
	line := b[:end]
	return bytes.Contains(line, []byte("info_hash=")) &&
		(bytes.Contains(line, []byte("peer_id=")) || bytes.Contains(line, []byte("/scrape"))), false
}

// extractHTTPHost 从 HTTP 请求头中提取 Host（不含端口），用于保留 tracker 域名信息
func extractHTTPHost(b []byte) string {
	lines := bytes.Split(b, []byte{'\n'})
	for i := 1; i < len(lines); i++ {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			break
		}
		k, v, found := bytes.Cut(line, []byte{':'})
		if !found || !strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			continue
		}
		host := strings.TrimSpace(string(v))
		if strings.HasPrefix(host, "[") {
			if end := strings.IndexByte(host, ']'); end > 1 {
				return strings.ToLower(host[1:end])
			}
			return ""
		}
		if colon := strings.LastIndexByte(host, ':'); colon > 0 {
			host = host[:colon]
		}
		return strings.ToLower(host)
	}
	return ""
}

// isStrictUTPSyn 在 bittorrent.SniffUTP 基础上追加 BEP 29 ST_SYN 不变量（wnd_size != 0 && ack_nr == 0），降低单包误判
func isStrictUTPSyn(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	wndSize := binary.BigEndian.Uint32(b[12:16])
	ackNr := binary.BigEndian.Uint16(b[18:20])
	return wndSize != 0 && ackNr == 0
}

type utpState struct {
	mu       sync.Mutex
	hits     []time.Time
	lastSeen time.Time
}

var (
	utpUsers     sync.Map
	utpSweepOnce sync.Once
)

// confirmUTP uTP 单包较弱，需同一用户在 1 分钟内连续命中多次才确认 BT 封禁，防止游戏/VOIP 偶发 20 字节碰撞误封号
func confirmUTP(key string) bool {
	return confirmUTPAt(key, time.Now())
}

func confirmUTPAt(key string, now time.Time) bool {
	if key == "" {
		return false
	}
	utpSweepOnce.Do(func() { go sweepUTP() })
	v, _ := utpUsers.LoadOrStore(key, &utpState{})
	s := v.(*utpState)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen = now
	keep := s.hits[:0]
	for _, t := range s.hits {
		if now.Sub(t) < utpWindow {
			keep = append(keep, t)
		}
	}
	s.hits = append(keep, now)
	if len(s.hits) >= utpConfirmHits {
		s.hits = nil
		return true
	}
	return false
}

func sweepUTP() {
	t := time.NewTicker(utpSweepInterval)
	defer t.Stop()
	for now := range t.C {
		utpUsers.Range(func(k, v any) bool {
			s := v.(*utpState)
			s.mu.Lock()
			idle := now.Sub(s.lastSeen) > utpWindow
			s.mu.Unlock()
			if idle {
				utpUsers.Delete(k)
			}
			return true
		})
	}
}
