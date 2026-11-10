package dispatcher

import (
	"bytes"
	"encoding/binary"
)

const (
	trackerConnectFlag    = 0
	trackerProtocolID     = 0x41727101980
	trackerConnectMinSize = 16
)

// isUDPTrackerConnect UDP Tracker Protocol 的 connect 请求（BEP 15）
func isUDPTrackerConnect(packet []byte) bool {
	return len(packet) >= trackerConnectMinSize &&
		binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerConnectFlag
}

var (
	dhtQueryPrefix  = []byte("d1:ad2:id20:")
	dhtQueryType    = []byte("1:y1:q")
	dhtResponseBody = []byte("1:rd2:id20:")
	dhtResponseType = []byte("1:y1:r")
)

// isDHTMessage Mainline DHT（KRPC，BEP 5）消息，peer 连接走 MSE/PE 加密时它仍是明文
func isDHTMessage(packet []byte) bool {
	if len(packet) < 32 || packet[0] != 'd' || packet[len(packet)-1] != 'e' {
		return false
	}
	if bytes.HasPrefix(packet, dhtQueryPrefix) {
		return bytes.Contains(packet, dhtQueryType)
	}
	return bytes.Contains(packet, dhtResponseBody) && bytes.Contains(packet, dhtResponseType)
}

// isHTTPTrackerRequest 明文 HTTP tracker 的 announce/scrape 请求（BEP 3 / BEP 48）
func isHTTPTrackerRequest(b []byte) (ok bool, needMore bool) {
	const method = "GET /"
	if len(b) < len(method) {
		return false, bytes.HasPrefix([]byte(method), b)
	}
	if !bytes.HasPrefix(b, []byte(method)) {
		return false, false
	}
	end := bytes.IndexByte(b, '\n')
	if end < 0 {
		return false, true
	}
	line := b[:end]
	return bytes.Contains(line, []byte("info_hash=")) &&
		(bytes.Contains(line, []byte("peer_id=")) || bytes.Contains(line, []byte("/scrape"))), false
}
