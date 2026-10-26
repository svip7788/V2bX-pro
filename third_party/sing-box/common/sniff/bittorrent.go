package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	trackerConnectFlag    = 0
	trackerProtocolID     = 0x41727101980
	trackerConnectMinSize = 16
)

// BitTorrent detects if the stream is a BitTorrent connection.
// For the BitTorrent protocol specification, see https://www.bittorrent.org/beps/bep_0003.html
func BitTorrent(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var first byte
	err := binary.Read(reader, binary.BigEndian, &first)
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}

	if first != 19 {
		return os.ErrInvalid
	}

	const header = "BitTorrent protocol"
	var protocol [19]byte
	var n int
	n, err = reader.Read(protocol[:])
	if string(protocol[:n]) != header[:n] {
		return os.ErrInvalid
	}
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}
	if n < 19 {
		return ErrNeedMoreData
	}

	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// UTP detects if the packet is a uTP connection packet.
// For the uTP protocol specification, see
//  1. https://www.bittorrent.org/beps/bep_0029.html
//  2. https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
//
// Only the opening ST_SYN packet is accepted: a looser "version 1, type <= 4" check matches
// WireGuard handshakes (01 00 00 00) and RakNet pings, and a match here bans the user.
func UTP(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if len(packet) < 20 {
		return os.ErrInvalid
	}
	// type 4 (ST_SYN), version 1
	if packet[0] != 0x41 {
		return os.ErrInvalid
	}
	// timestamp_difference is always 0 in new connections
	if binary.BigEndian.Uint32(packet[8:12]) != 0 {
		return os.ErrInvalid
	}
	// Walk the extension chain: selective ack (1) and extension bits (2)
	extension, offset := packet[1], 20
	for extension != 0 {
		if len(packet) < offset+2 {
			return os.ErrInvalid
		}
		length := int(packet[offset+1])
		switch extension {
		case 1:
			if length < 4 || length%4 != 0 {
				return os.ErrInvalid
			}
		case 2:
			if length != 8 {
				return os.ErrInvalid
			}
		default:
			return os.ErrInvalid
		}
		if len(packet) < offset+2+length {
			return os.ErrInvalid
		}
		extension = packet[offset]
		offset += 2 + length
	}
	// ST_SYN carries no payload
	if len(packet) != offset {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// UDPTracker detects if the packet is a UDP Tracker Protocol packet.
// For the UDP Tracker Protocol specification, see https://www.bittorrent.org/beps/bep_0015.html
func UDPTracker(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if !IsUDPTrackerConnect(packet) {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

func IsUDPTrackerConnect(packet []byte) bool {
	return len(packet) >= trackerConnectMinSize &&
		binary.BigEndian.Uint64(packet[:8]) == trackerProtocolID &&
		binary.BigEndian.Uint32(packet[8:12]) == trackerConnectFlag
}

// DHT detects Mainline DHT (KRPC) messages, which stay plaintext even when peer connections use MSE/PE.
// For the DHT protocol specification, see https://www.bittorrent.org/beps/bep_0005.html
func DHT(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if !IsDHTMessage(packet) {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

var (
	dhtQueryPrefix  = []byte("d1:ad2:id20:")
	dhtQueryType    = []byte("1:y1:q")
	dhtResponseBody = []byte("1:rd2:id20:")
	dhtResponseType = []byte("1:y1:r")
)

func IsDHTMessage(packet []byte) bool {
	if len(packet) < 32 || packet[0] != 'd' || packet[len(packet)-1] != 'e' {
		return false
	}
	if bytes.HasPrefix(packet, dhtQueryPrefix) {
		return bytes.Contains(packet, dhtQueryType)
	}
	return bytes.Contains(packet, dhtResponseBody) && bytes.Contains(packet, dhtResponseType)
}

// HTTPTracker detects plaintext HTTP tracker announce/scrape requests (BEP 3 / BEP 48).
func HTTPTracker(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var head [1024]byte
	n, _ := io.ReadFull(reader, head[:])
	ok, needMore := IsHTTPTrackerRequest(head[:n])
	if ok {
		metadata.Protocol = C.ProtocolBitTorrent
		return nil
	}
	if needMore && n < len(head) {
		return ErrNeedMoreData
	}
	return os.ErrInvalid
}

func IsHTTPTrackerRequest(b []byte) (ok bool, needMore bool) {
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
