package dispatcher

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestSniffBitTorrentSignals(t *testing.T) {
	id := "abcdefghij0123456789"
	cases := []struct {
		name     string
		network  net.Network
		payload  string
		protocol string
		domain   string
		weakBT   bool
	}{
		{"dht query", net.Network_UDP, "d1:ad2:id20:" + id + "9:info_hash20:" + id + "e1:q9:get_peers1:t2:aa1:y1:qe", "bittorrent", "", false},
		{"dht non-canonical order", net.Network_UDP, "d1:t2:aa1:y1:q1:q9:get_peers1:ad2:id20:" + id + "9:info_hash20:" + id + "ee", "bittorrent", "", false},
		{"udp tracker", net.Network_UDP, "\x00\x00\x04\x17\x27\x10\x19\x80\x00\x00\x00\x00\x12\x34\x56\x78", "bittorrent", "", false},
		{"http tracker", net.Network_TCP, "GET /announce?info_hash=%12&peer_id=-TR4050-abcdefghijkl HTTP/1.1\r\nHost: t.example.com:6969\r\n\r\n", "bittorrent", "t.example.com", false},
		{"http proxy tracker", net.Network_TCP, "GET http://tracker.example.org:1337/announce?info_hash=%12&peer_id=-TR4050-abcdefghijkl HTTP/1.1\r\nHost: tracker.example.org:1337\r\n\r\n", "bittorrent", "tracker.example.org", false},
		{"plain http", net.Network_TCP, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "http1", "example.com", false},
	}
	for _, c := range cases {
		s := &Sniffer{sniffer: contentSniffers()}
		result, err := s.Sniff(context.Background(), []byte(c.payload), c.network)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", c.name, err)
		}
		if result.Protocol() != c.protocol {
			t.Fatalf("%s: protocol = %s, want %s", c.name, result.Protocol(), c.protocol)
		}
		if c.domain != "" && result.Domain() != c.domain {
			t.Fatalf("%s: domain = %s, want %s", c.name, result.Domain(), c.domain)
		}
		if isWeakBitTorrent(result) != c.weakBT {
			t.Fatalf("%s: weakBT = %v, want %v", c.name, isWeakBitTorrent(result), c.weakBT)
		}
	}
}

func makeUTPSyn(wnd uint32, ack uint16) []byte {
	b := make([]byte, 20)
	b[0] = 0x41
	binary.BigEndian.PutUint16(b[2:4], 0x1234)
	binary.BigEndian.PutUint32(b[4:8], 0x8c3a91d2)
	binary.BigEndian.PutUint32(b[12:16], wnd)
	binary.BigEndian.PutUint16(b[16:18], 1)
	binary.BigEndian.PutUint16(b[18:20], ack)
	return b
}

func TestSniffStrictUTPAndConfirmation(t *testing.T) {
	s := &Sniffer{sniffer: contentSniffers()}
	res, err := s.Sniff(context.Background(), makeUTPSyn(0x00100000, 0), net.Network_UDP)
	if err != nil {
		t.Fatalf("valid uTP ST_SYN failed: %v", err)
	}
	if res.Protocol() != "bittorrent" || !isWeakBitTorrent(res) {
		t.Fatalf("expected weak bittorrent for uTP, got proto=%s weak=%v", res.Protocol(), isWeakBitTorrent(res))
	}

	// 非零 ack_nr 或零 wnd_size 的 20 字节包不应被误判为 uTP
	for _, bad := range [][]byte{makeUTPSyn(0x00100000, 1), makeUTPSyn(0, 0)} {
		s := &Sniffer{sniffer: contentSniffers()}
		if r, err := s.Sniff(context.Background(), bad, net.Network_UDP); err == nil {
			t.Fatalf("expected non-uTP packet rejected, got %s", r.Protocol())
		}
	}

	now := time.Now()
	if confirmUTPAt("u-utp", now) || confirmUTPAt("u-utp", now.Add(10*time.Second)) {
		t.Fatal("should not confirm before threshold")
	}
	if !confirmUTPAt("u-utp", now.Add(20*time.Second)) {
		t.Fatal("third hit within window should confirm")
	}
	// 确认后计数重置，且超过窗口的旧记录会过期
	if confirmUTPAt("u-utp", now.Add(25*time.Second)) {
		t.Fatal("should reset after confirmation")
	}
	if confirmUTPAt("u-utp", now.Add(25*time.Second+utpWindow+time.Second)) {
		t.Fatal("expired hit should not count")
	}
}

func TestEffectiveProtocolUnwrapsFakeDNS(t *testing.T) {
	r := DNSThenOthersSniffResult{
		domainName:           "example.com",
		protocolOriginalName: "bittorrent",
		weakBT:               true,
	}
	if r.Protocol() != "fakedns+others" {
		t.Fatalf("unexpected Protocol: %s", r.Protocol())
	}
	if effectiveProtocol(r) != "bittorrent" || !isWeakBitTorrent(r) {
		t.Fatalf("unwrap failed: proto=%s weak=%v", effectiveProtocol(r), isWeakBitTorrent(r))
	}
	comp := CompositeResult(fakeDNSSniffResult{domainName: "example.com"}, utpSniffResult{})
	if effectiveProtocol(comp) != "bittorrent" || !isWeakBitTorrent(comp) {
		t.Fatalf("composite unwrap failed: proto=%s weak=%v", effectiveProtocol(comp), isWeakBitTorrent(comp))
	}
}
