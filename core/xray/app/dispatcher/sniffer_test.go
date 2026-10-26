package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestSniffBitTorrentSignals(t *testing.T) {
	id := "abcdefghij0123456789"
	cases := []struct {
		name     string
		network  net.Network
		payload  string
		protocol string
	}{
		{"dht query", net.Network_UDP, "d1:ad2:id20:" + id + "9:info_hash20:" + id + "e1:q9:get_peers1:t2:aa1:y1:qe", "bittorrent"},
		{"udp tracker", net.Network_UDP, "\x00\x00\x04\x17\x27\x10\x19\x80\x00\x00\x00\x00\x12\x34\x56\x78", "bittorrent"},
		{"http tracker", net.Network_TCP, "GET /announce?info_hash=%12&peer_id=-TR4050-abcdefghijkl HTTP/1.1\r\nHost: t.example.com\r\n\r\n", "bittorrent"},
		{"plain http", net.Network_TCP, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "http1"},
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
	}
}
