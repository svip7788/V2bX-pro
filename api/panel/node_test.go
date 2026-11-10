package panel

import (
	"context"
	"log"
	"testing"

	"github.com/InazumaV/V2bX/conf"
)

var client *Client

func init() {
	c, err := New(&conf.ApiConfig{
		APIHost:  "http://127.0.0.1",
		Key:      "token",
		NodeType: "V2ray",
		NodeID:   1,
	})
	if err != nil {
		log.Panic(err)
	}
	client = c
}

func TestClient_GetNodeInfo(t *testing.T) {
	log.Println(client.GetNodeInfo(context.Background()))
	log.Println(client.GetNodeInfo(context.Background()))
}

func TestClient_ReportUserTraffic(t *testing.T) {
	log.Println(client.ReportUserTraffic(context.Background(), []UserTraffic{
		{
			UID:      10372,
			Upload:   1000,
			Download: 1000,
		},
	}))
}

func TestCoreConfigHashIgnoresHotReloadKeys(t *testing.T) {
	a := coreConfigHash([]byte(`{"server_port":443,"ip_watch":{"enable":true,"targets":["ip.sb"]},"dynamic_speed_limit":{"enable":true}}`))
	b := coreConfigHash([]byte(`{"dynamic_speed_limit":{"enable":false},"server_port":443,"ip_watch":{"enable":false},"conn_limit":100}`))
	c := coreConfigHash([]byte(`{"server_port":8443,"ip_watch":{"enable":true,"targets":["ip.sb"]}}`))
	if a == "" || a != b {
		t.Fatalf("hot reload keys should not change core hash: %q %q", a, b)
	}
	if a == c {
		t.Fatal("core field change must change core hash")
	}
	if coreConfigHash([]byte(`not json`)) != "" {
		t.Fatal("invalid body should return empty hash")
	}
}
