package panel

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/InazumaV/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// MachineNode 面板下发的机器节点
type MachineNode struct {
	ID       int    `json:"id"`
	Type     string `json:"type"`
	NodeType string `json:"node_type"`
	Name     string `json:"name"`
	// 节点入站接受 PROXY protocol，前置中转透传用户真实 IP
	ProxyProtocol bool `json:"proxy_protocol"`
}

type MachineBaseConfig struct {
	PushInterval int `json:"push_interval"`
	PullInterval int `json:"pull_interval"`
}

type MachineNodesResponse struct {
	Nodes      []MachineNode     `json:"nodes"`
	BaseConfig MachineBaseConfig `json:"base_config"`
}

type MachineStatus struct {
	CPU  float64 `json:"cpu"`
	Mem  Usage   `json:"mem"`
	Swap Usage   `json:"swap"`
	Disk Usage   `json:"disk"`
	Net  *struct {
		InSpeed  float64 `json:"in_speed"`
		OutSpeed float64 `json:"out_speed"`
	} `json:"net,omitempty"`
	V2bX struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	} `json:"v2bx"`
}

type Usage struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// MachineClient 机器级接口：节点列表、负载上报、握手、WS
type MachineClient struct {
	client    *resty.Client
	apiHost   string
	machineID int
	token     string
}

func (c *MachineClient) APIHost() string { return c.apiHost }

func NewMachineClient(c *conf.MachineConfig) (*MachineClient, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("machine config incomplete")
	}
	client := newRestyClient(&conf.ApiConfig{
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		Timeout:   c.Timeout,
	})
	client.SetQueryParams(map[string]string{
		"machine_id": strconv.Itoa(c.MachineID),
		"token":      c.Token,
	})
	return &MachineClient{
		client:    client,
		apiHost:   c.APIHost,
		machineID: c.MachineID,
		token:     c.Token,
	}, nil
}

func (m *MachineClient) post(path string, body any, out any) error {
	req := m.client.R().ForceContentType("application/json")
	if body != nil {
		req.SetBody(body)
	}
	r, err := req.Post(path)
	if err != nil {
		return fmt.Errorf("request %s failed: %w", m.apiHost+path, err)
	}
	if r.StatusCode() >= 400 {
		return fmt.Errorf("request %s failed: %d %s", m.apiHost+path, r.StatusCode(), string(r.Body()))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(r.Body(), out); err != nil {
		return fmt.Errorf("decode %s response error: %w", path, err)
	}
	return nil
}

func (m *MachineClient) FetchNodes() (*MachineNodesResponse, error) {
	var resp MachineNodesResponse
	if err := m.post("/api/v2/server/machine/nodes", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *MachineClient) ReportStatus(s *MachineStatus) error {
	return m.post("/api/v2/server/machine/status", s, nil)
}

func (m *MachineClient) Handshake() (*HandshakeResponse, error) {
	var resp HandshakeResponse
	if err := m.post("/api/v2/server/handshake", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// NewWSClient 建立机器级 WS 连接，所有节点共用
func (m *MachineClient) NewWSClient(wsURL string) (*WSClient, error) {
	return startWSClient(wsURL, &WSClient{
		stopCh:    make(chan struct{}),
		eventCh:   make(chan WSEvent, 256),
		apiHost:   m.apiHost,
		token:     m.token,
		machineID: m.machineID,
	})
}
