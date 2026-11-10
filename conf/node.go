package conf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"encoding/json"

	"github.com/InazumaV/V2bX/common/json5"
)

type NodeConfig struct {
	ApiConfig ApiConfig `json:"-"`
	Options   Options   `json:"-"`
}

type rawNodeConfig struct {
	Include string          `json:"Include"`
	ApiRaw  json.RawMessage `json:"ApiConfig"`
	OptRaw  json.RawMessage `json:"Options"`
}

type ApiConfig struct {
	APIHost      string `json:"ApiHost"`
	APISendIP    string `json:"ApiSendIP"`
	NodeID       int    `json:"-"`
	NodeIDs      []int  `json:"-"`
	Key          string `json:"ApiKey"`
	NodeType     string `json:"NodeType"`
	Timeout      int    `json:"Timeout"`
	RuleListPath string `json:"RuleListPath"`
}

type rawApiConfig struct {
	APIHost      string          `json:"ApiHost"`
	APISendIP    string          `json:"ApiSendIP"`
	NodeID       json.RawMessage `json:"NodeID"`
	Key          string          `json:"ApiKey"`
	NodeType     string          `json:"NodeType"`
	Timeout      int             `json:"Timeout"`
	RuleListPath string          `json:"RuleListPath"`
}

func (c *ApiConfig) UnmarshalJSON(data []byte) error {
	raw := rawApiConfig{
		APIHost: c.APIHost,
		Timeout: c.Timeout,
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.APIHost = raw.APIHost
	c.APISendIP = raw.APISendIP
	c.Key = raw.Key
	c.NodeType = raw.NodeType
	c.Timeout = raw.Timeout
	c.RuleListPath = raw.RuleListPath

	nodeIDs, err := parseNodeIDs(raw.NodeID)
	if err != nil {
		return err
	}
	c.SetNodeIDs(nodeIDs)
	return nil
}

func (c *ApiConfig) GetNodeIDs() []int {
	if len(c.NodeIDs) > 0 {
		ids := make([]int, len(c.NodeIDs))
		copy(ids, c.NodeIDs)
		return ids
	}
	if c.NodeID > 0 {
		return []int{c.NodeID}
	}
	return nil
}

func (c *ApiConfig) SetNodeIDs(nodeIDs []int) {
	c.NodeIDs = append([]int(nil), nodeIDs...)
	if len(nodeIDs) == 0 {
		c.NodeID = 0
		return
	}
	c.NodeID = nodeIDs[0]
}

func (n NodeConfig) ExpandedNodes() ([]NodeConfig, error) {
	nodeIDs := n.ApiConfig.GetNodeIDs()
	if len(nodeIDs) == 0 {
		return nil, fmt.Errorf("node id is empty")
	}
	expanded := make([]NodeConfig, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if nodeID <= 0 {
			return nil, fmt.Errorf("invalid node id: %d", nodeID)
		}
		cloned := n
		cloned.ApiConfig.SetNodeIDs([]int{nodeID})
		expanded = append(expanded, cloned)
	}
	return expanded, nil
}

func parseNodeIDs(raw json.RawMessage) ([]int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("parse node id error: %w", err)
	}

	nodeIDs, err := collectNodeIDsFromValue(value)
	if err != nil {
		return nil, err
	}
	return uniqueNodeIDs(nodeIDs)
}

func collectNodeIDsFromValue(value interface{}) ([]int, error) {
	switch v := value.(type) {
	case json.Number:
		nodeID, err := strconv.Atoi(v.String())
		if err != nil {
			return nil, fmt.Errorf("parse node id error: %w", err)
		}
		return []int{nodeID}, nil
	case float64:
		return []int{int(v)}, nil
	case string:
		parts := strings.Split(v, ",")
		nodeIDs := make([]int, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			nodeID, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("parse node id %q error: %w", part, err)
			}
			nodeIDs = append(nodeIDs, nodeID)
		}
		return nodeIDs, nil
	case []interface{}:
		nodeIDs := make([]int, 0, len(v))
		for _, item := range v {
			ids, err := collectNodeIDsFromValue(item)
			if err != nil {
				return nil, err
			}
			nodeIDs = append(nodeIDs, ids...)
		}
		return nodeIDs, nil
	default:
		return nil, fmt.Errorf("unsupported node id type %T", value)
	}
}

func uniqueNodeIDs(nodeIDs []int) ([]int, error) {
	seen := make(map[int]struct{}, len(nodeIDs))
	unique := make([]int, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if nodeID <= 0 {
			return nil, fmt.Errorf("invalid node id: %d", nodeID)
		}
		if _, ok := seen[nodeID]; ok {
			return nil, fmt.Errorf("duplicate node id: %d", nodeID)
		}
		seen[nodeID] = struct{}{}
		unique = append(unique, nodeID)
	}
	return unique, nil
}

func (n *NodeConfig) UnmarshalJSON(data []byte) (err error) {
	rn := rawNodeConfig{}
	err = json.Unmarshal(data, &rn)
	if err != nil {
		return err
	}
	if len(rn.Include) != 0 {
		if strings.HasPrefix(rn.Include, "http://") || strings.HasPrefix(rn.Include, "https://") {
			rsp, err := http.Get(rn.Include)
			if err != nil {
				return fmt.Errorf("fetch include url error: %s", err)
			}
			defer rsp.Body.Close()
			if rsp.StatusCode >= 400 {
				return fmt.Errorf("fetch include url error: status code %d", rsp.StatusCode)
			}
			data, err = io.ReadAll(json5.NewTrimNodeReader(rsp.Body))
			if err != nil {
				return fmt.Errorf("read include url error: %s", err)
			}
		} else {
			f, err := os.Open(rn.Include)
			if err != nil {
				return fmt.Errorf("open include file error: %s", err)
			}
			defer f.Close()
			data, err = io.ReadAll(json5.NewTrimNodeReader(f))
			if err != nil {
				return fmt.Errorf("read include file error: %s", err)
			}
		}
		err = json.Unmarshal(data, &rn)
		if err != nil {
			return fmt.Errorf("unmarshal include file error: %s", err)
		}
	}

	n.ApiConfig = ApiConfig{
		APIHost: "http://127.0.0.1",
		Timeout: 30,
	}
	if len(rn.ApiRaw) > 0 {
		err = json.Unmarshal(rn.ApiRaw, &n.ApiConfig)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.ApiConfig)
		if err != nil {
			return
		}
	}

	n.Options = Options{
		ListenIP:   "0.0.0.0",
		SendIP:     "0.0.0.0",
		CertConfig: NewCertConfig(),
	}
	if len(rn.OptRaw) > 0 {
		err = json.Unmarshal(rn.OptRaw, &n.Options)
		if err != nil {
			return
		}
	} else {
		err = json.Unmarshal(data, &n.Options)
		if err != nil {
			return
		}
	}
	return
}

type Options struct {
	Name                   string          `json:"Name"`
	Core                   string          `json:"Core"`
	CoreName               string          `json:"CoreName"`
	ListenIP               string          `json:"ListenIP"`
	SendIP                 string          `json:"SendIP"`
	DeviceOnlineMinTraffic int64           `json:"DeviceOnlineMinTraffic"`
	ReportMinTraffic       int64           `json:"ReportMinTraffic"`
	LimitConfig            LimitConfig     `json:"LimitConfig"`
	RawOptions             json.RawMessage `json:"RawOptions"`
	XrayOptions            *XrayOptions    `json:"XrayOptions"`
	CertConfig             *CertConfig     `json:"CertConfig"`
}

// legacySingCore 已移除的 sing-box 内核，旧配置里的 sing 一律改用 xray
const legacySingCore = "sing"

func (o *Options) UnmarshalJSON(data []byte) error {
	type opt Options
	err := json.Unmarshal(data, (*opt)(o))
	if err != nil {
		return err
	}
	switch o.Core {
	case "xray", legacySingCore:
		o.Core = "xray"
		o.XrayOptions = NewXrayOptions()
		return json.Unmarshal(data, o.XrayOptions)
	default:
		o.Core = ""
		o.RawOptions = data
	}
	return nil
}
