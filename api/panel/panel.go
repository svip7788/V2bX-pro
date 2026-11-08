package panel

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/InazumaV/V2bX/conf"
	"github.com/go-resty/resty/v2"
)

// Panel is the interface for different panel's api.

type Client struct {
	client                    *resty.Client
	APIHost                   string
	APISendIP                 string
	Token                     string
	NodeType                  string
	NodeId                    int
	nodeEtag                  string
	userEtag                  string
	userVer                   string // 面板增量同步的版本，空表示面板不支持或需要全量
	userListAt                time.Time
	responseBodyHash          string
	UserList                  *UserListBody
	AliveMap                  *AliveMap
	nowFunc                   func() time.Time
	userListForceRefreshAfter time.Duration
	lastUserListFullFetchAt   time.Time
	// >0 时为机器模式：以 machine_id + 机器 token 鉴权并走 /api/v2/server/*
	MachineID int
}

const (
	defaultUserListForceRefreshAfter = 5 * time.Minute
	// 增量同步下差异可校验人数，长时间才兜底拉一次全量
	deltaUserListForceRefreshAfter = 6 * time.Hour
)

// NewMachineNode 创建机器模式下单个节点的客户端，c.Key 为机器 token
func NewMachineNode(c *conf.ApiConfig, machineID int) (*Client, error) {
	if machineID <= 0 {
		return nil, fmt.Errorf("invalid machine id: %d", machineID)
	}
	client, err := New(c)
	if err != nil {
		return nil, err
	}
	client.MachineID = machineID
	client.client.QueryParam.Del("node_type")
	client.client.SetQueryParam("machine_id", strconv.Itoa(machineID))
	return client, nil
}

// apiPath 机器模式下把 V1 UniProxy 路径映射到 V2 路径
func (c *Client) apiPath(v1Path string) string {
	if c.MachineID <= 0 {
		return v1Path
	}
	return "/api/v2/server/" + v1Path[strings.LastIndex(v1Path, "/")+1:]
}

// UserAgent 面板常挂宝塔 WAF，Go 默认 UA 在其黑名单里，WS 握手会被拦截并封 IP
var UserAgent = "V2bX"

func newRestyClient(c *conf.ApiConfig) *resty.Client {
	var client *resty.Client
	if c.APISendIP != "" {
		client = resty.NewWithLocalAddr(&net.TCPAddr{
			IP: net.ParseIP(c.APISendIP),
		})
	} else {
		client = resty.New()
	}
	client.SetHeader("User-Agent", UserAgent)
	// Do not auto-retry panel requests. Traffic report APIs are POST and
	// not guaranteed to be idempotent, so retries can duplicate usage.
	if c.Timeout > 0 {
		client.SetTimeout(time.Duration(c.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		var v *resty.ResponseError
		if errors.As(err, &v) {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			logrus.Error(v.Err)
		}
	})
	client.SetBaseURL(c.APIHost)
	return client
}

func New(c *conf.ApiConfig) (*Client, error) {
	client := newRestyClient(c)
	// Check node type
	c.NodeType = strings.ToLower(c.NodeType)
	switch c.NodeType {
	case "v2ray":
		c.NodeType = "vmess"
	case
		"vmess",
		"trojan",
		"shadowsocks",
		"hysteria",
		"hysteria2",
		"tuic",
		"anytls",
		"vless":
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}
	// set params
	client.SetQueryParams(map[string]string{
		"node_type": c.NodeType,
		"node_id":   strconv.Itoa(c.NodeID),
		"token":     c.Key,
	})
	return &Client{
		client:    client,
		Token:     c.Key,
		APIHost:   c.APIHost,
		APISendIP: c.APISendIP,
		NodeType:  c.NodeType,
		NodeId:    c.NodeID,
		UserList:  &UserListBody{},
		AliveMap:  &AliveMap{},
	}, nil
}

func (c *Client) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

func (c *Client) userListRefreshInterval() time.Duration {
	if c.userListForceRefreshAfter > 0 {
		return c.userListForceRefreshAfter
	}
	if c.userVer != "" {
		return deltaUserListForceRefreshAfter
	}
	return defaultUserListForceRefreshAfter
}
