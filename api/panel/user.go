package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"encoding/json/jsontext"
	"encoding/json/v2"

	"github.com/vmihailenco/msgpack/v5"
)

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id          int    `json:"id" msgpack:"id"`
	Uuid        string `json:"uuid" msgpack:"uuid"`
	SpeedLimit  int    `json:"speed_limit" msgpack:"speed_limit"`
	DeviceLimit int    `json:"device_limit" msgpack:"device_limit"`
}

type UserListBody struct {
	Users []UserInfo `json:"users" msgpack:"users"`
}

// userListResp 面板增量同步的响应：全量带 users；差异带 delta、add、remove，total 为合并后应有的人数
type userListResp struct {
	Ver    string
	Age    int // 快照距今秒数
	Delta  bool
	Total  int
	Users  []UserInfo
	Add    []UserInfo
	Remove []int
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
	// DeviceIPv4Prefix 设备计数时 IPv4 归并前缀，与面板一致；老面板不下发为 0
	DeviceIPv4Prefix int `json:"device_ipv4_prefix"`
	// Excess 同 WSDevicesData.Excess
	Excess map[int][]string `json:"excess"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	path := c.apiPath("/api/v1/server/UniProxy/user")
	req := c.client.R().
		SetContext(ctx).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true)
	fresh := c.UserList != nil && !c.lastUserListFullFetchAt.IsZero() &&
		c.now().Sub(c.lastUserListFullFetchAt) < c.userListRefreshInterval()
	// 带 ver 即声明支持增量同步，0 表示要全量；老面板不认识会忽略，照旧按 ETag 返回全量
	ver := ""
	if fresh {
		ver = c.userVer
	}
	if ver == "" {
		req.SetQueryParam("ver", "0")
	} else {
		req.SetQueryParam("ver", ver)
	}
	if fresh && c.userEtag != "" {
		req.SetHeader("If-None-Match", c.userEtag)
	}
	sentAt := c.now()
	r, err := req.Get(path)
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	defer r.RawResponse.Body.Close()

	if r.StatusCode() == 304 {
		return nil, nil
	}

	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}
	resp := &userListResp{}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		userlist := &UserListBody{Users: []UserInfo{}}
		if err := msgpack.NewDecoder(r.RawResponse.Body).Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		resp.Users = userlist.Users
	} else if err := decodeUserListJSON(r.RawResponse.Body, resp); err != nil {
		return nil, fmt.Errorf("decode user list error: %w", err)
	}
	snapshotAt := sentAt.Add(-time.Duration(resp.Age) * time.Second)

	if resp.Delta {
		if ver == "" {
			return nil, fmt.Errorf("decode user list error: unexpected delta without base version")
		}
		users := applyUserDelta(c.UserList.Users, resp.Add, resp.Remove)
		if len(users) != resp.Total {
			// 本地快照与面板对不上，下次取全量重新对齐
			c.userVer = ""
			return nil, fmt.Errorf("user list delta mismatch: have %d users, panel has %d", len(users), resp.Total)
		}
		c.userVer = resp.Ver
		c.userListAt = snapshotAt
		c.UserList = &UserListBody{Users: users}
		return users, nil
	}
	if resp.Users == nil {
		resp.Users = []UserInfo{}
	}
	c.userVer = resp.Ver
	c.userListAt = snapshotAt
	c.userEtag = r.Header().Get("ETag")
	c.lastUserListFullFetchAt = c.now()
	c.UserList = &UserListBody{Users: resp.Users}
	return resp.Users, nil
}

// UserListAt 最近一次取到的用户列表对应的时刻（按本地时钟折算）
func (c *Client) UserListAt() time.Time {
	return c.userListAt
}

// decodeUserListJSON 流式解析，用户列表可能有数十万条，避免整体反序列化的峰值内存
func decodeUserListJSON(body io.Reader, resp *userListResp) error {
	dec := jsontext.NewDecoder(body)
	if tok, err := dec.ReadToken(); err != nil {
		return err
	} else if tok.Kind() != '{' {
		return fmt.Errorf("expected object")
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		switch key := tok.String(); key {
		case "users", "add":
			list, err := decodeUserArray(dec)
			if err != nil {
				return fmt.Errorf("read %s: %w", key, err)
			}
			if key == "users" {
				resp.Users = list
			} else {
				resp.Add = list
			}
		case "remove", "ver", "age", "delta", "total":
			val, err := dec.ReadValue()
			if err != nil {
				return err
			}
			var dst any
			switch key {
			case "remove":
				dst = &resp.Remove
			case "ver":
				dst = &resp.Ver
			case "age":
				dst = &resp.Age
			case "delta":
				dst = &resp.Delta
			default:
				dst = &resp.Total
			}
			if err := json.Unmarshal(val, dst); err != nil {
				return fmt.Errorf("read %s: %w", key, err)
			}
		default:
			if err := dec.SkipValue(); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeUserArray(dec *jsontext.Decoder) ([]UserInfo, error) {
	if tok, err := dec.ReadToken(); err != nil {
		return nil, err
	} else if tok.Kind() != '[' {
		return nil, fmt.Errorf("expected array")
	}
	users := []UserInfo{}
	for dec.PeekKind() != ']' {
		val, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		var u UserInfo
		if err := json.Unmarshal(val, &u); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	_, err := dec.ReadToken()
	return users, err
}

// applyUserDelta 返回新切片，不改动 base（base 可能仍被调用方持有）
func applyUserDelta(base, add []UserInfo, remove []int) []UserInfo {
	drop := make(map[int]struct{}, len(remove)+len(add))
	for _, id := range remove {
		drop[id] = struct{}{}
	}
	for _, u := range add {
		drop[u.Id] = struct{}{}
	}
	out := make([]UserInfo, 0, len(base)+len(add))
	for _, u := range base {
		if _, ok := drop[u.Id]; !ok {
			out = append(out, u)
		}
	}
	return append(out, add...)
}

// GetUserAlive will fetch the alive_ip count for users
func (c *Client) GetUserAlive(ctx context.Context) (map[int]int, error) {
	c.AliveMap = &AliveMap{}
	path := c.apiPath("/api/v1/server/UniProxy/alivelist")
	r, err := c.client.R().
		SetContext(ctx).
		ForceContentType("application/json").
		Get(path)
	if err != nil {
		return nil, fmt.Errorf("request user alive list error: %w", err)
	}
	if r == nil || r.RawResponse == nil {
		return nil, fmt.Errorf("received nil response or raw response")
	}
	if r.StatusCode() >= 399 {
		return nil, fmt.Errorf("request user alive list failed: status code %d", r.StatusCode())
	}
	defer r.RawResponse.Body.Close()
	if err := json.Unmarshal(r.Body(), c.AliveMap); err != nil {
		return nil, fmt.Errorf("unmarshal user alive list error: %w", err)
	}
	if c.AliveMap.Alive == nil {
		c.AliveMap.Alive = make(map[int]int)
	}

	return c.AliveMap.Alive, nil
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// ReportUserTraffic reports the user traffic
func (c *Client) ReportUserTraffic(ctx context.Context, userTraffic []UserTraffic) error {
	data := make(map[int][]int64, len(userTraffic))
	for i := range userTraffic {
		uid := userTraffic[i].UID
		if existing, ok := data[uid]; ok {
			existing[0] += userTraffic[i].Upload
			existing[1] += userTraffic[i].Download
		} else {
			data[uid] = []int64{userTraffic[i].Upload, userTraffic[i].Download}
		}
	}
	path := c.apiPath("/api/v1/server/UniProxy/push")
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}

// ReportViolations 上报违规用户（BT、SSH 爆破），面板收到即封号
func (c *Client) ReportViolations(ctx context.Context, items any) error {
	path := c.apiPath("/api/v1/server/UniProxy/violation")
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(items).
		ForceContentType("application/json").
		Post(path)
	return c.checkResponse(r, path, err)
}

func (c *Client) ReportNodeOnlineUsers(ctx context.Context, data *map[int][]string) error {
	path := c.apiPath("/api/v1/server/UniProxy/alive")
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(data).
		ForceContentType("application/json").
		Post(path)
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}

type ReportRequest struct {
	Traffic map[int][]int64  `json:"traffic,omitempty"`
	Alive   map[int][]string `json:"alive,omitempty"`
}

type UnsupportedReportError struct {
	URL        string
	StatusCode int
}

func (e *UnsupportedReportError) Error() string {
	return fmt.Sprintf("request %s failed: endpoint unsupported (status code %d)", e.URL, e.StatusCode)
}

func IsUnsupportedReportError(err error) bool {
	var target *UnsupportedReportError
	return errors.As(err, &target)
}

// Report merges traffic + alive into a single V2 API call
func (c *Client) Report(ctx context.Context, traffic []UserTraffic, alive map[int][]string) error {
	req := &ReportRequest{}
	if len(traffic) > 0 {
		req.Traffic = make(map[int][]int64, len(traffic))
		for i := range traffic {
			uid := traffic[i].UID
			if existing, ok := req.Traffic[uid]; ok {
				existing[0] += traffic[i].Upload
				existing[1] += traffic[i].Download
			} else {
				req.Traffic[uid] = []int64{traffic[i].Upload, traffic[i].Download}
			}
		}
	}
	if len(alive) > 0 {
		req.Alive = alive
	}
	const path = "/api/v2/server/report"
	r, err := c.client.R().
		SetContext(ctx).
		SetBody(req).
		ForceContentType("application/json").
		Post(path)
	if r != nil {
		switch r.StatusCode() {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
			return &UnsupportedReportError{
				URL:        c.assembleURL(path),
				StatusCode: r.StatusCode(),
			}
		}
	}
	err = c.checkResponse(r, path, err)
	if err != nil {
		return err
	}
	return nil
}
