package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

// GetUserList will pull user from v2board
func (c *Client) GetUserList(ctx context.Context) ([]UserInfo, error) {
	path := c.apiPath("/api/v1/server/UniProxy/user")
	req := c.client.R().
		SetContext(ctx).
		SetHeader("X-Response-Format", "msgpack").
		SetDoNotParseResponse(true)
	if c.userEtag != "" && !c.lastUserListFullFetchAt.IsZero() &&
		c.now().Sub(c.lastUserListFullFetchAt) < c.userListRefreshInterval() {
		req.SetHeader("If-None-Match", c.userEtag)
	}
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
	userlist := &UserListBody{Users: []UserInfo{}}
	if strings.Contains(r.Header().Get("Content-Type"), "application/x-msgpack") {
		decoder := msgpack.NewDecoder(r.RawResponse.Body)
		if err := decoder.Decode(userlist); err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
	} else {
		dec := jsontext.NewDecoder(r.RawResponse.Body)
		for {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: %w", err)
			}
			if tok.Kind() == '"' && tok.String() == "users" {
				break
			}
		}
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fmt.Errorf("decode user list error: %w", err)
		}
		if tok.Kind() != '[' {
			return nil, fmt.Errorf(`decode user list error: expected "users" array`)
		}
		for dec.PeekKind() != ']' {
			val, err := dec.ReadValue()
			if err != nil {
				return nil, fmt.Errorf("decode user list error: read user object: %w", err)
			}
			var u UserInfo
			if err := json.Unmarshal(val, &u); err != nil {
				return nil, fmt.Errorf("decode user list error: unmarshal user error: %w", err)
			}
			userlist.Users = append(userlist.Users, u)
		}
	}
	c.userEtag = r.Header().Get("ETag")
	c.lastUserListFullFetchAt = c.now()
	c.UserList = userlist
	return userlist.Users, nil
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
