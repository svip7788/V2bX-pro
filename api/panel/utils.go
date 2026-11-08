package panel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	path2 "path"
	"strings"

	"github.com/go-resty/resty/v2"
)

// Debug set the client debug for client
func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) assembleURL(path string) string {
	return path2.Join(c.APIHost + path)
}

// StatusError 面板返回了 >=400 的响应
type StatusError struct {
	URL        string
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("request %s failed: %s", e.URL, e.Body)
}

func (c *Client) checkResponse(res *resty.Response, path string, err error) error {
	if err != nil {
		return fmt.Errorf("request %s failed: %w", c.assembleURL(path), err)
	}
	if res.StatusCode() >= 400 {
		return &StatusError{URL: c.assembleURL(path), StatusCode: res.StatusCode(), Body: string(res.Body())}
	}
	return nil
}

// IsNodeNotExist 面板上该节点已被删除
func IsNodeNotExist(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusBadRequest && strings.Contains(se.Body, "Server does not exist")
}

// IsNotDelivered 请求确定没被面板处理（连不上 / DNS 失败 / 网关报上游不可用），可以安全重试而不会重复计费。
// 超时、连接中断等无法确定面板是否已入账的情况返回 false
func IsNotDelivered(err error) bool {
	if err == nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.StatusCode == http.StatusBadGateway || se.StatusCode == http.StatusServiceUnavailable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
