package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	TypeShadowsocks = "shadowsocks"
	TypeSocks       = "socks"
	TypeHTTP        = "http"
)

// Outbound 面板 action_value 的三种写法：
//
//	ss://method:password@host:port（userinfo 可为 base64）、socks5://user:pass@host:port、http://user:pass@host:port
//	{...}  内核原生出站 JSON（xray 用 protocol，sing-box 用 type）
//	其他   引用本机配置里已有的出站 tag
type Outbound struct {
	Type     string
	Server   string
	Port     uint16
	Method   string
	Username string
	Password string
	Raw      json.RawMessage
	Ref      string
}

func ParseOutbound(v string) (*Outbound, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty outbound")
	}
	if strings.HasPrefix(v, "{") {
		if !json.Valid([]byte(v)) {
			return nil, fmt.Errorf("invalid outbound json")
		}
		return &Outbound{Raw: json.RawMessage(v)}, nil
	}
	scheme, rest, ok := strings.Cut(v, "://")
	if !ok {
		return &Outbound{Ref: v}, nil
	}
	if i := strings.IndexAny(rest, "#?"); i >= 0 {
		rest = rest[:i]
	}
	userinfo, hostport := "", rest
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
	}
	hostport = strings.TrimSuffix(hostport, "/")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("invalid server address %q: %w", hostport, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	o := &Outbound{Server: host, Port: uint16(port)}
	switch strings.ToLower(scheme) {
	case "ss":
		o.Type = TypeShadowsocks
		cred := userinfo
		if decoded, ok := decodeBase64(cred); ok && strings.Contains(decoded, ":") {
			cred = decoded
		} else if unescaped, err := url.PathUnescape(cred); err == nil {
			cred = unescaped
		}
		method, password, ok := strings.Cut(cred, ":")
		if !ok || method == "" || password == "" {
			return nil, fmt.Errorf("ss outbound requires method:password")
		}
		o.Method, o.Password = method, password
	case "socks", "socks5":
		o.Type = TypeSocks
		o.Username, o.Password = splitUserinfo(userinfo)
	case "http":
		o.Type = TypeHTTP
		o.Username, o.Password = splitUserinfo(userinfo)
	default:
		return nil, fmt.Errorf("unsupported outbound scheme %q", scheme)
	}
	return o, nil
}

func splitUserinfo(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	user, pass, _ := strings.Cut(s, ":")
	if u, err := url.PathUnescape(user); err == nil {
		user = u
	}
	if p, err := url.PathUnescape(pass); err == nil {
		pass = p
	}
	return user, pass
}

func decodeBase64(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}

// Tag 节点专属的转发出站 tag，删除节点时按 TagPrefix 清理
func Tag(nodeTag string, routeId int) string {
	return TagPrefix(nodeTag) + strconv.Itoa(routeId)
}

func TagPrefix(nodeTag string) string {
	return nodeTag + "|relay|"
}
