package xray

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/limiter"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

type proxyHit struct {
	target, user, pass string
}

func pipeConns(a, b net.Conn) {
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
	}()
	_, _ = io.Copy(b, a)
	_ = b.Close()
}

// startSocks5 上游 socks5 代理：记下客户端要去的目标和账号，实际都连到 upstream
func startSocks5(t *testing.T, upstream string, hits chan<- proxyHit) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	serve := func(c net.Conn) {
		defer c.Close()
		r := bufio.NewReader(c)
		head := make([]byte, 2)
		if _, err := io.ReadFull(r, head); err != nil || head[0] != 5 {
			return
		}
		methods := make([]byte, head[1])
		if _, err := io.ReadFull(r, methods); err != nil {
			return
		}
		var hit proxyHit
		if strings.ContainsRune(string(methods), 2) {
			_, _ = c.Write([]byte{5, 2})
			readField := func() string {
				n, _ := r.ReadByte()
				b := make([]byte, n)
				_, _ = io.ReadFull(r, b)
				return string(b)
			}
			_, _ = r.ReadByte()
			hit.user, hit.pass = readField(), readField()
			_, _ = c.Write([]byte{1, 0})
		} else {
			_, _ = c.Write([]byte{5, 0})
		}
		req := make([]byte, 4)
		if _, err := io.ReadFull(r, req); err != nil || req[1] != 1 {
			return
		}
		var host string
		switch req[3] {
		case 1, 4:
			b := make([]byte, map[byte]int{1: 4, 4: 16}[req[3]])
			_, _ = io.ReadFull(r, b)
			host = net.IP(b).String()
		case 3:
			n, _ := r.ReadByte()
			b := make([]byte, n)
			_, _ = io.ReadFull(r, b)
			host = string(b)
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(r, port); err != nil {
			return
		}
		hit.target = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
		hits <- hit
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		pipeConns(up, &bufferedConn{Conn: c, r: r})
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return ln.Addr().String()
}

// startHTTPProxy 上游 http 代理（CONNECT），同样记下目标和账号后连到 upstream
func startHTTPProxy(t *testing.T, upstream string, hits chan<- proxyHit) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	serve := func(c net.Conn) {
		defer c.Close()
		r := bufio.NewReader(c)
		req, err := http.ReadRequest(r)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		hit := proxyHit{target: req.Host}
		if auth, ok := strings.CutPrefix(req.Header.Get("Proxy-Authorization"), "Basic "); ok {
			if b, err := base64.StdEncoding.DecodeString(auth); err == nil {
				hit.user, hit.pass, _ = strings.Cut(string(b), ":")
			}
		}
		hits <- hit
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		pipeConns(up, &bufferedConn{Conn: c, r: r})
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return ln.Addr().String()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// newSSClient 模拟用户客户端：一个只有 shadowsocks 出站的 xray 实例
func newSSClient(t *testing.T, port int, password string) *core.Instance {
	raw := fmt.Sprintf(`{"log":{"loglevel":"none"},"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":%d,"method":"aes-128-gcm","password":%q}]}}]}`, port, password)
	cfg := &coreConf.Config{}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		t.Fatal(err)
	}
	pb, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}

// fetchVia 经客户端实例发一个 HTTP 请求，返回响应体
func fetchVia(inst *core.Instance, host string, port int) (string, error) {
	return fetchViaTimeout(inst, host, port, 5*time.Second)
}

func fetchViaTimeout(inst *core.Instance, host string, port int, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := core.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	timer := time.AfterFunc(timeout, func() { _ = conn.Close() })
	defer timer.Stop()
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// 整条链路：客户端 → 落地节点入站（本内核）→ 按用户出口（socks5 / http 上游）→ 目标
func TestUserEgressEndToEnd(t *testing.T) {
	const tag = "e2e-node"
	// 不存在的域名：只有交给上游代理解析才到得了目标，落地机自己解析必然失败
	const site = "egress-e2e.invalid"
	// TEST-NET-3，公网上不可达
	const unreachable = "203.0.113.1"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "target-ok")
	}))
	defer target.Close()
	targetAddr := target.Listener.Addr().String()

	hits := make(chan proxyHit, 16)
	socksAddr := startSocks5(t, targetAddr, hits)
	httpAddr := startHTTPProxy(t, targetAddr, hits)
	wantHit := func(name string, want proxyHit) {
		t.Helper()
		select {
		case got := <-hits:
			if got != want {
				t.Fatalf("%s: upstream saw %+v, want %+v", name, got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: upstream proxy was not used", name)
		}
	}
	wantNoHit := func(name string) {
		t.Helper()
		select {
		case got := <-hits:
			t.Fatalf("%s: upstream proxy unexpectedly used: %+v", name, got)
		case <-time.After(200 * time.Millisecond):
		}
	}

	xc := conf.NewXrayConfig()
	xc.AssetPath = t.TempDir()
	xc.LogConfig.Level = "none"
	c, err := New(&conf.CoreConfig{Type: "xray", XrayConfig: xc})
	if err != nil {
		t.Fatal(err)
	}
	x := c.(*Xray)
	if err := x.Start(); err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	users := []panel.UserInfo{
		{Id: 1, Uuid: "11111111-1111-4111-8111-111111111111"},
		{Id: 2, Uuid: "22222222-2222-4222-8222-222222222222"},
		{Id: 3, Uuid: "33333333-3333-4333-8333-333333333333"},
	}
	info := &panel.NodeInfo{
		Id:          1,
		Type:        "shadowsocks",
		Shadowsocks: &panel.ShadowsocksNode{Cipher: "aes-128-gcm"},
		Common:      &panel.CommonNode{ServerPort: port},
	}
	opts := &conf.Options{ListenIP: "127.0.0.1", XrayOptions: conf.NewXrayOptions()}
	if err := x.AddNode(tag, info, opts); err != nil {
		t.Fatal(err)
	}
	limiter.Init()
	l := limiter.AddLimiter(tag, &conf.LimitConfig{}, users, map[int]int{})
	defer limiter.DeleteLimiter(tag)
	if _, err := x.AddUsers(&vCore.AddUsersParams{Tag: tag, Users: users, NodeInfo: info}); err != nil {
		t.Fatal(err)
	}
	apply := func(e *panel.UserEgress) {
		x.UpdateUserEgress(tag, e)
		l.SetUserEgress(tag, e)
	}

	outbounds := []panel.EgressOutbound{
		{Id: 7, Outbound: "socks5://su:p%401@" + socksAddr},
		{Id: 8, Outbound: "http://hu:hp@" + httpAddr},
		{Id: 9, Outbound: "socks5://no-port"},
	}
	apply(&panel.UserEgress{Outbounds: outbounds, Users: map[string]int{"1": 7, "2": 8}})

	u1 := newSSClient(t, port, users[0].Uuid)
	u2 := newSSClient(t, port, users[1].Uuid)
	u3 := newSSClient(t, port, users[2].Uuid)

	// 用户 1：socks5 出口，域名原样交给上游，账号密码（含转义的 @）正确
	if body, err := fetchVia(u1, site, 80); err != nil || body != "target-ok" {
		t.Fatalf("user1 via socks5: body=%q err=%v", body, err)
	}
	wantHit("user1", proxyHit{target: site + ":80", user: "su", pass: "p@1"})

	// 用户 2：http 出口
	if body, err := fetchVia(u2, site, 80); err != nil || body != "target-ok" {
		t.Fatalf("user2 via http: body=%q err=%v", body, err)
	}
	wantHit("user2", proxyHit{target: site + ":80", user: "hu", pass: "hp"})

	// 被拒绝的连接立刻断开；放行到本机默认出站的连接去连 unreachable（不可达的公网地址）只会挂着
	expectDropped := func(name string, inst *core.Instance) {
		t.Helper()
		start := time.Now()
		body, err := fetchViaTimeout(inst, unreachable, 80, 3*time.Second)
		if err == nil || time.Since(start) > 1500*time.Millisecond {
			t.Fatalf("%s: connection must be dropped at once, body=%q err=%v after %v", name, body, err, time.Since(start))
		}
		wantNoHit(name)
	}
	expectDirect := func(name string, inst *core.Instance) {
		t.Helper()
		start := time.Now()
		body, err := fetchViaTimeout(inst, unreachable, 80, 1500*time.Millisecond)
		if err == nil || time.Since(start) < 1400*time.Millisecond {
			t.Fatalf("%s: connection should leave through the default outbound, body=%q err=%v after %v", name, body, err, time.Since(start))
		}
		wantNoHit(name)
	}

	// 用户 3 没买 IP：照常走本机默认出站，不碰任何出口
	expectDirect("user3 direct", u3)

	// IP 目标同样走出口
	if body, err := fetchVia(u1, unreachable, 80); err != nil || body != "target-ok" {
		t.Fatalf("user1 ip target via socks5: body=%q err=%v", body, err)
	}
	wantHit("user1 ip target", proxyHit{target: unreachable + ":80", user: "su", pass: "p@1"})

	// 热更新：用户 1 换到 http 出口，不重建入站，新连接立刻生效
	apply(&panel.UserEgress{Outbounds: outbounds, Users: map[string]int{"1": 8, "2": 8}})
	if body, err := fetchVia(u1, site, 80); err != nil || body != "target-ok" {
		t.Fatalf("user1 after switch: body=%q err=%v", body, err)
	}
	wantHit("user1 after switch", proxyHit{target: site + ":80", user: "hu", pass: "hp"})

	// 出口写法无效：连接必须被拒绝，不能回落到本机 IP
	apply(&panel.UserEgress{Outbounds: outbounds, Users: map[string]int{"1": 7, "2": 9}})
	expectDropped("user2 unusable exit", u2)

	// 严格模式：没分到出口的用户 3 被拒绝，买了的用户 1 不受影响
	apply(&panel.UserEgress{Outbounds: outbounds, Users: map[string]int{"1": 7}, Strict: true})
	expectDropped("user3 strict", u3)
	if body, err := fetchVia(u1, site, 80); err != nil || body != "target-ok" {
		t.Fatalf("user1 on strict node: body=%q err=%v", body, err)
	}
	wantHit("user1 strict", proxyHit{target: site + ":80", user: "su", pass: "p@1"})

	// 撤掉全部出口：用户 1 回到本机默认出站
	apply(nil)
	expectDirect("user1 after egress removed", u1)
}
