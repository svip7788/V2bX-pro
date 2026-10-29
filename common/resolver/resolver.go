// Package resolver 实现面板 action=dns 指定的上游解析：
//
//	https://host/dns-query   DoH（https+local:// 同义）
//	tls://host[:853]         DoT
//	tcp://host[:53]          TCP
//	udp://host[:53] / host   UDP
package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	timeout     = 5 * time.Second
	minTTL      = 30 * time.Second
	maxTTL      = 10 * time.Minute
	negativeTTL = 30 * time.Second
	maxEntries  = 20000
)

type entry struct {
	addr    netip.Addr
	err     error
	expires time.Time
}

type Resolver struct {
	server string
	doh    string
	addr   string
	net    string
	http   *http.Client

	mu    sync.Mutex
	cache map[string]entry
}

var (
	poolMu sync.Mutex
	pool   = map[string]*Resolver{}
)

// Get 按服务器地址复用解析器（共享缓存与连接）
func Get(server string) (*Resolver, error) {
	server = strings.TrimSpace(server)
	poolMu.Lock()
	defer poolMu.Unlock()
	if r, ok := pool[server]; ok {
		return r, nil
	}
	r, err := New(server)
	if err != nil {
		return nil, err
	}
	pool[server] = r
	return r, nil
}

func New(server string) (*Resolver, error) {
	r := &Resolver{server: server, cache: map[string]entry{}}
	scheme, rest, ok := strings.Cut(server, "://")
	if !ok {
		scheme, rest = "udp", server
	}
	switch strings.ToLower(scheme) {
	case "https", "https+local":
		u, err := url.Parse("https://" + rest)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid DoH address %q", server)
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		r.doh = u.String()
		r.http = &http.Client{Timeout: timeout, Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		}}
		return r, nil
	case "tls":
		r.net, r.addr = "tcp-tls", withPort(rest, "853")
	case "tcp", "tcp+local":
		r.net, r.addr = "tcp", withPort(rest, "53")
	case "udp":
		r.net, r.addr = "udp", withPort(rest, "53")
	default:
		return nil, fmt.Errorf("unsupported dns server %q (支持 https:// tls:// tcp:// udp:// 或 IP)", server)
	}
	if h, _, err := net.SplitHostPort(r.addr); err != nil || h == "" {
		return nil, fmt.Errorf("invalid dns server %q", server)
	}
	return r, nil
}

func withPort(hostport, port string) string {
	hostport = strings.TrimSuffix(hostport, "/")
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

func (r *Resolver) String() string { return r.server }

// Lookup 优先返回 A 记录，没有则返回 AAAA
func (r *Resolver) Lookup(ctx context.Context, host string) (netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.addr, e.err
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr, ttl, err := r.query(ctx, host, dns.TypeA)
	if err == nil && !addr.IsValid() {
		addr, ttl, err = r.query(ctx, host, dns.TypeAAAA)
	}
	if err == nil && !addr.IsValid() {
		err = errors.New("no address record")
	}
	if err != nil {
		ttl = negativeTTL
	}
	ttl = min(max(ttl, minTTL), maxTTL)

	r.mu.Lock()
	if len(r.cache) >= maxEntries {
		for k, e := range r.cache {
			if now.After(e.expires) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxEntries {
			r.cache = map[string]entry{}
		}
	}
	r.cache[host] = entry{addr: addr, err: err, expires: now.Add(ttl)}
	r.mu.Unlock()
	return addr, err
}

func (r *Resolver) query(ctx context.Context, host string, qtype uint16) (netip.Addr, time.Duration, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), qtype)
	req.RecursionDesired = true
	var resp *dns.Msg
	var err error
	if r.doh != "" {
		resp, err = r.exchangeDoH(ctx, req)
	} else {
		c := &dns.Client{Net: r.net, Timeout: timeout}
		resp, _, err = c.ExchangeContext(ctx, req, r.addr)
	}
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return netip.Addr{}, 0, fmt.Errorf("dns rcode %s", dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a.Unmap(), time.Duration(rr.Header().Ttl) * time.Second, nil
		}
	}
	return netip.Addr{}, 0, nil
}

func (r *Resolver) exchangeDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	req.Id = 0
	body, err := req.Pack()
	if err != nil {
		return nil, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, r.doh, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/dns-message")
	hr.Header.Set("Accept", "application/dns-message")
	res, err := r.http.Do(hr)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh http %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err = resp.Unpack(data); err != nil {
		return nil, err
	}
	return resp, nil
}
