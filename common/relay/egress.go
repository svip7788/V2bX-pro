package relay

import (
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// 节点常见的出站白名单防火墙（OUTPUT 只放行 80/443 等）会把转发服务器的端口丢弃，
// 转发连接全部超时。这里维护独立链并挂在 OUTPUT 最前面，放行到转发服务器的流量。
const egressChain = "V2BX_RELAY"

const egressRefresh = 10 * time.Minute

type endpoint struct {
	host string
	port uint16
}

var (
	egressMu      sync.Mutex
	egressOwners  = map[string][]endpoint{}
	egressApplied = map[string][]string{} // iptables / ip6tables -> 已写入的 "ip port"
	egressOnce    sync.Once

	egressEnabled = runtime.GOOS == "linux"
	hasFirewall   = func(bin string) bool {
		_, err := exec.LookPath(bin)
		return err == nil
	}
	runFirewall = func(bin string, args ...string) error {
		return exec.Command(bin, append([]string{"-w"}, args...)...).Run()
	}
	listFirewall = func(bin string) (string, error) {
		out, err := exec.Command(bin, "-w", "-S", egressChain).Output()
		return string(out), err
	}
	lookupHost = func(host string) ([]netip.Addr, error) {
		ips, err := net.LookupIP(host)
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, a.Unmap())
			}
		}
		return addrs, err
	}
)

// AllowEgress 用 owner（节点 tag）的转发出站替换其放行列表，outs 为空即撤销。
// 之后每 egressRefresh 重新解析域名并补齐被外部清掉的规则
func AllowEgress(owner string, outs []*Outbound) {
	if !egressEnabled {
		return
	}
	var eps []endpoint
	for _, o := range outs {
		if ep, ok := o.endpoint(); ok {
			eps = append(eps, ep)
		}
	}
	egressMu.Lock()
	defer egressMu.Unlock()
	if len(eps) == 0 {
		delete(egressOwners, owner)
	} else {
		egressOwners[owner] = eps
	}
	syncEgressLocked()
	egressOnce.Do(func() {
		go func() {
			for range time.Tick(egressRefresh) {
				egressMu.Lock()
				syncEgressLocked()
				egressMu.Unlock()
			}
		}()
	})
}

// endpoint 链接写法直接取 Server/Port；原生 JSON 尽量从 xray / sing-box 常见字段里取
func (o *Outbound) endpoint() (endpoint, bool) {
	if o == nil || o.Ref != "" {
		return endpoint{}, false
	}
	if o.Raw == nil {
		return endpoint{o.Server, o.Port}, o.Server != "" && o.Port != 0
	}
	var v struct {
		Server     string `json:"server"`
		ServerPort uint16 `json:"server_port"`
		Settings   struct {
			Address string `json:"address"`
			Port    uint16 `json:"port"`
			Servers []struct {
				Address string `json:"address"`
				Port    uint16 `json:"port"`
			} `json:"servers"`
			Vnext []struct {
				Address string `json:"address"`
				Port    uint16 `json:"port"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	if json.Unmarshal(o.Raw, &v) != nil {
		return endpoint{}, false
	}
	s := v.Settings
	switch {
	case v.Server != "" && v.ServerPort != 0:
		return endpoint{v.Server, v.ServerPort}, true
	case s.Address != "" && s.Port != 0:
		return endpoint{s.Address, s.Port}, true
	case len(s.Servers) > 0 && s.Servers[0].Address != "" && s.Servers[0].Port != 0:
		return endpoint{s.Servers[0].Address, s.Servers[0].Port}, true
	case len(s.Vnext) > 0 && s.Vnext[0].Address != "" && s.Vnext[0].Port != 0:
		return endpoint{s.Vnext[0].Address, s.Vnext[0].Port}, true
	}
	return endpoint{}, false
}

func syncEgressLocked() {
	rules := map[string][]string{"iptables": nil, "ip6tables": nil}
	seen := map[string]struct{}{}
	for _, eps := range egressOwners {
		for _, ep := range eps {
			addrs, err := resolve(ep.host)
			if err != nil {
				log.WithFields(log.Fields{"host": ep.host, "err": err}).Warn("Resolve relay server failed")
			}
			for _, a := range addrs {
				if relayBypass(a) {
					continue
				}
				bin := "iptables"
				if a.Is6() {
					bin = "ip6tables"
				}
				r := a.String() + " " + strconv.Itoa(int(ep.port))
				if _, ok := seen[bin+r]; ok {
					continue
				}
				seen[bin+r] = struct{}{}
				rules[bin] = append(rules[bin], r)
			}
		}
	}
	for bin, rs := range rules {
		if !hasFirewall(bin) {
			continue
		}
		if _, ok := egressApplied[bin]; !ok {
			egressApplied[bin] = existingEgress(bin)
		}
		applied, err := applyEgress(bin, egressApplied[bin], rs)
		if err != nil {
			log.WithFields(log.Fields{"cmd": bin, "err": err}).Warn("Allow relay egress in firewall failed")
		}
		egressApplied[bin] = applied
	}
}

func resolve(host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	return lookupHost(host)
}

func relayBypass(a netip.Addr) bool {
	return a.IsLoopback() || a.IsUnspecified()
}

// applyEgress 增量同步：补齐缺失规则（含被外部清掉的）、删除不再需要的，不清空整链，
// 避免重载节点时出现放行空窗。返回仍在生效的规则，供下次计算删除
func applyEgress(bin string, applied, want []string) ([]string, error) {
	if len(want) == 0 && len(applied) == 0 {
		return nil, nil
	}
	if len(want) > 0 {
		if runFirewall(bin, "-L", egressChain, "-n") != nil {
			if err := runFirewall(bin, "-N", egressChain); err != nil {
				return applied, err
			}
		}
		if runFirewall(bin, "-C", "OUTPUT", "-j", egressChain) != nil {
			if err := runFirewall(bin, "-I", "OUTPUT", "1", "-j", egressChain); err != nil {
				return applied, err
			}
		}
	}
	var firstErr error
	keep := make([]string, 0, len(want))
	for _, r := range want {
		ok := true
		for _, args := range egressRuleArgs(r) {
			if runFirewall(bin, append([]string{"-C", egressChain}, args...)...) == nil {
				continue
			}
			if err := runFirewall(bin, append([]string{"-A", egressChain}, args...)...); err != nil {
				ok = false
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if ok {
			keep = append(keep, r)
		}
	}
	for _, r := range applied {
		if slices.Contains(want, r) {
			continue
		}
		for _, args := range egressRuleArgs(r) {
			_ = runFirewall(bin, append([]string{"-D", egressChain}, args...)...)
		}
	}
	return keep, firstErr
}

// existingEgress 读出链里已有的放行（上次运行留下的），已删除节点的规则据此清理
func existingEgress(bin string) []string {
	out, err := listFirewall(bin)
	if err != nil {
		return []string{}
	}
	rs := []string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		var ip, port string
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "-d":
				ip = f[i+1]
				if p, err := netip.ParsePrefix(ip); err == nil && p.IsSingleIP() {
					ip = p.Addr().String()
				}
			case "--dport":
				port = f[i+1]
			}
		}
		if ip == "" || port == "" {
			continue
		}
		if r := ip + " " + port; !slices.Contains(rs, r) {
			rs = append(rs, r)
		}
	}
	return rs
}

func egressRuleArgs(r string) [][]string {
	ip, port, _ := strings.Cut(r, " ")
	return [][]string{
		{"-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"},
		{"-d", ip, "-p", "udp", "--dport", port, "-j", "ACCEPT"},
	}
}
