// Package portreserve keeps node listen ports out of the kernel ephemeral
// range, so outbound connections can't grab a port before its inbound binds.
package portreserve

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	procPath    = "/proc/sys/net/ipv4/ip_local_reserved_ports"
	sysctlPath  = "/etc/sysctl.d/99-v2bx-reserved-ports.conf"
	sysctlEntry = "net.ipv4.ip_local_reserved_ports"
)

var mu sync.Mutex

// Reserve adds port to ip_local_reserved_ports and persists the result.
func Reserve(port int) error {
	if port <= 0 || port > 65535 {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	raw, err := os.ReadFile(procPath)
	if err != nil {
		return err
	}
	cur := strings.TrimSpace(string(raw))
	if contains(cur, port) {
		return nil
	}
	next := strconv.Itoa(port)
	if cur != "" {
		next = cur + "," + next
	}
	if err = os.WriteFile(procPath, []byte(next), 0644); err != nil {
		return err
	}
	if raw, err = os.ReadFile(procPath); err == nil {
		next = strings.TrimSpace(string(raw))
	}
	return os.WriteFile(sysctlPath, []byte(sysctlEntry+" = "+next+"\n"), 0644)
}

func contains(list string, port int) bool {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, ok := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			continue
		}
		b := a
		if ok {
			if b, err = strconv.Atoi(hi); err != nil {
				continue
			}
		}
		if port >= a && port <= b {
			return true
		}
	}
	return false
}
