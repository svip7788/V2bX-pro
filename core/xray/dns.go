package xray

import (
	"bytes"
	"net/url"
	"os"

	"encoding/json"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
	log "github.com/sirupsen/logrus"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func updateDNSConfig(node *panel.NodeInfo) (err error) {
	if !conf.CustomDNSAllowed() {
		return nil
	}
	dnsPath := os.Getenv("XRAY_DNS_PATH")
	if len(node.RawDNS.DNSJson) != 0 {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, node.RawDNS.DNSJson, "", " "); err != nil {
			return err
		}
		err = saveDnsConfig(prettyJSON.Bytes(), dnsPath)
	}
	return err
}

func saveDnsConfig(dns []byte, dnsPath string) (err error) {
	currentData, err := os.ReadFile(dnsPath)
	if err != nil {
		log.WithField("err", err).Error("Failed to read XRAY_DNS_PATH")
		return err
	}
	if !bytes.Equal(currentData, dns) {
		coreDnsConfig := &coreConf.DNSConfig{}
		if err = json.Unmarshal(dns, coreDnsConfig); err != nil {
			log.WithField("err", err).Error("Failed to unmarshal DNS config")
		}
		_, err := coreDnsConfig.Build()
		if err != nil {
			log.WithField("err", err).Error("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help")
			return err
		}
		if err = os.Truncate(dnsPath, 0); err != nil {
			log.WithField("err", err).Error("Failed to clear XRAY DNS PATH file")
		}
		if err = os.WriteFile(dnsPath, dns, 0644); err != nil {
			log.WithField("err", err).Error("Failed to write DNS to XRAY DNS PATH file")
		}
	}
	return err
}

// isLegacyDefaultDNS 报告 dns.json 是否只是旧安装脚本写的默认值：servers 全部是不带任何限定的
// localhost / 1.1.1.1 / 8.8.8.8（含 DoH、DoT、TCP 写法），且至少有一个公共 DNS。
// 这种配置会让出站解析先问公共 DNS，绕过机器系统 DNS（机房的解锁 DNS 就配在那里），
// 所以按未配置处理，一律走系统解析器。确实要用公共 DNS 的，把 server 写成对象形式
// （如 {"address": "1.1.1.1"}）或加上 hosts 等其他字段即可，不会被当成旧默认值。
func isLegacyDefaultDNS(data []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	for key := range raw {
		switch key {
		case "servers", "tag", "queryStrategy":
		default:
			return false
		}
	}
	// 带 domains、expectIPs 等限定的 server 是对象，解析成字符串会失败
	var servers []string
	if err := json.Unmarshal(raw["servers"], &servers); err != nil {
		return false
	}
	public := false
	for _, server := range servers {
		host := server
		if u, err := url.Parse(server); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		switch host {
		case "localhost":
		case "1.1.1.1", "8.8.8.8":
			public = true
		default:
			return false
		}
	}
	return public
}

// migrateLegacyDNSFile 把旧默认 dns.json 的 servers 改写成只用系统解析器，其余字段保留；
// 原文件另存为 .legacy。写失败只记日志，运行时仍按系统解析器处理。
func migrateLegacyDNSFile(path string, data []byte) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}
	raw["servers"] = json.RawMessage(`["localhost"]`)
	out, err := json.MarshalIndent(raw, "", "    ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path+".legacy", data, 0644); err != nil {
		log.WithField("err", err).Warn("Failed to back up legacy DNS config")
		return
	}
	if err := os.WriteFile(path, append(out, '\n'), 0644); err != nil {
		log.WithField("err", err).Warn("Failed to rewrite legacy DNS config")
	}
}
