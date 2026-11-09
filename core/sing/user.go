package sing

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/counter"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/core"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	log "github.com/sirupsen/logrus"
)

func (b *Sing) AddUsers(p *core.AddUsersParams) (added int, err error) {
	in, found := b.box.Inbound().Get(p.Tag)
	if !found {
		return 0, errors.New("the inbound not found")
	}
	switch p.NodeInfo.Type {
	case "vless":
		us := make([]option.VLESSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VLESSUser{
				Name: p.Users[i].Uuid,
				Flow: p.VAllss.Flow,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vless.Inbound).AddUsers(us)
	case "vmess":
		us := make([]option.VMessUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.VMessUser{
				Name: p.Users[i].Uuid,
				UUID: p.Users[i].Uuid,
			}
		}
		err = in.(*vmess.Inbound).AddUsers(us)
	case "shadowsocks":
		us := make([]option.ShadowsocksUser, len(p.Users))
		for i := range p.Users {
			var password = p.Users[i].Uuid
			switch p.Shadowsocks.Cipher {
			case "2022-blake3-aes-128-gcm":
				if len(password) >= 16 {
					password = base64.StdEncoding.EncodeToString([]byte(password[:16]))
				}
			case "2022-blake3-aes-256-gcm":
				if len(password) >= 32 {
					password = base64.StdEncoding.EncodeToString([]byte(password[:32]))
				}
			}
			us[i] = option.ShadowsocksUser{
				Name:     p.Users[i].Uuid,
				Password: password,
			}
		}
		err = in.(*shadowsocks.MultiInbound).AddUsers(us)
	case "trojan":
		us := make([]option.TrojanUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.TrojanUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*trojan.Inbound).AddUsers(us)
	case "tuic":
		us := make([]option.TUICUser, len(p.Users))
		id := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.TUICUser{
				Name:     p.Users[i].Uuid,
				UUID:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			id[i] = p.Users[i].Id
		}
		err = in.(*tuic.Inbound).AddUsers(us, id)
	case "hysteria":
		us := make([]option.HysteriaUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.HysteriaUser{
				Name:       p.Users[i].Uuid,
				AuthString: p.Users[i].Uuid,
			}
		}
		err = in.(*hysteria.Inbound).AddUsers(us)
	case "hysteria2":
		us := make([]option.Hysteria2User, len(p.Users))
		id := make([]int, len(p.Users))
		for i := range p.Users {
			us[i] = option.Hysteria2User{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
			id[i] = p.Users[i].Id
		}
		err = in.(*hysteria2.Inbound).AddUsers(us, id)
	case "anytls":
		us := make([]option.AnyTLSUser, len(p.Users))
		for i := range p.Users {
			us[i] = option.AnyTLSUser{
				Name:     p.Users[i].Uuid,
				Password: p.Users[i].Uuid,
			}
		}
		err = in.(*anytls.Inbound).AddUsers(us)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	if err != nil {
		return 0, err
	}
	b.users.mapLock.Lock()
	for i := range p.Users {
		b.users.uidMap[format.UserTag(p.Tag, p.Users[i].Uuid)] = p.Users[i].Id
	}
	b.users.mapLock.Unlock()
	return len(p.Users), nil
}

func (b *Sing) GetUserTraffic(tag, uuid string, reset bool) (up int64, down int64) {
	if v, ok := b.hookServer.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		up = c.GetUpCount(uuid)
		down = c.GetDownCount(uuid)
		if reset {
			c.Reset(uuid)
		}
		return
	}
	return 0, 0
}

func (b *Sing) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	var trafficSlice []panel.UserTraffic
	hook := b.hookServer
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	if v, ok := hook.counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		var minBytes int64
		if mv, ok := b.nodeReportMinTrafficBytes.Load(tag); ok {
			minBytes = mv.(int64)
		}
		c.Counters.Range(func(key, value interface{}) bool {
			uuid := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up == 0 && down == 0 {
				return true
			}
			uid := b.users.uidMap[format.UserTag(tag, uuid)]
			if uid == 0 {
				c.Delete(uuid)
				return true
			}
			if up+down > minBytes {
				if reset {
					// Swap 而非 Store(0)：Load 之后新写入的字节留到下一轮，不丢
					up = traffic.UpCounter.Swap(0)
					down = traffic.DownCounter.Swap(0)
				}
				trafficSlice = append(trafficSlice, panel.UserTraffic{
					UID:      uid,
					Upload:   up,
					Download: down,
				})
			}
			return true
		})
	}
	if len(trafficSlice) == 0 {
		return nil, nil
	}
	return trafficSlice, nil
}

func (b *Sing) RestoreUserTraffic(tag string, trafficSlice []panel.UserTraffic) error {
	if len(trafficSlice) == 0 {
		return nil
	}
	v, ok := b.hookServer.counter.Load(tag)
	if !ok {
		return nil
	}
	c := v.(*counter.TrafficCounter)
	uidToUUID := b.tagUIDToUUID(tag)
	for i := range trafficSlice {
		uuid, found := uidToUUID[trafficSlice[i].UID]
		if !found {
			continue
		}
		storage := c.GetCounter(uuid)
		storage.UpCounter.Add(trafficSlice[i].Upload)
		storage.DownCounter.Add(trafficSlice[i].Download)
	}
	return nil
}

func (b *Sing) CommitUserTraffic(tag string, trafficSlice []panel.UserTraffic) error {
	if len(trafficSlice) == 0 {
		return nil
	}
	v, ok := b.hookServer.counter.Load(tag)
	if !ok {
		return nil
	}
	c := v.(*counter.TrafficCounter)
	uidToUUID := b.tagUIDToUUID(tag)
	for i := range trafficSlice {
		uuid, found := uidToUUID[trafficSlice[i].UID]
		if !found {
			continue
		}
		storage := c.GetCounter(uuid)
		storage.UpCounter.Add(-trafficSlice[i].Upload)
		storage.DownCounter.Add(-trafficSlice[i].Download)
	}
	return nil
}

// tagUIDToUUID 取该节点的 uid → uuid；uidMap 按 tag|uuid 存，同一用户在多个节点上互不影响
func (b *Sing) tagUIDToUUID(tag string) map[int]string {
	prefix := tag + "|"
	b.users.mapLock.RLock()
	defer b.users.mapLock.RUnlock()
	m := make(map[int]string)
	for key, uid := range b.users.uidMap {
		if uuid, ok := strings.CutPrefix(key, prefix); ok {
			m[uid] = uuid
		}
	}
	return m
}

func (b *Sing) CloseUserConns(tag string, uuid string) int {
	if m, ok := b.hookServer.connManagers.Load(format.UserTag(tag, uuid)); ok {
		return m.(*userConnManager).CloseAll()
	}
	return 0
}

func (b *Sing) CloseUserIPConns(tag string, uuid string, match func(ip string) bool) int {
	if m, ok := b.hookServer.connManagers.Load(format.UserTag(tag, uuid)); ok {
		return m.(*userConnManager).CloseMatching(match)
	}
	return 0
}

func (b *Sing) ActiveUserIPs(tag string) map[string][]string {
	prefix := tag + "|"
	out := make(map[string][]string)
	b.hookServer.connManagers.Range(func(key, value any) bool {
		if uuid, ok := strings.CutPrefix(key.(string), prefix); ok {
			if ips := value.(*userConnManager).IPs(); len(ips) > 0 {
				out[uuid] = ips
			}
		}
		return true
	})
	return out
}

type UserDeleter interface {
	DelUsers(uuid []string) error
}

func (b *Sing) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	var del UserDeleter
	if i, found := b.box.Inbound().Get(tag); found {
		switch info.Type {
		case "vmess":
			del = i.(*vmess.Inbound)
		case "vless":
			del = i.(*vless.Inbound)
		case "shadowsocks":
			del = i.(*shadowsocks.MultiInbound)
		case "trojan":
			del = i.(*trojan.Inbound)
		case "tuic":
			del = i.(*tuic.Inbound)
		case "hysteria":
			del = i.(*hysteria.Inbound)
		case "hysteria2":
			del = i.(*hysteria2.Inbound)
		case "anytls":
			del = i.(*anytls.Inbound)
		default:
			return fmt.Errorf("unsupported node type: %s", info.Type)
		}
	} else {
		return errors.New("the inbound not found")
	}
	uuids := make([]string, len(users))
	for i := range users {
		uuids[i] = users[i].Uuid
	}
	err := del.DelUsers(uuids)
	if err != nil {
		return err
	}
	b.users.mapLock.Lock()
	var tc *counter.TrafficCounter
	if v, ok := b.hookServer.counter.Load(tag); ok {
		tc = v.(*counter.TrafficCounter)
	}
	connKeys := make([]string, 0, len(users))
	for i := range users {
		if tc != nil {
			tc.Delete(users[i].Uuid)
		}
		delete(b.users.uidMap, format.UserTag(tag, users[i].Uuid))
		connKeys = append(connKeys, format.UserTag(tag, users[i].Uuid))
	}
	b.users.mapLock.Unlock()
	var closed int
	for _, key := range connKeys {
		if n := b.hookServer.closeUserConnections(key); n > 0 {
			closed += n
		}
	}
	log.WithFields(log.Fields{
		"tag":       tag,
		"users":     len(users),
		"closeConn": closed,
	}).Infof("sing: DelUsers removed %d users, closed %d live conns", len(users), closed)
	return nil
}
