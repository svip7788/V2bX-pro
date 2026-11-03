package xray

import (
	"context"
	"fmt"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/counter"
	"github.com/InazumaV/V2bX/common/format"
	vCore "github.com/InazumaV/V2bX/core"
	"github.com/InazumaV/V2bX/core/xray/app/dispatcher"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy"
)

func (c *Xray) GetUserManager(tag string) (proxy.UserManager, error) {
	handler, err := c.ihm.GetHandler(context.Background(), tag)
	if err != nil {
		return nil, fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}
	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return nil, fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	return userManager, nil
}

func (c *Xray) CloseUserConns(tag string, uuid string) int {
	if v, ok := c.dispatcher.LinkManagers.Load(format.UserTag(tag, uuid)); ok {
		return v.(*dispatcher.LinkManager).CloseAll()
	}
	return 0
}

func (c *Xray) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	userManager, err := c.GetUserManager(tag)
	if err != nil {
		return fmt.Errorf("get user manager error: %s", err)
	}
	removedUsers := make([]string, 0, len(users))
	for i := range users {
		user := format.UserTag(tag, users[i].Uuid)
		err = userManager.RemoveUser(context.Background(), user)
		if err != nil {
			break
		}
		removedUsers = append(removedUsers, user)
	}
	c.users.mapLock.Lock()
	defer c.users.mapLock.Unlock()
	var tc *counter.TrafficCounter
	if v, ok := c.dispatcher.Counter.Load(tag); ok {
		tc = v.(*counter.TrafficCounter)
	}
	var closed int
	for _, user := range removedUsers {
		delete(c.users.uidMap, user)
		if tc != nil {
			tc.Delete(user)
		}
		if v, ok := c.dispatcher.LinkManagers.Load(user); ok {
			lm := v.(*dispatcher.LinkManager)
			closed += lm.CloseAll()
			c.dispatcher.LinkManagers.Delete(user)
		}
	}
	log.WithFields(log.Fields{
		"tag":       tag,
		"users":     len(removedUsers),
		"closeConn": closed,
	}).Infof("xray: DelUsers removed %d users, closed %d live conns", len(removedUsers), closed)
	if err != nil {
		return err
	}
	return nil
}

func (x *Xray) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	var trafficSlice []panel.UserTraffic
	x.users.mapLock.RLock()
	defer x.users.mapLock.RUnlock()
	if v, ok := x.dispatcher.Counter.Load(tag); ok {
		c := v.(*counter.TrafficCounter)
		minBytes := x.nodeReportMinTrafficBytes[tag]
		c.Counters.Range(func(key, value interface{}) bool {
			email := key.(string)
			traffic := value.(*counter.TrafficStorage)
			up := traffic.UpCounter.Load()
			down := traffic.DownCounter.Load()
			if up == 0 && down == 0 {
				return true
			}
			uid := x.users.uidMap[email]
			if uid == 0 {
				c.Delete(email)
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

func (x *Xray) RestoreUserTraffic(tag string, trafficSlice []panel.UserTraffic) error {
	if len(trafficSlice) == 0 {
		return nil
	}
	v, ok := x.dispatcher.Counter.Load(tag)
	if !ok {
		return nil
	}
	c := v.(*counter.TrafficCounter)
	x.users.mapLock.RLock()
	uidToUser := make(map[int]string, len(x.users.uidMap))
	for user, uid := range x.users.uidMap {
		uidToUser[uid] = user
	}
	x.users.mapLock.RUnlock()
	for i := range trafficSlice {
		user, found := uidToUser[trafficSlice[i].UID]
		if !found {
			continue
		}
		storage := c.GetCounter(user)
		storage.UpCounter.Add(trafficSlice[i].Upload)
		storage.DownCounter.Add(trafficSlice[i].Download)
	}
	return nil
}

func (x *Xray) CommitUserTraffic(tag string, trafficSlice []panel.UserTraffic) error {
	if len(trafficSlice) == 0 {
		return nil
	}
	v, ok := x.dispatcher.Counter.Load(tag)
	if !ok {
		return nil
	}
	c := v.(*counter.TrafficCounter)
	x.users.mapLock.RLock()
	uidToUser := make(map[int]string, len(x.users.uidMap))
	for user, uid := range x.users.uidMap {
		uidToUser[uid] = user
	}
	x.users.mapLock.RUnlock()
	for i := range trafficSlice {
		user, found := uidToUser[trafficSlice[i].UID]
		if !found {
			continue
		}
		storage := c.GetCounter(user)
		storage.UpCounter.Add(-trafficSlice[i].Upload)
		storage.DownCounter.Add(-trafficSlice[i].Download)
	}
	return nil
}

func (c *Xray) AddUsers(p *vCore.AddUsersParams) (added int, err error) {
	var users []*protocol.User
	switch p.NodeInfo.Type {
	case "vmess":
		users = buildVmessUsers(p.Tag, p.Users)
	case "vless":
		users = buildVlessUsers(p.Tag, p.Users, p.VAllss.Flow)
	case "trojan":
		users = buildTrojanUsers(p.Tag, p.Users)
	case "shadowsocks":
		users = buildSSUsers(p.Tag,
			p.Users,
			p.Shadowsocks.Cipher,
			p.Shadowsocks.ServerKey)
	case "hysteria":
		users = buildHysteria2Users(p.Tag, p.Users)
	case "hysteria2":
		users = buildHysteria2Users(p.Tag, p.Users)
	case "tuic":
		users = buildTuicUsers(p.Tag, p.Users)
	case "anytls":
		users = buildAnyTLSUsers(p.Tag, p.Users)
	default:
		return 0, fmt.Errorf("unsupported node type: %s", p.NodeInfo.Type)
	}
	man, err := c.GetUserManager(p.Tag)
	if err != nil {
		return 0, fmt.Errorf("get user manager error: %s", err)
	}
	for _, u := range users {
		mUser, err := u.ToMemoryUser()
		if err != nil {
			return 0, err
		}
		err = man.AddUser(context.Background(), mUser)
		if err != nil {
			return 0, err
		}
	}
	c.users.mapLock.Lock()
	for i := range p.Users {
		c.users.uidMap[format.UserTag(p.Tag, p.Users[i].Uuid)] = p.Users[i].Id
	}
	c.users.mapLock.Unlock()
	return len(users), nil
}
