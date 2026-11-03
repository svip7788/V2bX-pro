package core

import (
	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/conf"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type Core interface {
	Start() error
	Close() error
	AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error
	DelNode(tag string) error
	AddUsers(p *AddUsersParams) (added int, err error)
	GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error)
	CommitUserTraffic(tag string, traffic []panel.UserTraffic) error
	RestoreUserTraffic(tag string, traffic []panel.UserTraffic) error
	DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error
	// CloseUserConns 断开用户现有连接，返回断开数；限速变更只对新连接生效时用来让其立即生效
	CloseUserConns(tag string, uuid string) int
	Protocols() []string
	Type() string
}
