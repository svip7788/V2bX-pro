package limiter

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/format"
	"github.com/InazumaV/V2bX/conf"
	"github.com/juju/ratelimit"
)

var limitLock sync.RWMutex
var limiter map[string]*Limiter

func Init() {
	limiter = map[string]*Limiter{}
}

type Limiter struct {
	DomainRules   []*regexp.Regexp
	ProtocolRules []string
	SpeedLimit    int

	relayRules    []relayRule
	dnsRules      []dnsRule
	ruleMu        sync.RWMutex
	aliveMu       sync.RWMutex
	userLimitInfo sync.Map // taguuid -> *UserLimitInfo
	speedLimiter  sync.Map // taguuid -> *ratelimit.Bucket
	userDevices   sync.Map // taguuid -> *userDeviceState
	uuidToUID     sync.Map // uuid -> int
	aliveList     map[int]int
	aliveIPs      map[int][]string // 面板 sync.devices 下发的全节点在线 IP，nil 表示只有计数
	aliveIPsAt    time.Time
	dyWhitelist   map[int]struct{}
	dyTimeRanges  []timeRange
	dyConfig      conf.DynamicSpeedLimitConfig
	dyApplied     bool
	btBanDuration time.Duration
	btBanned      sync.Map // taguuid -> int64 (ban expiry, unix nano)
	allowBT       atomic.Bool
}

const defaultBTBanDuration = 2 * time.Minute

// WS 断开后不再有 sync.devices，过期的 IP 列表不能继续放行，退回只按计数判断
const aliveIPsMaxAge = 10 * time.Minute

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
	ShareDivisor      int   // 面板 speed.share：固定限速按全节点平分的份数
	ShareExpire       int64 // unix 秒
}

// sharedSpeedLimit 返回按全节点平分后的固定限速，未平分或已过期时为原值
func (u *UserLimitInfo) sharedSpeedLimit(now int64) int {
	if u.SpeedLimit <= 0 || u.ShareDivisor <= 1 || u.ShareExpire <= now {
		return u.SpeedLimit
	}
	return max(1, (u.SpeedLimit+u.ShareDivisor-1)/u.ShareDivisor)
}

// UpdateSpeedShare 设置用户固定限速的平分份数，返回生效限速是否变低（变低时须断开现有连接才能生效；
// 变高不断开，新连接自然按新限速）
func (l *Limiter) UpdateSpeedShare(tag, uuid string, divisor int, expire time.Time) (bool, error) {
	key := format.UserTag(tag, uuid)
	v, ok := l.userLimitInfo.Load(key)
	if !ok {
		return false, errors.New("not found")
	}
	old := v.(*UserLimitInfo)
	now := time.Now().Unix()
	info := *old
	info.ShareDivisor = divisor
	info.ShareExpire = expire.Unix()
	if divisor <= 1 {
		info.ShareDivisor, info.ShareExpire = 0, 0
	}
	l.userLimitInfo.Store(key, &info)
	return info.sharedSpeedLimit(now) < old.sharedSpeedLimit(now), nil
}

type userDeviceState struct {
	uid      int
	mu       sync.Mutex
	current  map[string]struct{}
	reported map[string]struct{}
}

func newUserDeviceState(uid int) *userDeviceState {
	return &userDeviceState{
		uid:     uid,
		current: make(map[string]struct{}),
	}
}

func (s *userDeviceState) setUID(uid int) {
	s.mu.Lock()
	s.uid = uid
	if s.current == nil {
		s.current = make(map[string]struct{})
	}
	s.mu.Unlock()
}

// allow 返回 true 表示拒绝。aliveIPs 非 nil 时是面板汇总的全节点在线 IP：
// 已在其中的 IP 是同一设备换节点或多节点并用，直接放行；设备数按本节点与全节点 IP 的并集计。
// aliveIPs 为 nil（只有 alivelist 计数）时只能取两者较大值。
func (s *userDeviceState) allow(ip string, deviceLimit int, aliveCount int, aliveIPs []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		s.current = make(map[string]struct{})
	}
	if _, exists := s.current[ip]; exists {
		return false
	}
	if _, exists := s.reported[ip]; exists {
		delete(s.reported, ip)
		s.current[ip] = struct{}{}
		return false
	}
	knownCount := len(s.current) + len(s.reported)
	if aliveIPs != nil {
		for _, g := range aliveIPs {
			if g == ip {
				s.current[ip] = struct{}{}
				return false
			}
			_, inCurrent := s.current[g]
			_, inReported := s.reported[g]
			if !inCurrent && !inReported {
				knownCount++
			}
		}
	} else if aliveCount > knownCount {
		knownCount = aliveCount
	}
	if deviceLimit > 0 && knownCount >= deviceLimit {
		return true
	}
	s.current[ip] = struct{}{}
	return false
}

func (s *userDeviceState) snapshotCurrent() []panel.OnlineUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.current) == 0 {
		return nil
	}
	users := make([]panel.OnlineUser, 0, len(s.current))
	for ip := range s.current {
		users = append(users, panel.OnlineUser{
			UID: s.uid,
			IP:  ip,
		})
	}
	return users
}

func (s *userDeviceState) markReported() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 每个上报周期对所有出现过的用户执行一次，空闲用户不分配新 map（allow 会按需创建）
	if len(s.current) == 0 {
		s.reported = nil
		s.current = nil
		return
	}
	s.reported = s.current
	s.current = make(map[string]struct{}, len(s.reported))
}

func AddLimiter(tag string, l *conf.LimitConfig, users []panel.UserInfo, aliveList map[int]int) *Limiter {
	info := &Limiter{
		SpeedLimit:    l.SpeedLimit,
		aliveList:     aliveList,
		btBanDuration: defaultBTBanDuration,
	}
	if l.BTBanMinutes > 0 {
		info.btBanDuration = time.Duration(l.BTBanMinutes) * time.Minute
	}
	info.SetDynamicConfig(l)
	for i := range users {
		info.uuidToUID.Store(users[i].Uuid, users[i].Id)
		ul := &UserLimitInfo{
			UID: users[i].Id,
		}
		if users[i].SpeedLimit != 0 {
			ul.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			ul.DeviceLimit = users[i].DeviceLimit
		}
		info.userLimitInfo.Store(format.UserTag(tag, users[i].Uuid), ul)
	}
	limitLock.Lock()
	limiter[tag] = info
	limitLock.Unlock()
	return info
}

func GetLimiter(tag string) (info *Limiter, err error) {
	limitLock.RLock()
	info, ok := limiter[tag]
	limitLock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func DeleteLimiter(tag string) {
	limitLock.Lock()
	delete(limiter, tag)
	limitLock.Unlock()
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	for i := range deleted {
		key := format.UserTag(tag, deleted[i].Uuid)
		l.userLimitInfo.Delete(key)
		l.userDevices.Delete(key)
		l.speedLimiter.Delete(key)
		l.btBanned.Delete(key)
		l.uuidToUID.Delete(deleted[i].Uuid)
		l.aliveMu.Lock()
		delete(l.aliveList, deleted[i].Id)
		l.aliveMu.Unlock()
	}
	for i := range added {
		ul := &UserLimitInfo{
			UID: added[i].Id,
		}
		if added[i].SpeedLimit != 0 {
			ul.SpeedLimit = added[i].SpeedLimit
			ul.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			ul.DeviceLimit = added[i].DeviceLimit
		}
		l.userLimitInfo.Store(format.UserTag(tag, added[i].Uuid), ul)
		l.uuidToUID.Store(added[i].Uuid, added[i].Id)
	}
}

// UpdateUserLimit 原地更新固定限速和设备数，保留动态限速、平分份额和在线设备状态；
// 返回生效限速变低的 uuid（限速桶在建连时取定，须断开现有连接才能生效）
func (l *Limiter) UpdateUserLimit(tag string, users []panel.UserInfo) (tightened []string) {
	now := time.Now().Unix()
	effective := func(u *UserLimitInfo) int {
		s := u.sharedSpeedLimit(now)
		if u.DynamicSpeedLimit > 0 && (u.ExpireTime == 0 || u.ExpireTime >= now) {
			s = determineSpeedLimit(s, u.DynamicSpeedLimit)
		}
		return determineSpeedLimit(l.SpeedLimit, s)
	}
	for i := range users {
		key := format.UserTag(tag, users[i].Uuid)
		info := UserLimitInfo{UID: users[i].Id}
		oldLimit := l.SpeedLimit
		if v, ok := l.userLimitInfo.Load(key); ok {
			old := v.(*UserLimitInfo)
			info = *old
			oldLimit = effective(old)
		}
		info.SpeedLimit = users[i].SpeedLimit
		info.DeviceLimit = users[i].DeviceLimit
		l.userLimitInfo.Store(key, &info)
		l.uuidToUID.Store(users[i].Uuid, users[i].Id)
		if newLimit := effective(&info); newLimit > 0 && (oldLimit == 0 || newLimit < oldLimit) {
			tightened = append(tightened, users[i].Uuid)
		}
	}
	return tightened
}

func (l *Limiter) IsWhitelisted(uid int) bool {
	if l.dyWhitelist == nil {
		return false
	}
	_, ok := l.dyWhitelist[uid]
	return ok
}

// SetDynamicConfig 幂等；配置变化时解除已有动态限速，让新参数立即生效。
// 与 IsWhitelisted/InDynamicLimitTimeRange 须在同一把锁（控制器 runtimeMu）下调用
func (l *Limiter) SetDynamicConfig(lc *conf.LimitConfig) {
	var cur conf.DynamicSpeedLimitConfig
	if lc.EnableDynamicSpeedLimit && lc.DynamicSpeedLimitConfig != nil {
		cur = *lc.DynamicSpeedLimitConfig
	}
	if l.dyApplied && l.dyConfig == cur {
		return
	}
	if l.dyApplied {
		l.ClearDynamicSpeedLimit()
	}
	l.dyApplied, l.dyConfig = true, cur
	l.dyWhitelist = parseWhitelist(cur.DyLimitWhiteUserID)
	l.dyTimeRanges = parseTimeRanges(cur.DyLimitDuration)
}

// ClearDynamicSpeedLimit 立即解除所有用户的动态限速
func (l *Limiter) ClearDynamicSpeedLimit() {
	l.userLimitInfo.Range(func(k, v any) bool {
		u := v.(*UserLimitInfo)
		if u.DynamicSpeedLimit == 0 && u.ExpireTime == 0 {
			return true
		}
		info := *u
		info.DynamicSpeedLimit = 0
		info.ExpireTime = 0
		l.userLimitInfo.Store(k, &info)
		l.speedLimiter.Delete(k)
		return true
	})
}

func (l *Limiter) InDynamicLimitTimeRange() bool {
	return inTimeRanges(l.dyTimeRanges, time.Now())
}

func (l *Limiter) IsDynamicLimited(tag, uuid string) bool {
	key := format.UserTag(tag, uuid)
	v, ok := l.userLimitInfo.Load(key)
	if !ok {
		return false
	}
	u := v.(*UserLimitInfo)
	return u.DynamicSpeedLimit > 0 && (u.ExpireTime == 0 || u.ExpireTime > time.Now().Unix())
}

func (l *Limiter) UpdateDynamicSpeedLimit(tag, uuid string, limit int, expire time.Time) error {
	key := format.UserTag(tag, uuid)
	v, ok := l.userLimitInfo.Load(key)
	if !ok {
		return errors.New("not found")
	}
	old := v.(*UserLimitInfo)
	info := *old
	info.DynamicSpeedLimit = limit
	info.ExpireTime = expire.Unix()
	l.userLimitInfo.Store(key, &info)
	return nil
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	ip = strings.TrimPrefix(ip, "::ffff:")
	if l.isBitTorrentBanned(taguuid) {
		return nil, true
	}

	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int

	v, ok := l.userLimitInfo.Load(taguuid)
	if !ok {
		return nil, true
	}
	u := v.(*UserLimitInfo)
	deviceLimit = u.DeviceLimit
	uid = u.UID
	now := time.Now().Unix()
	speedLimit := u.sharedSpeedLimit(now)
	dynamicExpired := u.ExpireTime != 0 && u.ExpireTime < now
	if dynamicExpired {
		userLimit = speedLimit
	} else if u.DynamicSpeedLimit > 0 {
		userLimit = determineSpeedLimit(speedLimit, u.DynamicSpeedLimit)
	} else {
		userLimit = speedLimit
	}

	if noSSUDP {
		aliveCount, aliveIPs := l.getAlive(uid)
		state := l.getOrCreateDeviceState(taguuid, uid)
		if state.allow(ip, deviceLimit, aliveCount, aliveIPs) {
			return nil, true
		}
	}

	if dynamicExpired {
		info := *u
		info.DynamicSpeedLimit = 0
		info.ExpireTime = 0
		l.userLimitInfo.Store(taguuid, &info)
		l.speedLimiter.Delete(taguuid)
	}

	limit := int64(determineSpeedLimit(nodeLimit, userLimit)) * 1000000 / 8
	if limit > 0 {
		if bv, ok := l.speedLimiter.Load(taguuid); ok {
			b := bv.(*ratelimit.Bucket)
			if b.Capacity() == limit {
				return b, false
			}
		}
		bucket := ratelimit.NewBucketWithQuantum(time.Second, limit, limit)
		if actual, loaded := l.speedLimiter.LoadOrStore(taguuid, bucket); loaded {
			existing := actual.(*ratelimit.Bucket)
			if existing.Capacity() == limit {
				return existing, false
			}
		}
		l.speedLimiter.Store(taguuid, bucket)
		return bucket, false
	}
	l.speedLimiter.Delete(taguuid)
	return nil, false
}

// BanBitTorrent bans the user on this node; returns false if the user was already banned.
func (l *Limiter) BanBitTorrent(taguuid string) (newly bool, d time.Duration) {
	d = l.btBanDuration
	if d <= 0 {
		d = defaultBTBanDuration
	}
	now := time.Now()
	prev, loaded := l.btBanned.Swap(taguuid, now.Add(d).UnixNano())
	return !loaded || prev.(int64) <= now.UnixNano(), d
}

func (l *Limiter) isBitTorrentBanned(taguuid string) bool {
	v, ok := l.btBanned.Load(taguuid)
	if !ok {
		return false
	}
	if v.(int64) > time.Now().UnixNano() {
		return true
	}
	l.btBanned.CompareAndDelete(taguuid, v)
	return false
}

func (l *Limiter) SetAliveList(alive map[int]int) {
	l.aliveMu.Lock()
	l.aliveList = alive
	l.aliveMu.Unlock()
}

func (l *Limiter) GetUIDByUUID(uuid string) (int, bool) {
	v, ok := l.uuidToUID.Load(uuid)
	if !ok {
		return 0, false
	}
	return v.(int), true
}

func (l *Limiter) GetOnlineDevice() ([]panel.OnlineUser, error) {
	var onlineUser []panel.OnlineUser
	l.userDevices.Range(func(_, value interface{}) bool {
		onlineUser = append(onlineUser, value.(*userDeviceState).snapshotCurrent()...)
		return true
	})
	return onlineUser, nil
}

func (l *Limiter) MarkOnlineDeviceReported() {
	l.userDevices.Range(func(_, value interface{}) bool {
		value.(*userDeviceState).markReported()
		return true
	})
}

// SetAliveIPs 设置面板下发的全节点在线 IP（uid => ips），at 为收到时间
func (l *Limiter) SetAliveIPs(devices map[int][]string, at time.Time) {
	l.aliveMu.Lock()
	l.aliveIPs = devices
	l.aliveIPsAt = at
	l.aliveMu.Unlock()
}

// getAlive 返回 alivelist 计数，以及未过期时的全节点在线 IP（用户不在线时为空切片而非 nil）
func (l *Limiter) getAlive(uid int) (int, []string) {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	if l.aliveIPs != nil && time.Since(l.aliveIPsAt) <= aliveIPsMaxAge {
		ips := l.aliveIPs[uid]
		if ips == nil {
			ips = []string{}
		}
		return len(ips), ips
	}
	return l.aliveList[uid], nil
}

func (l *Limiter) getOrCreateDeviceState(taguuid string, uid int) *userDeviceState {
	if v, ok := l.userDevices.Load(taguuid); ok {
		state := v.(*userDeviceState)
		state.setUID(uid)
		return state
	}
	state := newUserDeviceState(uid)
	actual, _ := l.userDevices.LoadOrStore(taguuid, state)
	deviceState := actual.(*userDeviceState)
	deviceState.setUID(uid)
	return deviceState
}
