package limiter

import (
	"errors"
	"net/netip"
	"regexp"
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
	excess        map[int]map[string]struct{} // 面板裁决的超限设备计数键，拒绝其连接
	excessAt      time.Time
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
	uid int
	mu  sync.Mutex
	// 设备计数键（deviceKey）=> 最近一次的原始 IP；上报原始 IP，面板按自己的口径归并并用于展示、查归属地
	current  map[string]string
	reported map[string]string
}

func newUserDeviceState(uid int) *userDeviceState {
	return &userDeviceState{
		uid:     uid,
		current: make(map[string]string),
	}
}

func (s *userDeviceState) setUID(uid int) {
	s.mu.Lock()
	s.uid = uid
	if s.current == nil {
		s.current = make(map[string]string)
	}
	s.mu.Unlock()
}

// allow 返回 true 表示拒绝。key 为 deviceKey 归并后的计数键，raw 为原始 IP。
// aliveIPs 非 nil 时是面板汇总的全节点在线 IP：
// 已在其中的 IP 是同一设备换节点或多节点并用，直接放行；设备数按本节点与全节点 IP 的并集计。
// aliveIPs 为 nil（只有 alivelist 计数）时只能取两者较大值。
func (s *userDeviceState) allow(key, raw string, deviceLimit int, aliveCount int, aliveIPs []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		s.current = make(map[string]string)
	}
	if _, exists := s.current[key]; exists {
		s.current[key] = raw
		return false
	}
	if _, exists := s.reported[key]; exists {
		delete(s.reported, key)
		s.current[key] = raw
		return false
	}
	knownCount := len(s.current) + len(s.reported)
	if aliveIPs != nil {
		for _, g := range aliveIPs {
			if g == key {
				s.current[key] = raw
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
	s.current[key] = raw
	return false
}

func (s *userDeviceState) snapshotCurrent() []panel.OnlineUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.current) == 0 {
		return nil
	}
	users := make([]panel.OnlineUser, 0, len(s.current))
	for _, raw := range s.current {
		users = append(users, panel.OnlineUser{
			UID: s.uid,
			IP:  raw,
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
	s.current = make(map[string]string, len(s.reported))
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

var ipv4Prefix atomic.Int32

// SetIPv4Prefix 设置设备计数的 IPv4 归并前缀（面板随 alivelist 下发），<8 或 >=32 为不归并
func SetIPv4Prefix(prefix int) {
	if prefix < 8 || prefix > 32 {
		prefix = 32
	}
	ipv4Prefix.Store(int32(prefix))
}

// deviceKey 设备计数用的 IP 键：IPv6 临时地址会定期更换，同一 /64 视为同一设备；
// 移动网络 CGNAT 出口 IPv4 频繁变动，按面板下发的前缀归并
func deviceKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		if p := int(ipv4Prefix.Load()); p >= 8 && p < 32 {
			pfx, _ := addr.Prefix(p)
			return pfx.String()
		}
		return addr.String()
	}
	p, _ := addr.WithZone("").Prefix(64)
	return p.String()
}

// TouchActiveDevices 把仍有活跃连接的 IP 记入本轮设备：设备只在建连时登记，
// 长连接（mux、gRPC、QUIC 等）不再建新连接时，否则两轮后就从上报中消失、让出名额
func (l *Limiter) TouchActiveDevices(tag string, active map[string][]string) {
	for uuid, ips := range active {
		uid, ok := l.GetUIDByUUID(uuid)
		if !ok {
			continue
		}
		state := l.getOrCreateDeviceState(format.UserTag(tag, uuid), uid)
		state.mu.Lock()
		if state.current == nil {
			state.current = make(map[string]string, len(ips))
		}
		for _, ip := range ips {
			if l.IsExcess(uid, ip) {
				continue
			}
			key := deviceKey(ip)
			state.current[key] = ip
			delete(state.reported, key)
		}
		state.mu.Unlock()
	}
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	key := deviceKey(ip)
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

	// 超限设备的 UDP 也拒绝，否则踢掉 TCP 后仍能走 UDP
	if deviceLimit > 0 && l.IsExcess(uid, ip) {
		return nil, true
	}
	if noSSUDP {
		aliveCount, aliveIPs := l.getAlive(uid)
		state := l.getOrCreateDeviceState(taguuid, uid)
		if state.allow(key, ip, deviceLimit, aliveCount, aliveIPs) {
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
	devices = normalizeAliveIPs(devices)
	l.aliveMu.Lock()
	l.aliveIPs = devices
	l.aliveIPsAt = at
	l.aliveMu.Unlock()
}

// SetExcess 设置面板裁决的超限设备（uid => 计数键），并从本节点设备状态中移除，at 为收到时间；
// 面板按全节点首次上线先到先留，各节点结论一致
func (l *Limiter) SetExcess(excess map[int][]string, at time.Time) {
	var sets map[int]map[string]struct{}
	if len(excess) > 0 {
		sets = make(map[int]map[string]struct{}, len(excess))
		for uid, keys := range excess {
			set := make(map[string]struct{}, len(keys))
			for _, k := range keys {
				set[deviceKey(k)] = struct{}{}
			}
			sets[uid] = set
		}
	}
	l.aliveMu.Lock()
	l.excess, l.excessAt = sets, at
	l.aliveMu.Unlock()
	if sets == nil {
		return
	}
	l.userDevices.Range(func(_, value any) bool {
		state := value.(*userDeviceState)
		state.mu.Lock()
		if set, ok := sets[state.uid]; ok {
			for k := range set {
				delete(state.current, k)
				delete(state.reported, k)
			}
		}
		state.mu.Unlock()
		return true
	})
}

// IsExcess 该 IP 是否属于面板判定超限的设备；超过 aliveIPsMaxAge 没收到新裁决则不再生效
func (l *Limiter) IsExcess(uid int, ip string) bool {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	set, ok := l.excess[uid]
	if !ok || time.Since(l.excessAt) > aliveIPsMaxAge {
		return false
	}
	_, ok = set[deviceKey(ip)]
	return ok
}

// normalizeAliveIPs 旧版节点上报的是原始 IPv6，按 deviceKey 归并去重后再比对
func normalizeAliveIPs(devices map[int][]string) map[int][]string {
	if devices == nil {
		return nil
	}
	out := make(map[int][]string, len(devices))
	for uid, ips := range devices {
		keys := make([]string, 0, len(ips))
		seen := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			k := deviceKey(ip)
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				keys = append(keys, k)
			}
		}
		out[uid] = keys
	}
	return out
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
