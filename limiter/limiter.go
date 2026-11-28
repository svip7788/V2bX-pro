package limiter

import (
	"errors"
	"net/netip"
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

	relayRules     []relayRule
	dnsRules       []dnsRule
	ruleMu         sync.RWMutex
	aliveMu        sync.RWMutex
	userInfoMu     sync.Mutex
	userLimitInfo  sync.Map // taguuid -> *UserLimitInfo
	speedBuckets   sync.Map // taguuid -> *BucketHolder
	userDevices    sync.Map // taguuid -> *userDeviceState
	uuidToUID      sync.Map // uuid -> int
	aliveList      map[int]int
	aliveIPs       map[int][]string // 面板 sync.devices 下发的全节点在线 IP，nil 表示只有计数
	aliveIPsPrefix int
	aliveIPsAt     time.Time
	excess         map[int]map[string]struct{} // 面板裁决的超限设备计数键，拒绝其连接
	excessAt       time.Time
	dyWhitelist    map[int]struct{}
	dyTimeRanges   []timeRange
	dyConfig       conf.DynamicSpeedLimitConfig
	dyApplied      bool
	btBanDuration  time.Duration
	btBanned       sync.Map // taguuid -> int64 (ban expiry, unix nano)
	allowBT        atomic.Bool
	connLimit      atomic.Int64 // 节点默认的用户并发连接数上限，面板可热更新
	egressUsers    atomic.Pointer[egressTable]
}

const bucketFillInterval = 50 * time.Millisecond

type speedBucketState struct {
	bucket   *ratelimit.Bucket
	expireAt int64
}

// BucketHolder 持有用户当前的限速桶指针，限速变更或到期时原地切换，现有连接无需重连即可生效
type BucketHolder struct {
	state   atomic.Pointer[speedBucketState]
	refresh func()
}

// Current 返回当前有效限速桶；临时限速（动态/平分）到期时自动刷新
func (h *BucketHolder) Current() *ratelimit.Bucket {
	if h == nil {
		return nil
	}
	s := h.state.Load()
	if s == nil {
		return nil
	}
	if s.expireAt > 0 && time.Now().Unix() >= s.expireAt {
		if h.refresh != nil {
			h.refresh()
		}
		s = h.state.Load()
		if s == nil {
			return nil
		}
	}
	return s.bucket
}

func newSmoothBucket(limitMbps int) *ratelimit.Bucket {
	if limitMbps <= 0 {
		return nil
	}
	limit := int64(limitMbps) * 1000000 / 8
	quantum := max(1, limit/20)
	return ratelimit.NewBucketWithQuantum(bucketFillInterval, limit, quantum)
}

const defaultBTBanDuration = 2 * time.Minute

// WS 断开后不再有 sync.devices，过期的 IP 列表不能继续放行，退回只按计数判断
const aliveIPsMaxAge = 10 * time.Minute

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	ConnLimit         int
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
// 变高不断开，现有连接通过动态限速桶自动恢复）
func (l *Limiter) UpdateSpeedShare(tag, uuid string, divisor int, expire time.Time) (bool, error) {
	key := format.UserTag(tag, uuid)
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	v, ok := l.userLimitInfo.Load(key)
	if !ok {
		return false, errors.New("not found")
	}
	old := v.(*UserLimitInfo)
	now := time.Now().Unix()
	info := *old
	info.ShareDivisor = divisor
	info.ShareExpire = expire.Unix()
	if divisor <= 1 || info.ShareExpire <= now {
		info.ShareDivisor, info.ShareExpire = 0, 0
	}
	l.userLimitInfo.Store(key, &info)
	l.syncSpeedBucketLocked(key, &info, now)
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
	info.SetConnLimit(l.ConnLimit)
	if l.BTBanMinutes > 0 {
		info.btBanDuration = time.Duration(l.BTBanMinutes) * time.Minute
	}
	info.SetDynamicConfig(l)
	for i := range users {
		info.uuidToUID.Store(users[i].Uuid, users[i].Id)
		ul := &UserLimitInfo{
			UID:       users[i].Id,
			ConnLimit: users[i].ConnLimit,
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
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	now := time.Now().Unix()
	for i := range deleted {
		key := format.UserTag(tag, deleted[i].Uuid)
		l.userLimitInfo.Delete(key)
		l.userDevices.Delete(key)
		if v, ok := l.speedBuckets.LoadAndDelete(key); ok {
			v.(*BucketHolder).state.Store(nil)
		}
		l.btBanned.Delete(key)
		l.uuidToUID.Delete(deleted[i].Uuid)
		l.aliveMu.Lock()
		delete(l.aliveList, deleted[i].Id)
		l.aliveMu.Unlock()
	}
	for i := range added {
		key := format.UserTag(tag, added[i].Uuid)
		ul := &UserLimitInfo{
			UID:       added[i].Id,
			ConnLimit: added[i].ConnLimit,
		}
		if added[i].SpeedLimit != 0 {
			ul.SpeedLimit = added[i].SpeedLimit
			ul.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			ul.DeviceLimit = added[i].DeviceLimit
		}
		l.userLimitInfo.Store(key, ul)
		l.uuidToUID.Store(added[i].Uuid, added[i].Id)
		l.syncSpeedBucketLocked(key, ul, now)
	}
}

// UserConnLimit 返回用户在本节点的并发连接数上限，面板下发值优先，否则用节点配置，0 为不限
func (l *Limiter) UserConnLimit(taguuid string) int {
	if v, ok := l.userLimitInfo.Load(taguuid); ok {
		if n := v.(*UserLimitInfo).ConnLimit; n > 0 {
			return n
		}
	}
	return int(l.connLimit.Load())
}

// SetConnLimit 更新节点默认的连接数上限，只影响之后的新连接
func (l *Limiter) SetConnLimit(n int) {
	l.connLimit.Store(int64(max(0, n)))
}

// UpdateUserLimit 原地更新固定限速、设备数和连接数，保留动态限速、平分份额和在线设备状态；
// 返回生效限速变低的 uuid（限速桶在建连时取定，须断开现有连接才能生效）
func (l *Limiter) UpdateUserLimit(tag string, users []panel.UserInfo) (tightened []string) {
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	now := time.Now().Unix()
	for i := range users {
		key := format.UserTag(tag, users[i].Uuid)
		info := UserLimitInfo{UID: users[i].Id}
		oldLimit := l.SpeedLimit
		if v, ok := l.userLimitInfo.Load(key); ok {
			old := v.(*UserLimitInfo)
			info = *old
			oldLimit = l.effectiveSpeedLimit(old, now)
		}
		info.SpeedLimit = users[i].SpeedLimit
		info.DeviceLimit = users[i].DeviceLimit
		info.ConnLimit = users[i].ConnLimit
		l.userLimitInfo.Store(key, &info)
		l.uuidToUID.Store(users[i].Uuid, users[i].Id)
		l.syncSpeedBucketLocked(key, &info, now)
		if newLimit := l.effectiveSpeedLimit(&info, now); newLimit > 0 && (oldLimit == 0 || newLimit < oldLimit) {
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

// SetDynamicConfig 幂等；配置变化时解除已有动态限速，让新参数立即生效，返回配置是否发生变化。
// 与 IsWhitelisted/InDynamicLimitTimeRange 须在同一把锁（控制器 runtimeMu）下调用
func (l *Limiter) SetDynamicConfig(lc *conf.LimitConfig) bool {
	var cur conf.DynamicSpeedLimitConfig
	if lc.EnableDynamicSpeedLimit && lc.DynamicSpeedLimitConfig != nil {
		cur = *lc.DynamicSpeedLimitConfig
	}
	if l.dyApplied && l.dyConfig == cur {
		return false
	}
	if l.dyApplied {
		l.ClearDynamicSpeedLimit()
	}
	l.dyApplied, l.dyConfig = true, cur
	l.dyWhitelist = parseWhitelist(cur.DyLimitWhiteUserID)
	l.dyTimeRanges = parseTimeRanges(cur.DyLimitDuration)
	return true
}

// ClearDynamicSpeedLimit 立即解除所有用户的动态限速
func (l *Limiter) ClearDynamicSpeedLimit() {
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	now := time.Now().Unix()
	l.userLimitInfo.Range(func(k, v any) bool {
		u := v.(*UserLimitInfo)
		if u.DynamicSpeedLimit == 0 && u.ExpireTime == 0 {
			return true
		}
		info := *u
		info.DynamicSpeedLimit = 0
		info.ExpireTime = 0
		l.userLimitInfo.Store(k, &info)
		l.syncSpeedBucketLocked(k.(string), &info, now)
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
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	v, ok := l.userLimitInfo.Load(key)
	if !ok {
		return errors.New("not found")
	}
	now := time.Now().Unix()
	old := v.(*UserLimitInfo)
	info := *old
	if limit <= 0 {
		info.DynamicSpeedLimit = 0
		info.ExpireTime = 0
	} else {
		info.DynamicSpeedLimit = limit
		info.ExpireTime = expire.Unix()
	}
	l.userLimitInfo.Store(key, &info)
	l.syncSpeedBucketLocked(key, &info, now)
	return nil
}

// InheritFrom 在节点配置变更重建 Limiter 时，继承旧 Limiter 上未过期的动态限速、平分限速、BT 封禁及在线设备状态
func (l *Limiter) InheritFrom(oldTag, newTag string, old *Limiter) {
	if old == nil {
		return
	}
	now := time.Now().Unix()
	nowTime := time.Now()

	l.userInfoMu.Lock()
	l.userLimitInfo.Range(func(k, v any) bool {
		newKey := k.(string)
		uuid := strings.TrimPrefix(newKey, newTag+"|")
		oldKey := format.UserTag(oldTag, uuid)

		if ov, ok := old.userLimitInfo.Load(oldKey); ok {
			ou := ov.(*UserLimitInfo)
			nu := *v.(*UserLimitInfo)
			changed := false
			if ou.DynamicSpeedLimit > 0 && (ou.ExpireTime == 0 || ou.ExpireTime > now) {
				nu.DynamicSpeedLimit = ou.DynamicSpeedLimit
				nu.ExpireTime = ou.ExpireTime
				changed = true
			}
			if ou.ShareDivisor > 1 && ou.ShareExpire > now {
				nu.ShareDivisor = ou.ShareDivisor
				nu.ShareExpire = ou.ShareExpire
				changed = true
			}
			if changed {
				l.userLimitInfo.Store(newKey, &nu)
				l.syncSpeedBucketLocked(newKey, &nu, now)
			}
		}

		if bv, ok := old.btBanned.Load(oldKey); ok && bv.(int64) > nowTime.UnixNano() {
			l.btBanned.Store(newKey, bv)
		}

		if dv, ok := old.userDevices.Load(oldKey); ok {
			ods := dv.(*userDeviceState)
			ods.mu.Lock()
			var copiedCurrent, copiedReported map[string]string
			if len(ods.current) > 0 {
				copiedCurrent = make(map[string]string, len(ods.current))
				for dk, raw := range ods.current {
					copiedCurrent[dk] = raw
				}
			}
			if len(ods.reported) > 0 {
				copiedReported = make(map[string]string, len(ods.reported))
				for dk, raw := range ods.reported {
					copiedReported[dk] = raw
				}
			}
			uid := ods.uid
			ods.mu.Unlock()
			if len(copiedCurrent) > 0 || len(copiedReported) > 0 {
				l.userDevices.Store(newKey, &userDeviceState{
					uid:      uid,
					current:  copiedCurrent,
					reported: copiedReported,
				})
			}
		}
		return true
	})
	l.userInfoMu.Unlock()
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

func (l *Limiter) effectiveSpeedLimit(u *UserLimitInfo, now int64) int {
	s := u.sharedSpeedLimit(now)
	if u.DynamicSpeedLimit > 0 && (u.ExpireTime == 0 || u.ExpireTime > now) {
		s = determineSpeedLimit(s, u.DynamicSpeedLimit)
	}
	return determineSpeedLimit(l.SpeedLimit, s)
}

func (l *Limiter) nextLimitExpiry(u *UserLimitInfo, now int64) int64 {
	var exp int64
	if u.DynamicSpeedLimit > 0 && u.ExpireTime > now {
		exp = u.ExpireTime
	}
	if u.ShareDivisor > 1 && u.ShareExpire > now && (exp == 0 || u.ShareExpire < exp) {
		exp = u.ShareExpire
	}
	return exp
}

func (l *Limiter) getOrCreateBucketHolder(taguuid string) *BucketHolder {
	if v, ok := l.speedBuckets.Load(taguuid); ok {
		return v.(*BucketHolder)
	}
	h := &BucketHolder{
		refresh: func() { l.refreshSpeedBucket(taguuid) },
	}
	actual, _ := l.speedBuckets.LoadOrStore(taguuid, h)
	return actual.(*BucketHolder)
}

// SpeedBucketHolder 返回用户的动态限速桶持有者；建连一次取得，后续长连接可实时感知限速变化与到期恢复
func (l *Limiter) SpeedBucketHolder(taguuid string) *BucketHolder {
	h := l.getOrCreateBucketHolder(taguuid)
	if h.state.Load() == nil {
		l.refreshSpeedBucket(taguuid)
	}
	return h
}

func (l *Limiter) refreshSpeedBucket(taguuid string) {
	l.userInfoMu.Lock()
	defer l.userInfoMu.Unlock()
	v, ok := l.userLimitInfo.Load(taguuid)
	if !ok {
		if hv, ok := l.speedBuckets.Load(taguuid); ok {
			hv.(*BucketHolder).state.Store(nil)
		}
		return
	}
	now := time.Now().Unix()
	u := v.(*UserLimitInfo)
	cleaned := false
	info := *u
	if info.ExpireTime != 0 && info.ExpireTime <= now {
		info.DynamicSpeedLimit = 0
		info.ExpireTime = 0
		cleaned = true
	}
	if info.ShareExpire != 0 && info.ShareExpire <= now {
		info.ShareDivisor = 0
		info.ShareExpire = 0
		cleaned = true
	}
	if cleaned {
		l.userLimitInfo.Store(taguuid, &info)
		u = &info
	}
	l.syncSpeedBucketLocked(taguuid, u, now)
}

// syncSpeedBucketLocked 须持有 l.userInfoMu
func (l *Limiter) syncSpeedBucketLocked(taguuid string, u *UserLimitInfo, now int64) {
	h := l.getOrCreateBucketHolder(taguuid)
	limitMbps := l.effectiveSpeedLimit(u, now)
	if limitMbps <= 0 {
		h.state.Store(nil)
		return
	}
	expireAt := l.nextLimitExpiry(u, now)
	wantCap := int64(limitMbps) * 1000000 / 8
	if cur := h.state.Load(); cur != nil && cur.bucket != nil && cur.bucket.Capacity() == wantCap {
		if cur.expireAt == expireAt {
			return
		}
		h.state.Store(&speedBucketState{bucket: cur.bucket, expireAt: expireAt})
		return
	}
	h.state.Store(&speedBucketState{
		bucket:   newSmoothBucket(limitMbps),
		expireAt: expireAt,
	})
}

func (l *Limiter) CheckLimit(taguuid string, ip string, isTcp bool, noSSUDP bool) (Bucket *ratelimit.Bucket, Reject bool) {
	key := deviceKey(ip)
	if !l.AllowBitTorrent() && l.isBitTorrentBanned(taguuid) {
		return nil, true
	}

	v, ok := l.userLimitInfo.Load(taguuid)
	if !ok {
		return nil, true
	}
	u := v.(*UserLimitInfo)
	deviceLimit := u.DeviceLimit
	uid := u.UID

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

	return l.SpeedBucketHolder(taguuid).Current(), false
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
	prefix := int(ipv4Prefix.Load())
	devices = normalizeAliveIPs(devices)
	l.aliveMu.Lock()
	l.aliveIPs = devices
	l.aliveIPsPrefix = prefix
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

// getAlive 返回 alivelist 计数，以及未过期时的全节点在线 IP（用户不在线时为空切片而非 nil）；
// 已判超限的设备被踢后还会在面板汇总里停留一两个上报周期，不占名额
func (l *Limiter) getAlive(uid int) (int, []string) {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	excess := l.excess[uid]
	if time.Since(l.excessAt) > aliveIPsMaxAge {
		excess = nil
	}
	if l.aliveIPs != nil && time.Since(l.aliveIPsAt) <= aliveIPsMaxAge {
		curPrefix := int(ipv4Prefix.Load())
		recheck := l.aliveIPsPrefix != curPrefix
		ips := l.aliveIPs[uid]
		if ips == nil {
			ips = []string{}
		}
		if recheck || len(excess) > 0 {
			kept := make([]string, 0, len(ips))
			var seen map[string]struct{}
			if recheck {
				seen = make(map[string]struct{}, len(ips))
			}
			for _, k := range ips {
				if recheck {
					k = deviceKey(k)
					if _, dup := seen[k]; dup {
						continue
					}
					seen[k] = struct{}{}
				}
				if _, ok := excess[k]; !ok {
					kept = append(kept, k)
				}
			}
			ips = kept
		}
		return len(ips), ips
	}
	return max(0, l.aliveList[uid]-len(excess)), nil
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
