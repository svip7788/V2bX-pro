package limiter

import (
	"errors"
	"regexp"
	"strings"
	"sync"
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

	ruleMu        sync.RWMutex
	aliveMu       sync.RWMutex
	userLimitInfo sync.Map // taguuid -> *UserLimitInfo
	speedLimiter  sync.Map // taguuid -> *ratelimit.Bucket
	userDevices   sync.Map // taguuid -> *userDeviceState
	uuidToUID     sync.Map // uuid -> int
	aliveList     map[int]int
	dyWhitelist   map[int]struct{}
	dyTimeRanges  []timeRange
	btBanDuration time.Duration
	btBanned      sync.Map // taguuid -> int64 (ban expiry, unix nano)
}

const defaultBTBanDuration = 2 * time.Minute

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
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

func (s *userDeviceState) allow(ip string, deviceLimit int, aliveCount int) bool {
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
	if aliveCount > knownCount {
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
	if l.DynamicSpeedLimitConfig != nil {
		info.dyWhitelist = parseWhitelist(l.DynamicSpeedLimitConfig.DyLimitWhiteUserID)
		info.dyTimeRanges = parseTimeRanges(l.DynamicSpeedLimitConfig.DyLimitDuration)
	}
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

func (l *Limiter) IsWhitelisted(uid int) bool {
	if l.dyWhitelist == nil {
		return false
	}
	_, ok := l.dyWhitelist[uid]
	return ok
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
	dynamicExpired := u.ExpireTime != 0 && u.ExpireTime < time.Now().Unix()
	if dynamicExpired {
		userLimit = u.SpeedLimit
	} else if u.DynamicSpeedLimit > 0 {
		userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
	} else {
		userLimit = u.SpeedLimit
	}

	if noSSUDP {
		aliveIp := l.getAliveCount(uid)
		state := l.getOrCreateDeviceState(taguuid, uid)
		if state.allow(ip, deviceLimit, aliveIp) {
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

func (l *Limiter) getAliveCount(uid int) int {
	l.aliveMu.RLock()
	defer l.aliveMu.RUnlock()
	return l.aliveList[uid]
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
