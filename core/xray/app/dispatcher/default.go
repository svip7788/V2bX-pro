package dispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/InazumaV/V2bX/common/counter"
	"github.com/InazumaV/V2bX/common/probe"
	"github.com/InazumaV/V2bX/common/rate"
	"github.com/InazumaV/V2bX/limiter"
	llog "github.com/sirupsen/logrus"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var errSniffingTimeout = errors.New("timeout on sniffing")

const bittorrentProtocol = "bittorrent"

var sniffBufPool = sync.Pool{
	New: func() interface{} {
		return buf.NewWithSize(32767)
	},
}

type cachedReader struct {
	sync.Mutex
	reader buf.TimeoutReader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer, deadline time.Duration) error {
	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	if err != nil {
		return err
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(min(r.cache.Len(), b.Cap()))
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
	return nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) peek(b *buf.Buffer) {
	r.Lock()
	b.Clear()
	n := r.cache.Copy(b.Extend(min(r.cache.Len(), b.Cap())))
	b.Resize(0, int32(n))
	r.Unlock()
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	if p, ok := r.reader.(*pipe.Reader); ok {
		p.Interrupt()
	}
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm          outbound.Manager
	router       routing.Router
	policy       policy.Manager
	stats        stats.Manager
	fdns         dns.FakeDNSEngine
	Counter      sync.Map
	LinkManagers sync.Map // map[string]*LinkManager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, dc dns.Client) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error { return nil }

func (d *DefaultDispatcher) getLink(ctx context.Context, network net.Network) (*transport.Link, *transport.Link, *limiter.Limiter, error) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	var limit *limiter.Limiter
	var err error
	if user != nil && len(user.Email) > 0 {
		limit, err = limiter.GetLimiter(sessionInbound.Tag)
		if err != nil {
			errors.LogInfo(ctx, "get limiter ", sessionInbound.Tag, " error: ", err)
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, nil, errors.New("get limiter ", sessionInbound.Tag, " error: ", err)
		}
		// Speed Limit and Device Limit
		w, reject := limit.CheckLimit(user.Email,
			sessionInbound.Source.Address.IP().String(),
			network == net.Network_TCP,
			sessionInbound.Source.Network == net.Network_TCP)
		if reject {
			errors.LogInfo(ctx, "Limited ", user.Email, " by conn or ip")
			common.Close(outboundLink.Writer)
			common.Close(inboundLink.Writer)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, nil, errors.New("Limited ", user.Email, " by conn or ip")
		}
		lm := d.getOrCreateLinkManager(user.Email)
		managedWriter := &ManagedWriter{
			writer:  uplinkWriter,
			manager: lm,
		}
		lm.AddLink(managedWriter, outboundLink.Reader, sessionInbound.Conn)
		// Safety net: the tracking map holds a strong reference to the
		// connection and is normally cleaned up via ManagedWriter.Close().
		// Some connections end without an explicit Close (xray abandons the
		// link and relies on GC), which would pin them in the map forever.
		// Removing them when the per-connection context is cancelled bounds
		// the leak to the connection lifetime. Close is idempotent.
		context.AfterFunc(ctx, func() { _ = managedWriter.Close() })
		inboundLink.Writer = managedWriter
		if w != nil {
			sessionInbound.CanSpliceCopy = 3
			inboundLink.Writer = rate.NewRateLimitWriter(inboundLink.Writer, w)
			outboundLink.Writer = rate.NewRateLimitWriter(outboundLink.Writer, w)
		}
		t := d.getOrCreateCounter(sessionInbound.Tag)

		ts := t.GetCounter(user.Email)
		upcounter := &counter.XrayTrafficCounter{V: &ts.UpCounter}
		downcounter := &counter.XrayTrafficCounter{V: &ts.DownCounter}
		inboundLink.Writer = &dispatcher.SizeStatWriter{
			Counter: upcounter,
			Writer:  inboundLink.Writer,
		}
		outboundLink.Writer = &dispatcher.SizeStatWriter{
			Counter: downcounter,
			Writer:  outboundLink.Writer,
		}
	}

	return inboundLink, outboundLink, limit, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	if request.ExcludeForDomain != nil && request.ExcludeForDomain.MatchAny(strings.ToLower(domain)) {
		return false
	}
	if request.ExcludeForIP != nil && destination.Address.Family().IsIP() && request.ExcludeForIP.Match(destination.Address.IP()) {
		return false
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest
	inbound, outbound, l, err := d.getLink(ctx, destination.Network)
	if err != nil {
		return nil, err
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination, l, "")
	} else {
		go func() {
			cReader := &cachedReader{
				reader: outbound.Reader.(*pipe.Reader),
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = net.ParseAddress(domain)
				protocol := result.Protocol()
				if resComp, ok := result.(SnifferResultComposite); ok {
					protocol = resComp.ProtocolForDomainResult()
				}
				isFakeIP := false
				if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && ob.Target.Address.Family().IsIP() && fkr0.IsIPInIPPool(ob.Target.Address) {
					isFakeIP = true
				}
				if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination, l, content.Protocol)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	var limit *limiter.Limiter
	var err error
	if user != nil && len(user.Email) > 0 {
		limit, err = limiter.GetLimiter(sessionInbound.Tag)
		if err != nil {
			errors.LogInfo(ctx, "get limiter ", sessionInbound.Tag, " error: ", err)
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
			return errors.New("get limiter ", sessionInbound.Tag, " error: ", err)
		}
		// Speed Limit and Device Limit
		w, reject := limit.CheckLimit(user.Email,
			sessionInbound.Source.Address.IP().String(),
			destination.Network == net.Network_TCP,
			sessionInbound.Source.Network == net.Network_TCP)
		if reject {
			errors.LogInfo(ctx, "Limited ", user.Email, " by conn or ip")
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
			return errors.New("Limited ", user.Email, " by conn or ip")
		}
		lm := d.getOrCreateLinkManager(user.Email)
		managedWriter := &ManagedWriter{
			writer:  outbound.Writer,
			manager: lm,
		}
		outbound.Writer = managedWriter
		if w != nil {
			sessionInbound.CanSpliceCopy = 3
			outbound.Writer = rate.NewRateLimitWriter(outbound.Writer, w)
		}
		t := d.getOrCreateCounter(sessionInbound.Tag)

		ts := t.GetCounter(user.Email)
		downcounter := &counter.XrayTrafficCounter{V: &ts.DownCounter}
		outbound.Reader = &CounterReader{
			Reader:  &buf.TimeoutWrapperReader{Reader: outbound.Reader},
			Counter: &ts.UpCounter,
		}
		lm.AddLink(managedWriter, outbound.Reader, sessionInbound.Conn)
		context.AfterFunc(ctx, func() { _ = managedWriter.Close() })
		outbound.Writer = &dispatcher.SizeStatWriter{
			Counter: downcounter,
			Writer:  outbound.Writer,
		}
	}

	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled {
		d.routedDispatch(ctx, outbound, destination, limit, "")
	} else {
		cReader := &cachedReader{
			reader: outbound.Reader.(buf.TimeoutReader),
		}
		outbound.Reader = cReader
		result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
		if err == nil {
			content.Protocol = result.Protocol()
		}
		if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
			domain := result.Domain()
			errors.LogInfo(ctx, "sniffed domain: ", domain)
			destination.Address = net.ParseAddress(domain)
			protocol := result.Protocol()
			if resComp, ok := result.(SnifferResultComposite); ok {
				protocol = resComp.ProtocolForDomainResult()
			}
			isFakeIP := false
			if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
				isFakeIP = true
			}
			if sniffingRequest.RouteOnly && protocol != "fakedns" && protocol != "fakedns+others" && !isFakeIP {
				ob.RouteTarget = destination
			} else {
				ob.Target = destination
			}
		}
		d.routedDispatch(ctx, outbound, destination, limit, content.Protocol)
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	payload := sniffBufPool.Get().(*buf.Buffer)
	defer func() {
		payload.Clear()
		sniffBufPool.Put(payload)
	}()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		cacheDeadline := 200 * time.Millisecond
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				cachingStartingTimeStamp := time.Now()
				err := cReader.Cache(payload, cacheDeadline)
				if err != nil {
					return nil, err
				}
				cachingTimeElapsed := time.Since(cachingStartingTimeStamp)
				cacheDeadline -= cachingTimeElapsed

				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					switch err {
					case common.ErrNoClue: // No Clue: protocol not matches, and sniffer cannot determine whether there will be a match or not
						totalAttempt++
					case protocol.ErrProtoNeedMoreData: // Protocol Need More Data: protocol matches, but need more data to complete sniffing
						// in this case, do not add totalAttempt(allow to read until timeout)
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				if totalAttempt >= 2 || cacheDeadline <= 0 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination, l *limiter.Limiter, protocol string) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]

	sessionInbound := session.InboundFromContext(ctx)
	if sessionInbound.User != nil {
		if l == nil {
			var err error
			l, err = limiter.GetLimiter(sessionInbound.Tag)
			if err != nil {
				errors.LogError(ctx, "get limiter ", sessionInbound.Tag, " error: ", err)
			}
		}
		if l != nil && protocol == bittorrentProtocol {
			email := sessionInbound.User.Email
			newly, banFor := l.BanBitTorrent(email)
			closed := 0
			if v, ok := d.LinkManagers.Load(email); ok {
				closed = v.(*LinkManager).CloseAll()
			}
			if newly {
				llog.WithFields(llog.Fields{
					"user":   email,
					"ip":     sessionInbound.Source.Address.String(),
					"dest":   destination.String(),
					"ban":    banFor.String(),
					"closed": closed,
				}).Warn("BitTorrent detected, user banned on this node")
			}
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
		if l != nil {
			var destStr string
			if destination.Address.Family().IsDomain() {
				destStr = destination.Address.Domain()
			} else {
				destStr = destination.Address.IP().String()
			}
			if l.CheckDomainRule(destStr) {
				errors.LogError(ctx, fmt.Sprintf(
					"User %s access domain %s reject by rule",
					sessionInbound.User.Email,
					destStr))
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
			if len(protocol) != 0 {
				if l.CheckProtocolRule(protocol) {
					errors.LogError(ctx, fmt.Sprintf(
						"User %s access protocol %s reject by rule",
						sessionInbound.User.Email,
						protocol))
					common.Close(link.Writer)
					common.Interrupt(link.Reader)
					return
				}
			}
		}
	}

	if destination.Network == net.Network_TCP && destination.Port == probe.Port && replyLatencyProbe(ctx, link, destination) {
		return
	}

	var handler outbound.Handler

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				if route.GetRuleTag() == "" {
					errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				} else {
					errors.LogInfo(ctx, "Hit route rule: [", route.GetRuleTag(), "] so taking detour [", outTag, "] for [", destination, "]")
				}
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	ob.Tag = handler.Tag()
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}

func multiBufferBytes(mb buf.MultiBuffer) []byte {
	b := make([]byte, mb.Len())
	mb.Copy(b)
	buf.ReleaseMulti(mb)
	return b
}

// replyLatencyProbe 明文测速请求由节点直接应答（keep-alive），不再拨号出站；不匹配时已读数据留在 link.Reader 里继续转发
func replyLatencyProbe(ctx context.Context, link *transport.Link, destination net.Destination) bool {
	reader, ok := link.Reader.(buf.TimeoutReader)
	if !ok {
		return false
	}
	cReader, ok := reader.(*cachedReader)
	if !ok {
		cReader = &cachedReader{reader: reader}
		link.Reader = cReader
	}
	payload := buf.New()
	defer payload.Release()
	cReader.peek(payload)
	deadline := time.Now().Add(probe.PeekTimeout)
	for !probe.RequestLineComplete(payload.Bytes()) && payload.Len() < payload.Cap() {
		remaining := time.Until(deadline)
		if remaining <= 0 || cReader.Cache(payload, remaining) != nil {
			break
		}
	}
	var host string
	if destination.Address.Family().IsDomain() {
		host = destination.Address.Domain()
	}
	if probe.Match(host, payload.Bytes()) == nil {
		return false
	}
	probe.Serve(host, multiBufferBytes(cReader.readInternal()), func(timeout time.Duration) ([]byte, error) {
		mb, err := cReader.ReadMultiBufferTimeout(timeout)
		return multiBufferBytes(mb), err
	}, func(b []byte) error {
		return link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, b))
	})
	common.Close(link.Writer)
	common.Interrupt(link.Reader)
	errors.LogInfo(ctx, "reply latency probe for [", destination, "]")
	return true
}

func (d *DefaultDispatcher) getOrCreateCounter(tag string) *counter.TrafficCounter {
	if c, ok := d.Counter.Load(tag); ok {
		return c.(*counter.TrafficCounter)
	}
	c, _ := d.Counter.LoadOrStore(tag, counter.NewTrafficCounter())
	return c.(*counter.TrafficCounter)
}

func (d *DefaultDispatcher) getOrCreateLinkManager(email string) *LinkManager {
	if v, ok := d.LinkManagers.Load(email); ok {
		lm := v.(*LinkManager)
		lm.markOwner(email, &d.LinkManagers)
		return lm
	}
	v, _ := d.LinkManagers.LoadOrStore(email, &LinkManager{
		links: make(map[*ManagedWriter]managedLink),
		key:   email,
		owner: &d.LinkManagers,
	})
	lm := v.(*LinkManager)
	lm.markOwner(email, &d.LinkManagers)
	return lm
}
