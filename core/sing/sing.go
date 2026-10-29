package sing

import (
	"context"
	"fmt"
	"os"
	"sync"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"

	"github.com/InazumaV/V2bX/conf"
	vCore "github.com/InazumaV/V2bX/core"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	llog "github.com/sirupsen/logrus"
)

var _ vCore.Core = (*Sing)(nil)

type DNSConfig struct {
	Servers []map[string]interface{} `json:"servers"`
	Rules   []map[string]interface{} `json:"rules"`
}

type Sing struct {
	box                       *box.Box
	ctx                       context.Context
	hookServer                *HookServer
	router                    adapter.Router
	logFactory                log.Factory
	users                     *UserMap
	nodeReportMinTrafficBytes sync.Map // tag -> int64
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func init() {
	vCore.RegisterCore("sing", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	ctx := context.Background()
	ctx = box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	options := option.Options{}
	if len(c.SingConfig.OriginalPath) != 0 {
		data, err := os.ReadFile(c.SingConfig.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("read original config error: %s", err)
		}
		options, err = json.UnmarshalExtendedContext[option.Options](ctx, data)
		if err != nil {
			return nil, fmt.Errorf("unmarshal original config error: %s", err)
		}
	}
	logConfig := c.SingConfig.LogConfig.Normalized()
	options.Log = &option.LogOptions{
		Disabled:  logConfig.Disabled,
		Level:     logConfig.Level,
		Timestamp: logConfig.Timestamp,
		Output:    logConfig.Output,
	}
	options.NTP = &option.NTPOptions{
		Enabled:       c.SingConfig.NtpConfig.Enable,
		WriteToSystem: true,
		ServerOptions: option.ServerOptions{
			Server:     c.SingConfig.NtpConfig.Server,
			ServerPort: c.SingConfig.NtpConfig.ServerPort,
		},
	}
	if options.DNS == nil || len(options.DNS.Servers) == 0 {
		defaultDNS, err := defaultSingDNS(ctx)
		if err != nil {
			llog.WithField("err", err).Warn("Failed to build default DNS for sing-box, using empty DNS")
		} else {
			options.DNS = defaultDNS
			llog.Info("No custom DNS configured for sing-box, using system resolver")
		}
	}
	ensureSniffRule(&options)
	os.Setenv("SING_DNS_PATH", "")
	b, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return nil, err
	}
	hs := &HookServer{
		counter: sync.Map{},
	}
	b.Router().AppendTracker(hs)
	if r, ok := b.Router().(interface {
		SetOutboundOverride(func(*adapter.InboundContext) string)
	}); ok {
		r.SetOutboundOverride(relayOutboundTag)
	}
	return &Sing{
		ctx:        b.Router().GetCtx(),
		box:        b,
		hookServer: hs,
		router:     b.Router(),
		logFactory: b.LogFactory(),
		users: &UserMap{
			uidMap: make(map[string]int),
		},
	}, nil
}

func (b *Sing) Start() error {
	return b.box.Start()
}

func (b *Sing) Close() error {
	return b.box.Close()
}

func (b *Sing) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
		"tuic",
		"anytls",
		"hysteria",
		"hysteria2",
	}
}

func (b *Sing) Type() string {
	return "sing"
}

func defaultSingDNS(ctx context.Context) (*option.DNSOptions, error) {
	defaultJSON := []byte(`{
		"dns": {
			"servers": [
				{"tag": "local", "type": "local"}
			],
			"final": "local"
		}
	}`)
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, defaultJSON)
	if err != nil {
		return nil, err
	}
	return opts.DNS, nil
}

// sing-box 1.11+ ignores inbound sniff fields; metadata.Protocol is only set by a route "sniff" action,
// and the BitTorrent ban in HookServer depends on it.
func ensureSniffRule(options *option.Options) {
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	for _, r := range options.Route.Rules {
		if (r.Type == "" || r.Type == C.RuleTypeDefault) && r.DefaultOptions.Action == C.RuleActionTypeSniff {
			return
		}
	}
	sniff := option.Rule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeSniff}},
	}
	options.Route.Rules = append([]option.Rule{sniff}, options.Route.Rules...)
}
