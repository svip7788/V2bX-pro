package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/anytls"
	"google.golang.org/protobuf/proto"
)

// AnyTLSUser is a single user entry
// For ANYTLS, only password is required; level/email optional.
type AnyTLSUser struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

type AnyTLSServerConfig struct {
	Users []*AnyTLSUser `json:"users"`
	// Easier authoring: accept padding scheme as lines and join internally
	PaddingScheme []string `json:"paddingScheme"`
	FallbackAddr  string   `json:"fallbackAddr"`
	FallbackPort  uint32   `json:"fallbackPort"`
}

func (c *AnyTLSServerConfig) Build() (proto.Message, error) {
	if (c.FallbackAddr == "") != (c.FallbackPort == 0) || c.FallbackPort > 65535 {
		return nil, errors.New("ANYTLS: fallbackAddr and fallbackPort (1-65535) must be set together")
	}
	cfg := &anytls.ServerConfig{
		Users:        make([]*protocol.User, 0, len(c.Users)),
		FallbackAddr: c.FallbackAddr,
		FallbackPort: c.FallbackPort,
	}
	if len(c.PaddingScheme) > 0 {
		cfg.PaddingScheme = strings.Join(c.PaddingScheme, "\n")
	}
	for _, u := range c.Users {
		if u.Password == "" {
			return nil, errors.New("ANYTLS: user password required")
		}
		cfg.Users = append(cfg.Users, &protocol.User{
			Level: uint32(u.Level),
			Email: u.Email,
			Account: serial.ToTypedMessage(&anytls.Account{
				Password: u.Password,
			}),
		})
	}
	return cfg, nil
}

type AnyTLSClientConfig struct {
	Address                  *Address `json:"address"`
	Port                     uint16   `json:"port"`
	Email                    string   `json:"email"`
	Password                 string   `json:"password"`
	Level                    uint32   `json:"level"`
	IdleSessionCheckInterval uint32   `json:"idleSessionCheckInterval"` // seconds
	IdleSessionTimeout       uint32   `json:"idleSessionTimeout"`       // seconds
	MinIdleSession           int      `json:"minIdleSession"`
}

func (c *AnyTLSClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("ANYTLS: server address is required")
	}
	if c.Password == "" {
		return nil, errors.New("ANYTLS: password is required")
	}

	cfg := &anytls.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Level: c.Level,
				Email: c.Email,
				Account: serial.ToTypedMessage(&anytls.Account{
					Password: c.Password,
				}),
			},
		},
		IdleSessionCheckInterval: c.IdleSessionCheckInterval,
		IdleSessionTimeout:       c.IdleSessionTimeout,
	}
	if c.MinIdleSession < 0 {
		return nil, errors.New("ANYTLS: minIdleSession must be non-negative")
	}
	cfg.MinIdleSession = uint32(c.MinIdleSession)

	return cfg, nil
}
