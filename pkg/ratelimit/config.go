package ratelimit

import (
	"time"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

type Config struct {
	KeyPrefix string `json:"key_prefix"`

	// LoginIP bounds bulk traffic from one address bucket; LoginPair bounds
	// attempts against one account from one address. Both are written as
	// "<count>/<duration>".
	LoginIP   Rule `json:"login_ip"`
	LoginPair Rule `json:"login_pair"`
	Register  Rule `json:"register"`

	// Per-account exponential backoff after a wrong password.
	BackoffAfter  int           `json:"backoff_after"`
	BackoffBase   time.Duration `json:"backoff_base"`
	BackoffMax    time.Duration `json:"backoff_max"`
	FailureWindow time.Duration `json:"failure_window"`

	// FailClosed makes an unreachable Redis reject authentication attempts
	// rather than wave them through. Default true: a cache outage must not
	// silently open a brute-force window.
	FailClosed bool `json:"fail_closed"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		KeyPrefix:     "goauth:",
		LoginIP:       Rule{Limit: 100, Window: 15 * time.Minute},
		LoginPair:     Rule{Limit: 10, Window: 15 * time.Minute},
		Register:      Rule{Limit: 20, Window: time.Hour},
		BackoffAfter:  3,
		BackoffBase:   time.Second,
		BackoffMax:    60 * time.Second,
		FailureWindow: 15 * time.Minute,
		FailClosed:    true,
	}
	if err := root.Section("ratelimit", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
