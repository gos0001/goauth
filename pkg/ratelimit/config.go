package ratelimit

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	KeyPrefix string `envconfig:"REDIS_KEY_PREFIX" default:"goauth:"`

	// LoginIP bounds bulk traffic from one address bucket; LoginPair bounds
	// attempts against one account from one address. Both are written as
	// "<count>/<duration>".
	LoginIP   Rule `envconfig:"RATELIMIT_LOGIN_IP"   default:"100/15m"`
	LoginPair Rule `envconfig:"RATELIMIT_LOGIN_PAIR" default:"10/15m"`
	Register  Rule `envconfig:"RATELIMIT_REGISTER"   default:"20/1h"`

	// Per-account exponential backoff after a wrong password.
	BackoffAfter  int           `envconfig:"RATELIMIT_BACKOFF_AFTER"  default:"3"`
	BackoffBase   time.Duration `envconfig:"RATELIMIT_BACKOFF_BASE"   default:"1s"`
	BackoffMax    time.Duration `envconfig:"RATELIMIT_BACKOFF_MAX"    default:"60s"`
	FailureWindow time.Duration `envconfig:"RATELIMIT_FAILURE_WINDOW" default:"15m"`

	// FailClosed makes an unreachable Redis reject authentication attempts
	// rather than wave them through. Default true: a cache outage must not
	// silently open a brute-force window.
	FailClosed bool `envconfig:"RATELIMIT_FAIL_CLOSED" default:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
