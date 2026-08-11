package redis

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	KeyPrefix  string        `envconfig:"REDIS_KEY_PREFIX"  default:"goauth:"`
	DefaultTTL time.Duration `envconfig:"REDIS_DEFAULT_TTL" default:"1h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
