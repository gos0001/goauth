package redis

import (
	"time"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

type Config struct {
	KeyPrefix  string        `json:"key_prefix"`
	DefaultTTL time.Duration `json:"default_ttl"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{KeyPrefix: "goauth:", DefaultTTL: time.Hour}
	if err := root.Section("redis", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
