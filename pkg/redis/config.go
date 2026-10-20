package redis

import (
	"errors"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

type Config struct {
	URL string `json:"url"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{}
	if err := root.Section("redis", &cfg); err != nil {
		return Config{}, err
	}
	if cfg.URL == "" {
		return Config{}, errors.New("redis.url is required")
	}
	return cfg, nil
}
