package redis

import "github.com/kelseyhightower/envconfig"

type Config struct {
	URL string `envconfig:"REDIS_URL" required:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
