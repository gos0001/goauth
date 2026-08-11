package postgres

import "github.com/kelseyhightower/envconfig"

type Config struct {
	DSN string `envconfig:"POSTGRES_URL" required:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
