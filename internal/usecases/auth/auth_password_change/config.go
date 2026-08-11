package auth_password_change

import "github.com/kelseyhightower/envconfig"

type Config struct {
	MinPasswordLength int `envconfig:"AUTH_MIN_PASSWORD_LEN" default:"12"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
