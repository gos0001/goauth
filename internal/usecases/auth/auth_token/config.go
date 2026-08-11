package auth_token

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// FailClosed makes an unreachable Redis reject login attempts rather than
	// wave them through. A cache outage must not silently open a brute-force
	// window on the one endpoint that checks passwords.
	FailClosed bool `envconfig:"RATELIMIT_FAIL_CLOSED" default:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
