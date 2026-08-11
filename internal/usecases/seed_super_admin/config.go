package seed_super_admin

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// Username and Password bootstrap the first admin. Leaving Username empty
	// disables seeding entirely.
	Username string `envconfig:"SUPER_ADMIN_USERNAME"`
	Password string `envconfig:"SUPER_ADMIN_PASSWORD"`
	Email    string `envconfig:"SUPER_ADMIN_EMAIL"`

	MinPasswordLength int `envconfig:"AUTH_MIN_PASSWORD_LEN" default:"12"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

func (c Config) Enabled() bool { return c.Username != "" || c.Email != "" }
