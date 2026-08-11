package middleware

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// AdminToken authenticates machines on the private admin listener. Empty
	// means the private listener does not start at all — never a default token,
	// never open access.
	AdminToken string `envconfig:"ADMIN_TOKEN"`

	// ReauthWindow is how recently a password must have been presented for
	// destructive admin operations to be accepted. A stolen browser session
	// without the password can then read, but not destroy.
	ReauthWindow time.Duration `envconfig:"ADMIN_REAUTH_WINDOW" default:"15m"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

// AdminTokenEnabled reports whether the machine-facing listener has a credential
// to check against.
func (c Config) AdminTokenEnabled() bool { return c.AdminToken != "" }
