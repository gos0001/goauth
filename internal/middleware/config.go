package middleware

import (
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// AdminToken authenticates machines on the private admin listener. Empty
	// means the private listener does not start at all — never a default token,
	// never open access.
	AdminToken string `json:"token"`

	// ReauthWindow is how recently a password must have been presented for
	// destructive admin operations to be accepted. A stolen browser session
	// without the password can then read, but not destroy.
	ReauthWindow time.Duration `json:"reauth_window"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{ReauthWindow: 15 * time.Minute}
	if err := root.Section("admin", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// AdminTokenEnabled reports whether the machine-facing listener has a credential
// to check against.
func (c Config) AdminTokenEnabled() bool { return c.AdminToken != "" }
