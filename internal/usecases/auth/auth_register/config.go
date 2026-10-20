package auth_register

import (
	"fmt"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

// Registration modes. The default is closed, because the common case for this
// service is a paid panel whose accounts are created by an admin or by a
// payment webhook — an open endpoint there only collects bots.
const (
	ModeClosed = "closed"
	ModeOpen   = "open"
)

type Config struct {
	Mode              string `json:"registration_mode"`
	MinPasswordLength int    `json:"min_password_len"`

	// RequireEmail makes an email address mandatory at registration. Off by
	// default: goauth sends no mail, so an address it cannot verify is just an
	// identifier like any other.
	RequireEmail bool `json:"registration_require_email"`
}

func (c Config) Open() bool { return c.Mode == ModeOpen }

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{Mode: ModeClosed, MinPasswordLength: 12}
	if err := root.Section("auth", &cfg); err != nil {
		return cfg, err
	}

	switch cfg.Mode {
	case ModeClosed, ModeOpen:
	default:
		return cfg, fmt.Errorf("auth_register: auth.registration_mode must be %q or %q, got %q",
			ModeClosed, ModeOpen, cfg.Mode)
	}

	return cfg, nil
}
