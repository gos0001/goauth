package auth_register

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Registration modes. The default is closed, because the common case for this
// service is a paid panel whose accounts are created by an admin or by a
// payment webhook — an open endpoint there only collects bots.
const (
	ModeClosed = "closed"
	ModeOpen   = "open"
)

type Config struct {
	Mode              string `envconfig:"AUTH_REGISTRATION_MODE" default:"closed"`
	MinPasswordLength int    `envconfig:"AUTH_MIN_PASSWORD_LEN"  default:"12"`

	// RequireEmail makes an email address mandatory at registration. Off by
	// default: goauth sends no mail, so an address it cannot verify is just an
	// identifier like any other.
	RequireEmail bool `envconfig:"AUTH_REGISTRATION_REQUIRE_EMAIL" default:"false"`
}

func (c Config) Open() bool { return c.Mode == ModeOpen }

func LoadConfig() (Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, err
	}

	switch cfg.Mode {
	case ModeClosed, ModeOpen:
	default:
		return cfg, fmt.Errorf("auth_register: AUTH_REGISTRATION_MODE must be %q or %q, got %q",
			ModeClosed, ModeOpen, cfg.Mode)
	}

	return cfg, nil
}
