package authcookie

import (
	"fmt"
	"strings"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// Enabled turns the cookie channel on. Off by default: JSON plus the
	// Authorization header is the API goauth promises, and a cookie channel is
	// a deployment's opt-in, not a change forced on every client.
	Enabled bool `json:"enabled"`

	// Secure marks the cookies HTTPS-only. The default is the safe direction;
	// plain HTTP on localhost still works because current browsers treat it as
	// a secure context, so this rarely needs touching in development.
	Secure bool `json:"secure"`

	// SameSite is "strict" or "lax". Strict is the default because these
	// cookies are credentials: a request another site provoked must not carry
	// them. The cost is that following a link from a mail client or a chat
	// arrives without cookies on the first hop — "lax" trades that away for
	// top-level navigations if a frontend would rather show a logged-in page
	// immediately.
	SameSite string `json:"samesite"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{Secure: true, SameSite: "strict"}
	if err := root.Section("authcookie", &cfg); err != nil {
		return cfg, err
	}

	// Parsed at startup so a typo fails the boot rather than surfacing as
	// cookies that behave differently from the ones the frontend expected.
	cfg.SameSite = strings.ToLower(strings.TrimSpace(cfg.SameSite))
	if cfg.SameSite != "strict" && cfg.SameSite != "lax" {
		return cfg, fmt.Errorf(
			"authcookie: samesite must be \"strict\" or \"lax\", got %q", cfg.SameSite)
	}

	return cfg, nil
}
