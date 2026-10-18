package cors

import (
	"github.com/google/wire"

	"github.com/gos0001/goauth/pkg/authcookie"
)

// NewWithCookies ties AllowCredentials to the authcookie channel: credentials
// headers exist for cookies and no other reason, so the two switches belong
// together where wire can keep them from drifting apart.
func NewWithCookies(cfg Config, cookies *authcookie.Cookies) (*Middleware, error) {
	cfg.AllowCredentials = cookies.Enabled()
	return New(cfg)
}

var Set = wire.NewSet(LoadConfig, NewWithCookies)
