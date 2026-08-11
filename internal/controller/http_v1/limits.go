package http_v1

import "github.com/gos0001/goauth/pkg/ratelimit"

// Limits carries the rate-limit rules the router attaches to the credential
// endpoints. It exists so the controller reads rules rather than configuration —
// routing stays the only thing it decides.
type Limits struct {
	Login    ratelimit.Rule
	Register ratelimit.Rule
}

func NewLimits(cfg ratelimit.Config) Limits {
	return Limits{Login: cfg.LoginIP, Register: cfg.Register}
}
