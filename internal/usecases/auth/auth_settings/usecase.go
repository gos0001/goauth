// Package auth_settings exposes the handful of server-side switches a frontend
// needs to render itself correctly — chiefly whether to show a "sign up" link.
// Without it every panel would hardcode the answer and drift out of sync with
// the deployment it talks to.
package auth_settings

import (
	"context"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	RegistrationMode  string `json:"registration_mode"`
	MinPasswordLength int    `json:"min_password_len"`
	Issuer            string `json:"-"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{RegistrationMode: "closed", MinPasswordLength: 12, Issuer: "goauth"}
	if err := root.Section("auth", &cfg); err != nil {
		return Config{}, err
	}

	// The issuer is the token section's, not a second knob: one issuer, one
	// place, and this use case only echoes it back to clients.
	var token struct {
		Issuer string `json:"issuer"`
	}
	token.Issuer = cfg.Issuer
	if err := root.Section("token", &token); err != nil {
		return Config{}, err
	}
	cfg.Issuer = token.Issuer
	return cfg, nil
}

type Usecase struct {
	cfg Config
}

func New(cfg Config) *Usecase {
	return &Usecase{cfg: cfg}
}

// Execute returns only values that are already observable from outside. Nothing
// here is a secret: the registration mode is visible by calling the endpoint,
// and the password floor by trying a short one.
func (uc *Usecase) Execute(_ context.Context, _ Input) (Output, error) {
	return Output{
		Registration:      uc.cfg.RegistrationMode,
		MinPasswordLength: uc.cfg.MinPasswordLength,
		Issuer:            uc.cfg.Issuer,
	}, nil
}

type Input struct{}

type Output struct {
	Registration      string `json:"registration"`
	MinPasswordLength int    `json:"min_password_length"`
	Issuer            string `json:"issuer"`
}
