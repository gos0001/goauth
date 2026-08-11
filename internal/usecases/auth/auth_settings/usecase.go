// Package auth_settings exposes the handful of server-side switches a frontend
// needs to render itself correctly — chiefly whether to show a "sign up" link.
// Without it every panel would hardcode the answer and drift out of sync with
// the deployment it talks to.
package auth_settings

import (
	"context"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	RegistrationMode  string `envconfig:"AUTH_REGISTRATION_MODE" default:"closed"`
	MinPasswordLength int    `envconfig:"AUTH_MIN_PASSWORD_LEN"  default:"12"`
	Issuer            string `envconfig:"JWT_ISSUER"             default:"goauth"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
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
