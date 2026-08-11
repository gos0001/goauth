package token

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// PrivateKey is the base64-encoded 32-byte ed25519 seed. Required: an
	// auto-generated ephemeral key would silently invalidate every issued token
	// on restart, which is a far worse failure than refusing to boot.
	// Generate one with `make jwt-key`.
	PrivateKey string `envconfig:"JWT_PRIVATE_KEY" required:"true"`

	// PreviousPublicKeys are base64-encoded 32-byte public keys that are still
	// published in the JWKS and still accepted for verification, but never used
	// for signing. This is what makes key rotation a two-step deploy with no
	// downtime and no coordination with consumers.
	PreviousPublicKeys []string `envconfig:"JWT_PREVIOUS_PUBLIC_KEYS"`

	Issuer   string `envconfig:"JWT_ISSUER"   default:"goauth"`
	Audience string `envconfig:"JWT_AUDIENCE" default:"goauth"`

	AccessTTL  time.Duration `envconfig:"JWT_ACCESS_TTL"  default:"15m"`
	RefreshTTL time.Duration `envconfig:"JWT_REFRESH_TTL" default:"720h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
