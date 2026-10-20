package token

import (
	"errors"
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// PrivateKey is the base64-encoded 32-byte ed25519 seed. Required: an
	// auto-generated ephemeral key would silently invalidate every issued token
	// on restart, which is a far worse failure than refusing to boot.
	// Generate one with `make jwt-key`.
	PrivateKey string `json:"private_key"`

	// PreviousPublicKeys are base64-encoded 32-byte public keys that are still
	// published in the JWKS and still accepted for verification, but never used
	// for signing. This is what makes key rotation a two-step deploy with no
	// downtime and no coordination with consumers.
	PreviousPublicKeys []string `json:"previous_public_keys"`

	Issuer     string        `json:"issuer"`
	Audience   string        `json:"audience"`
	AccessTTL  time.Duration `json:"access_ttl"`
	RefreshTTL time.Duration `json:"refresh_ttl"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		Issuer:     "goauth",
		Audience:   "goauth",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	}
	if err := root.Section("token", &cfg); err != nil {
		return Config{}, err
	}
	if cfg.PrivateKey == "" {
		return Config{}, errors.New("token.private_key is required")
	}
	return cfg, nil
}
