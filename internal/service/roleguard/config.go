package roleguard

import (
	"fmt"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

// Ownership modes, read from the "admin" section.
//
// Off is the default and the byte-for-byte v2 behaviour: no ownership exists,
// every holder of users:read sees every user. Delegated turns creation into
// an implicit administrative unit — a non-superadmin sees and manages only
// users strictly below their own rank that they created, plus whatever the
// users:read_all / users:manage_all exceptions widen.
const (
	ModeOff       = "off"
	ModeDelegated = "delegated"
)

type Config struct {
	Ownership string `json:"ownership"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{Ownership: ModeOff}
	if err := root.Section("admin", &cfg); err != nil {
		return cfg, err
	}

	switch cfg.Ownership {
	case ModeOff, ModeDelegated:
	default:
		return cfg, fmt.Errorf("roleguard: admin.ownership must be %q or %q, got %q",
			ModeOff, ModeDelegated, cfg.Ownership)
	}

	return cfg, nil
}
