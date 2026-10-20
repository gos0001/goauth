package seed_roles

import (
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

// RoleSeed is one entry of the config file's seed.roles array. It draws the
// deployment's custom floor: self-hosted applications with a fixed panel can
// declare their roles here and never build role-management UI at all.
type RoleSeed struct {
	Name        string              `json:"name"`
	Rank        int                 `json:"rank"`
	Permissions []domain.Permission `json:"permissions"`
	IsSystem    bool                `json:"is_system"`
}

type Config struct {
	Roles []RoleSeed `json:"roles"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{}
	if err := root.Section("seed", &cfg); err != nil {
		return Config{}, err
	}

	// Validated before anything touches the database: a bad seed must fail
	// the boot loudly, not surface later as a role that behaves strangely.
	for _, r := range cfg.Roles {
		if _, builtin := builtinNames[r.Name]; builtin {
			// Not an error: re-declaring a built-in is how an operator
			// documents intent, and ignoring it is what "the database is the
			// truth" already promised.
			continue
		}
		if !domain.ValidRoleName(r.Name) {
			return Config{}, errSeed{Name: r.Name, Cause: "invalid name"}
		}
		if !domain.ValidCustomRank(r.Rank) {
			return Config{}, errSeed{Name: r.Name, Cause: "rank must be between 1 and 99"}
		}
		if err := domain.ValidatePermissions(r.Permissions); err != nil {
			return Config{}, errSeed{Name: r.Name, Cause: err.Error()}
		}
	}
	return cfg, nil
}

var builtinNames = map[string]struct{}{
	domain.RoleUser:       {},
	domain.RoleManager:    {},
	domain.RoleAdmin:      {},
	domain.RoleSuperAdmin: {},
}

type errSeed struct {
	Name  string
	Cause string
}

func (e errSeed) Error() string { return "seed role " + e.Name + ": " + e.Cause }
