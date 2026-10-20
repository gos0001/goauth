// Package seed_roles draws the role floor at startup: the built-in hierarchy
// every installation needs, plus the deployment's own entries from
// seed.roles in the config file.
//
// Seeding is idempotent and never overwrites: a role that already exists is
// left exactly as it stands, so a rank or a permission changed at runtime
// survives every restart. The config file draws the floor; the database is
// the truth.
package seed_roles

import (
	"context"

	"go.uber.org/zap"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	SeedRole(ctx context.Context, r domain.Role) (bool, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	auditor  Auditor
	cfg      Config
	logger   *zap.SugaredLogger
}

func New(pg *postgresadapter.Adapter, auditor *audit.Recorder, cfg Config, logger *zap.SugaredLogger) *Usecase {
	return &Usecase{postgres: pg, auditor: auditor, cfg: cfg, logger: logger}
}

// Execute seeds the built-in roles and then the config file's. It must run
// before any user is created: ga_users.role is NOT NULL and foreign-keyed, so
// the 'user' row has to exist before the first account references it.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	created := 0

	for _, r := range domain.DefaultRoles() {
		made, err := uc.seed(ctx, r)
		if err != nil {
			return Output{}, err
		}
		if made {
			created++
		}
	}

	for _, r := range uc.cfg.Roles {
		if _, builtin := builtinNames[r.Name]; builtin {
			// Re-declaring a built-in is documentation, not instruction:
			// the seed never overwrites, so there is nothing to do.
			continue
		}
		made, err := uc.seed(ctx, domain.Role{
			Name:        r.Name,
			Rank:        r.Rank,
			IsSystem:    r.IsSystem,
			Permissions: r.Permissions,
		})
		if err != nil {
			return Output{}, err
		}
		if made {
			created++
		}
	}

	return Output{Created: created}, nil
}

func (uc *Usecase) seed(ctx context.Context, r domain.Role) (bool, error) {
	made, err := uc.postgres.SeedRole(ctx, r)
	if err != nil {
		return false, err
	}
	if made {
		uc.logger.Infow("role seeded", "role", r.Name, "rank", r.Rank)
		uc.auditor.Record(ctx, audit.Event(domain.ActorSystem, domain.ActionRoleCreated, "", "",
			map[string]any{"role": r.Name, "rank": r.Rank, "seeded": true}))
	}
	return made, nil
}

type Input struct{}

type Output struct {
	Created int
}
