// Package bootstrap runs the one-time startup work that must happen after the
// dependency graph is built but before the service accepts traffic.
package bootstrap

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/usecases/seed_super_admin"
	"github.com/gos0001/goauth/pkg/dbschema"
)

type Bootstrap struct {
	schema *dbschema.Applier
	seed   *seed_super_admin.Usecase
	logger *zap.SugaredLogger
}

func New(schema *dbschema.Applier, seed *seed_super_admin.Usecase, logger *zap.SugaredLogger) *Bootstrap {
	return &Bootstrap{schema: schema, seed: seed, logger: logger}
}

// Run executes startup tasks in order. An error here aborts the boot: a service
// whose tables are missing, or that cannot establish its first administrator, is
// misconfigured — starting anyway would serve requests against a database it
// does not understand.
func (b *Bootstrap) Run(ctx context.Context) error {
	// Schema first: the seed inserts into ga_users and needs the table.
	if err := b.ensureSchema(ctx); err != nil {
		return err
	}
	return b.seedSuperAdmin(ctx)
}

func (b *Bootstrap) ensureSchema(ctx context.Context) error {
	res, err := b.schema.Ensure(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: ensure schema: %w", err)
	}

	if res.Skipped {
		b.logger.Infow("schema check skipped", "reason", res.Reason)
	} else {
		b.logger.Info("schema ready")
	}

	return nil
}

func (b *Bootstrap) seedSuperAdmin(ctx context.Context) error {
	out, err := b.seed.Execute(ctx, seed_super_admin.Input{})
	if err != nil {
		return fmt.Errorf("bootstrap: seed super admin: %w", err)
	}

	switch {
	case out.Created:
		b.logger.Infow("bootstrap administrator created",
			"identifier", out.Identifier, "user_id", out.UserID)
	case out.Skipped:
		b.logger.Infow("super admin seed skipped", "reason", out.Reason)
	}

	return nil
}
