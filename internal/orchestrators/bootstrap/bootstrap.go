// Package bootstrap runs the one-time startup work that must happen after the
// dependency graph is built but before the service accepts traffic.
package bootstrap

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/usecases/seed_super_admin"
	"github.com/gos0001/goauth/pkg/migrator"
)

type Bootstrap struct {
	migrator *migrator.Migrator
	seed     *seed_super_admin.Usecase
	logger   *zap.SugaredLogger
}

func New(m *migrator.Migrator, seed *seed_super_admin.Usecase, logger *zap.SugaredLogger) *Bootstrap {
	return &Bootstrap{migrator: m, seed: seed, logger: logger}
}

// Run executes startup tasks in order. An error here aborts the boot: a service
// whose schema is not current, or that cannot establish its first
// administrator, is misconfigured — starting anyway would serve requests
// against a database it does not understand.
func (b *Bootstrap) Run(ctx context.Context) error {
	// Migrations first: the seed inserts into ga_users and needs the table.
	if err := b.migrate(ctx); err != nil {
		return err
	}
	return b.seedSuperAdmin(ctx)
}

func (b *Bootstrap) migrate(ctx context.Context) error {
	res, err := b.migrator.Up(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: migrate: %w", err)
	}

	if res.Dirty {
		// A dirty schema means an earlier run failed partway. Continuing would
		// be guessing about what actually exists.
		return fmt.Errorf("bootstrap: database is marked dirty at version %d; repair it before starting", res.Version)
	}

	switch {
	case res.Skipped:
		b.logger.Infow("migrations skipped", "reason", res.Reason)
	case res.Applied:
		b.logger.Infow("migrations applied", "version", res.Version)
	default:
		b.logger.Infow("migrations up to date", "version", res.Version)
	}

	return nil
}

func (b *Bootstrap) seedSuperAdmin(ctx context.Context) error {
	out, err := b.seed.Execute(ctx, seed_super_admin.Input{})
	if err != nil {
		return fmt.Errorf("bootstrap: seed super admin: %w", err)
	}

	switch {
	case out.Created && out.GeneratedPassword != "":
		// Printed exactly once, on the run that created the account. The
		// account carries must_change_password, so this value stops working the
		// moment the real admin logs in — but it does land in the container
		// logs, so set SUPER_ADMIN_PASSWORD explicitly where logs are shipped
		// somewhere you would rather it not reach.
		b.logger.Warnw("bootstrap administrator created with a generated password — shown once, change it on first login",
			"identifier", out.Identifier,
			"password", out.GeneratedPassword,
			"user_id", out.UserID)
	case out.Created:
		b.logger.Warnw("bootstrap administrator created — log in and change the password immediately",
			"identifier", out.Identifier, "user_id", out.UserID)
	case out.Skipped:
		b.logger.Infow("super admin seed skipped", "reason", out.Reason)
	}

	return nil
}
