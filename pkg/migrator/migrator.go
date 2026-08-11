// Package migrator applies embedded SQL migrations at startup.
//
// It wraps golang-migrate rather than hand-rolling a runner, for two reasons
// that matter operationally:
//
//   - it writes the same schema_migrations table the `migrate` CLI uses, so a
//     source checkout running `make migrate-up` and a container migrating itself
//     can never disagree about what is applied;
//
//   - its Postgres driver takes a session advisory lock around the run, so two
//     containers starting against one database at the same moment serialise
//     instead of both trying to create the same tables.
//
// Zero domain imports; the migration files arrive as an fs.FS so this package
// stays independent of where they live.
package migrator

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

type Migrator struct {
	cfg   Config
	files fs.FS
}

func New(cfg Config, files fs.FS) *Migrator {
	return &Migrator{cfg: cfg, files: files}
}

// Result describes what a run did, so the caller can log it meaningfully
// instead of reporting "ok" for three different outcomes.
type Result struct {
	Skipped bool
	Reason  string

	Applied bool
	Version uint

	// Dirty means a previous run failed partway and left the schema in an
	// unknown state. It must be repaired by hand.
	Dirty bool
}

// Up applies every pending migration.
func (m *Migrator) Up(ctx context.Context) (Result, error) {
	if !m.cfg.AutoMigrate {
		return Result{Skipped: true, Reason: "AUTO_MIGRATE is false"}, nil
	}

	src, err := iofs.New(m.files, ".")
	if err != nil {
		return Result{}, fmt.Errorf("migrator: read embedded migrations: %w", err)
	}

	mig, err := migrate.NewWithSourceInstance("iofs", src, pgxURL(m.cfg.URL))
	if err != nil {
		return Result{}, fmt.Errorf("migrator: open: %w", err)
	}
	defer func() {
		// Close reports the source and database errors separately; neither is
		// worth failing a successful migration over, but a leak would be.
		_, _ = mig.Close()
	}()

	// The context guards the caller's startup timeout; golang-migrate exposes
	// cancellation through GracefulStop rather than a context parameter.
	done := make(chan error, 1)
	go func() { done <- mig.Up() }()

	select {
	case err = <-done:
	case <-ctx.Done():
		mig.GracefulStop <- true
		<-done
		return Result{}, fmt.Errorf("migrator: cancelled: %w", ctx.Err())
	}

	version, dirty, verErr := mig.Version()
	if verErr != nil && !errors.Is(verErr, migrate.ErrNilVersion) {
		return Result{}, fmt.Errorf("migrator: read version: %w", verErr)
	}

	switch {
	case errors.Is(err, migrate.ErrNoChange):
		return Result{Version: version, Dirty: dirty}, nil
	case err != nil:
		return Result{Version: version, Dirty: dirty}, fmt.Errorf("migrator: apply: %w", err)
	}

	return Result{Applied: true, Version: version, Dirty: dirty}, nil
}

// pgxURL rewrites the connection scheme for golang-migrate.
//
// golang-migrate selects its database driver by URL scheme, and the pgx/v5
// driver registers itself as "pgx5". The service's own POSTGRES_URL uses the
// standard "postgres://" form, so it is translated here rather than forcing
// operators to configure a second, differently-spelled connection string — or
// pulling in lib/pq purely to satisfy the "postgres" scheme when pgx is already
// linked in.
func pgxURL(url string) string {
	for _, scheme := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(url, scheme) {
			return "pgx5://" + strings.TrimPrefix(url, scheme)
		}
	}
	return url
}
