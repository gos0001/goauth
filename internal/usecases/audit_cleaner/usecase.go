// Package audit_cleaner keeps ga_audit_log from growing without bound.
//
// The table is written on every login, every failed login and every token
// refresh. With a 15-minute access TTL a single active user produces roughly
// four rows an hour from refreshes alone, so a busy installation adds six-figure
// row counts per day — nearly all of it `session.refreshed` entries that record
// no decision anyone will ever look up.
package audit_cleaner

import (
	"context"
	"fmt"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
)

type Postgres interface {
	DeleteAuditEntriesBefore(ctx context.Context, cutoff time.Time) (int, error)
	DeleteAuditEntriesBeyond(ctx context.Context, keep int) (int, error)
}

type Usecase struct {
	postgres Postgres
	cfg      Config
}

func New(pg *postgresadapter.Adapter, cfg Config) *Usecase {
	return &Usecase{postgres: pg, cfg: cfg}
}

// Execute applies the retention window, then the row cap.
//
// Both limits are opt-out by being zero, and both are checked before any delete
// is issued: a misread configuration must leave the audit trail alone rather
// than empty it.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	var out Output

	if uc.cfg.Retention > 0 {
		cutoff := time.Now().Add(-uc.cfg.Retention)

		n, err := uc.postgres.DeleteAuditEntriesBefore(ctx, cutoff)
		if err != nil {
			return Output{}, fmt.Errorf("audit_cleaner: delete before %s: %w", cutoff.Format(time.RFC3339), err)
		}
		out.DeletedByAge = n
	}

	if uc.cfg.MaxRows > 0 {
		n, err := uc.postgres.DeleteAuditEntriesBeyond(ctx, uc.cfg.MaxRows)
		if err != nil {
			return Output{}, fmt.Errorf("audit_cleaner: trim to %d rows: %w", uc.cfg.MaxRows, err)
		}
		out.DeletedByCap = n
	}

	return out, nil
}

type Input struct{}

type Output struct {
	DeletedByAge int
	DeletedByCap int
}

// Total is what the caller logs; the split matters only when tuning the limits.
func (o Output) Total() int { return o.DeletedByAge + o.DeletedByCap }
