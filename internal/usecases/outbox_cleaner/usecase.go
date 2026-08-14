// Package outbox_cleaner keeps ga_outbox bounded.
//
// It is a separate job from the dispatcher on purpose. The dispatcher prunes
// only as a side effect of delivering, and returns early when no webhook is
// configured — so switching webhooks off, or setting WEBHOOK_INTERVAL to zero,
// used to leave the table growing with nothing able to clean it.
package outbox_cleaner

import (
	"context"
	"fmt"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
)

type Postgres interface {
	DeleteOutboxEventsBefore(ctx context.Context, cutoff time.Time) (int, error)
	DeleteStuckOutboxEvents(ctx context.Context, cutoff time.Time) (int, error)
}

type Usecase struct {
	postgres Postgres
	cfg      Config
}

func New(pg *postgresadapter.Adapter, cfg Config) *Usecase {
	return &Usecase{postgres: pg, cfg: cfg}
}

// Execute removes settled events past their retention, then undelivered ones
// past the hard ceiling.
//
// The two cutoffs are different values and must stay that way: passing the
// retention window where the ceiling belongs would silently discard undelivered
// events a week early.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	var out Output

	if uc.cfg.Retention > 0 {
		n, err := uc.postgres.DeleteOutboxEventsBefore(ctx, time.Now().Add(-uc.cfg.Retention))
		if err != nil {
			return Output{}, fmt.Errorf("outbox_cleaner: delete settled: %w", err)
		}
		out.Settled = n
	}

	if uc.cfg.MaxAge > 0 {
		n, err := uc.postgres.DeleteStuckOutboxEvents(ctx, time.Now().Add(-uc.cfg.MaxAge))
		if err != nil {
			return Output{}, fmt.Errorf("outbox_cleaner: delete stuck: %w", err)
		}
		out.Stuck = n
	}

	return out, nil
}

type Input struct{}

type Output struct {
	Settled int
	Stuck   int
}

func (o Output) Total() int { return o.Settled + o.Stuck }
