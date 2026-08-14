// Package webhook_dispatcher delivers outbox events to the configured webhook.
//
// Events are written to ga_outbox in the same transaction as the change they
// describe, so this package's only job is getting them out — and getting them
// out eventually rather than immediately. A receiver that is down delays events;
// it does not lose them.
package webhook_dispatcher

import (
	"context"
	"fmt"
	"math"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/pkg/webhook"
)

type Postgres interface {
	ClaimDueOutboxEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.OutboxEvent, error)
	MarkOutboxDelivered(ctx context.Context, id string) error
	MarkOutboxFailed(ctx context.Context, id, reason string, nextAttempt time.Time, giveUp bool) error
}

type Sender interface {
	Enabled() bool
	Send(ctx context.Context, eventID, event string, attempt int, payload []byte) error
}

type Usecase struct {
	postgres Postgres
	sender   Sender
	cfg      Config
}

func New(pg *postgresadapter.Adapter, sender *webhook.Sender, cfg Config) *Usecase {
	return &Usecase{postgres: pg, sender: sender, cfg: cfg}
}

// Execute delivers one batch. Removing rows afterwards belongs to
// outbox_cleaner: pruning here only ever ran when a webhook was configured, so
// switching webhooks off left the table with nothing able to clean it.
//
// It never returns an error for a receiver that rejected an event — that is
// recorded against the row and retried later. An error here means the outbox
// itself could not be read or written.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	if !uc.sender.Enabled() {
		return Output{Skipped: true, Reason: "WEBHOOK_URL is not set"}, nil
	}

	// The lease must outlast a delivery attempt, or a second worker could pick
	// up an event this one is still sending.
	lease := uc.cfg.Timeout*2 + 30*time.Second

	events, err := uc.postgres.ClaimDueOutboxEvents(ctx, uc.cfg.BatchSize, lease)
	if err != nil {
		return Output{}, fmt.Errorf("webhook_dispatcher: claim: %w", err)
	}

	var out Output
	for _, ev := range events {
		attempt := ev.Attempts + 1

		sendErr := uc.sender.Send(ctx, ev.ID, ev.Event, attempt, ev.RawPayload)
		if sendErr == nil {
			if err := uc.postgres.MarkOutboxDelivered(ctx, ev.ID); err != nil {
				return out, fmt.Errorf("webhook_dispatcher: mark delivered: %w", err)
			}
			out.Delivered++
			continue
		}

		giveUp := attempt >= uc.cfg.MaxAttempts
		next := time.Now().Add(uc.backoff(attempt))

		if err := uc.postgres.MarkOutboxFailed(ctx, ev.ID, sendErr.Error(), next, giveUp); err != nil {
			return out, fmt.Errorf("webhook_dispatcher: mark failed: %w", err)
		}

		if giveUp {
			out.GaveUp++
		} else {
			out.Failed++
		}
	}

	return out, nil
}

// backoff grows exponentially from BackoffBase and stops at BackoffMax, so a
// receiver that has been down for an hour is retried every BackoffMax rather
// than at an interval that keeps doubling past any useful value.
func (uc *Usecase) backoff(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(attempt-1))) * uc.cfg.BackoffBase
	if d <= 0 || d > uc.cfg.BackoffMax {
		return uc.cfg.BackoffMax
	}
	return d
}

type Input struct{}

type Output struct {
	Skipped bool
	Reason  string

	Delivered int
	Failed    int
	GaveUp    int
}

func (o Output) Touched() int { return o.Delivered + o.Failed + o.GaveUp }
