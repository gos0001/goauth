package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
)

// insertEvent writes an outbox row through the caller's transaction-scoped
// queries.
//
// It is unexported and takes q rather than using the adapter's own connection
// deliberately: an event must be written by the same transaction as the change
// it announces, or the two can disagree — a user modified with no event, or an
// event for a change that rolled back.
func (a *Adapter) insertEvent(ctx context.Context, q *generated.Queries, ev *domain.OutboxEvent) error {
	if ev == nil || !a.emitEvents {
		return nil
	}

	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return fmt.Errorf("postgres: marshal event payload: %w", err)
	}

	return q.InsertOutboxEvent(ctx, generated.InsertOutboxEventParams{
		Event:   ev.Event,
		Payload: payload,
	})
}

// ClaimDueOutboxEvents leases the next batch of undelivered events.
//
// The lease should comfortably exceed the delivery timeout: it is what stops a
// second worker picking up an event the first is still sending, and what returns
// the event to the queue if that worker dies.
func (a *Adapter) ClaimDueOutboxEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.OutboxEvent, error) {
	rows, err := a.q.ClaimDueOutboxEvents(ctx, generated.ClaimDueOutboxEventsParams{
		Lim:          int32(limit),
		LeaseSeconds: int32(lease.Seconds()),
	})
	if err != nil {
		return nil, MapError(err, nil)
	}

	out := make([]domain.OutboxEvent, 0, len(rows))
	for _, row := range rows {
		ev := domain.OutboxEvent{
			ID:        uuidText(row.ID),
			Event:     row.Event,
			Attempts:  int(row.Attempts),
			CreatedAt: tsOut(row.CreatedAt),
		}
		if len(row.Payload) > 0 {
			// A row whose payload will not parse is still worth returning: the
			// dispatcher records the failure against it rather than silently
			// skipping an event forever.
			_ = json.Unmarshal(row.Payload, &ev.Payload)
			ev.RawPayload = row.Payload
		}
		out = append(out, ev)
	}
	return out, nil
}

func (a *Adapter) MarkOutboxDelivered(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.ErrNotFound
	}
	return MapError(a.q.MarkOutboxDelivered(ctx, parsed), nil)
}

// MarkOutboxFailed records the error and when to try again. giveUp closes the
// event off for good, so the backoff policy stays in Go.
func (a *Adapter) MarkOutboxFailed(ctx context.Context, id, reason string, nextAttempt time.Time, giveUp bool) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.ErrNotFound
	}

	return MapError(a.q.MarkOutboxFailed(ctx, generated.MarkOutboxFailedParams{
		ID:            parsed,
		LastError:     text(truncate(reason, 500)),
		NextAttemptAt: ts(nextAttempt),
		GiveUp:        giveUp,
	}), nil)
}

// DeleteOutboxEventsBefore removes settled rows — delivered or given up on.
// Pending events are never touched, however old.
func (a *Adapter) DeleteOutboxEventsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	n, err := a.q.DeleteOutboxEventsBefore(ctx, ts(cutoff))
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

func (a *Adapter) CountPendingOutboxEvents(ctx context.Context) (int, error) {
	n, err := a.q.CountPendingOutboxEvents(ctx)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

// truncate keeps a receiver's error page out of the database.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
