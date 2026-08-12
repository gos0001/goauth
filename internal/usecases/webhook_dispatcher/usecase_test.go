package webhook_dispatcher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gos0001/goauth/internal/domain"
)

type fakePostgres struct {
	due []domain.OutboxEvent

	delivered []string
	failed    []failure
	pruned    int
}

type failure struct {
	id     string
	reason string
	next   time.Time
	giveUp bool
}

func (f *fakePostgres) ClaimDueOutboxEvents(_ context.Context, limit int, _ time.Duration) ([]domain.OutboxEvent, error) {
	if len(f.due) > limit {
		return f.due[:limit], nil
	}
	out := f.due
	f.due = nil
	return out, nil
}

func (f *fakePostgres) MarkOutboxDelivered(_ context.Context, id string) error {
	f.delivered = append(f.delivered, id)
	return nil
}

func (f *fakePostgres) MarkOutboxFailed(_ context.Context, id, reason string, next time.Time, giveUp bool) error {
	f.failed = append(f.failed, failure{id, reason, next, giveUp})
	return nil
}

func (f *fakePostgres) DeleteOutboxEventsBefore(_ context.Context, _ time.Time) (int, error) {
	return f.pruned, nil
}

type fakeSender struct {
	enabled bool
	err     error
	sent    []string
	attempt []int
}

func (s *fakeSender) Enabled() bool { return s.enabled }

func (s *fakeSender) Send(_ context.Context, eventID, _ string, attempt int, _ []byte) error {
	s.sent = append(s.sent, eventID)
	s.attempt = append(s.attempt, attempt)
	return s.err
}

func harness(cfg Config) (*Usecase, *fakePostgres, *fakeSender) {
	pg := &fakePostgres{}
	s := &fakeSender{enabled: true}
	return &Usecase{postgres: pg, sender: s, cfg: cfg}, pg, s
}

func defaultConfig() Config {
	return Config{
		Interval: time.Second, BatchSize: 50, MaxAttempts: 3,
		BackoffBase: time.Second, BackoffMax: time.Hour,
		Retention: time.Hour, Timeout: time.Second,
	}
}

func TestDeliversAndMarks(t *testing.T) {
	uc, pg, s := harness(defaultConfig())
	pg.due = []domain.OutboxEvent{
		{ID: "e1", Event: domain.EventUserCreated, RawPayload: []byte(`{}`)},
		{ID: "e2", Event: domain.EventUserBlocked, RawPayload: []byte(`{}`)},
	}

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Delivered != 2 || len(pg.delivered) != 2 {
		t.Fatalf("delivered = %d, marked = %v", out.Delivered, pg.delivered)
	}
	if len(s.sent) != 2 {
		t.Fatalf("sent = %v", s.sent)
	}
}

// A receiver rejecting an event is not an error for the dispatcher — it is
// recorded and retried. Returning an error here would make the cron runner log
// a failure on every ordinary hiccup.
func TestReceiverFailureIsRecordedNotReturned(t *testing.T) {
	uc, pg, s := harness(defaultConfig())
	s.err = errors.New("connection refused")
	pg.due = []domain.OutboxEvent{{ID: "e1", Event: domain.EventUserCreated, RawPayload: []byte(`{}`)}}

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("a failing receiver produced an error: %v", err)
	}
	if out.Failed != 1 || out.Delivered != 0 {
		t.Fatalf("out = %+v", out)
	}
	if len(pg.failed) != 1 || pg.failed[0].giveUp {
		t.Fatalf("failure = %+v, want recorded without giving up", pg.failed)
	}
	if pg.failed[0].reason == "" {
		t.Error("the failure was recorded with no reason, leaving nothing to debug")
	}
}

// Giving up loses the event permanently, so it must happen only at the limit.
func TestGivesUpOnlyAtTheAttemptLimit(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxAttempts = 3

	for _, tc := range []struct {
		attemptsSoFar int
		wantGiveUp    bool
	}{
		{0, false}, // first attempt
		{1, false},
		{2, true}, // this is attempt 3
		{5, true},
	} {
		uc, pg, s := harness(cfg)
		s.err = errors.New("down")
		pg.due = []domain.OutboxEvent{{ID: "e1", Attempts: tc.attemptsSoFar, RawPayload: []byte(`{}`)}}

		if _, err := uc.Execute(context.Background(), Input{}); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if pg.failed[0].giveUp != tc.wantGiveUp {
			t.Errorf("attempts=%d giveUp=%v, want %v", tc.attemptsSoFar, pg.failed[0].giveUp, tc.wantGiveUp)
		}
	}
}

func TestAttemptNumberIsPassedToTheSender(t *testing.T) {
	uc, pg, s := harness(defaultConfig())
	pg.due = []domain.OutboxEvent{{ID: "e1", Attempts: 2, RawPayload: []byte(`{}`)}}

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if s.attempt[0] != 3 {
		t.Fatalf("attempt = %d, want 3 — a receiver deduplicating on it would be misled", s.attempt[0])
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	cfg := defaultConfig()
	cfg.BackoffBase = 10 * time.Second
	cfg.BackoffMax = time.Minute
	uc, _, _ := harness(cfg)

	if got := uc.backoff(1); got != 10*time.Second {
		t.Errorf("backoff(1) = %s, want 10s", got)
	}
	if got := uc.backoff(3); got != 40*time.Second {
		t.Errorf("backoff(3) = %s, want 40s", got)
	}
	// Without a cap this would keep doubling into days.
	if got := uc.backoff(20); got != time.Minute {
		t.Errorf("backoff(20) = %s, want the 1m cap", got)
	}
}

func TestSkippedWhenNoWebhookConfigured(t *testing.T) {
	uc, pg, s := harness(defaultConfig())
	s.enabled = false
	pg.due = []domain.OutboxEvent{{ID: "e1", RawPayload: []byte(`{}`)}}

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !out.Skipped {
		t.Fatal("expected the run to report itself skipped")
	}
	if len(s.sent) != 0 {
		t.Fatal("something was sent with no webhook configured")
	}
}

func TestBatchSizeIsRespected(t *testing.T) {
	cfg := defaultConfig()
	cfg.BatchSize = 2
	uc, pg, s := harness(cfg)
	for i := 0; i < 5; i++ {
		pg.due = append(pg.due, domain.OutboxEvent{ID: string(rune('a' + i)), RawPayload: []byte(`{}`)})
	}

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(s.sent) != 2 {
		t.Fatalf("sent %d events, want the batch size of 2", len(s.sent))
	}
}
