package outbox_cleaner

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePostgres struct {
	settledCutoffs []time.Time
	stuckCutoffs   []time.Time

	settled int
	stuck   int
	err     error
}

func (f *fakePostgres) DeleteOutboxEventsBefore(_ context.Context, cutoff time.Time) (int, error) {
	f.settledCutoffs = append(f.settledCutoffs, cutoff)
	return f.settled, f.err
}

func (f *fakePostgres) DeleteStuckOutboxEvents(_ context.Context, cutoff time.Time) (int, error) {
	f.stuckCutoffs = append(f.stuckCutoffs, cutoff)
	return f.stuck, f.err
}

func harness(cfg Config) (*Usecase, *fakePostgres) {
	pg := &fakePostgres{}
	return &Usecase{postgres: pg, cfg: cfg}, pg
}

func defaultConfig() Config {
	return Config{Interval: time.Hour, Retention: 168 * time.Hour, MaxAge: 720 * time.Hour}
}

// The two windows are different values, and swapping them would quietly discard
// undelivered events weeks early — the mistake this test exists to catch.
func TestEachCutoffUsesItsOwnWindow(t *testing.T) {
	uc, pg := harness(defaultConfig())

	before := time.Now()
	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	after := time.Now()

	if len(pg.settledCutoffs) != 1 || len(pg.stuckCutoffs) != 1 {
		t.Fatalf("settled=%d stuck=%d, want one call each", len(pg.settledCutoffs), len(pg.stuckCutoffs))
	}

	within := func(got time.Time, window time.Duration) bool {
		return !got.Before(before.Add(-window)) && !got.After(after.Add(-window))
	}
	if !within(pg.settledCutoffs[0], 168*time.Hour) {
		t.Errorf("settled cutoff %s is not ~168h ago", pg.settledCutoffs[0])
	}
	if !within(pg.stuckCutoffs[0], 720*time.Hour) {
		t.Errorf("stuck cutoff %s is not ~720h ago", pg.stuckCutoffs[0])
	}
	if pg.settledCutoffs[0].Equal(pg.stuckCutoffs[0]) {
		t.Fatal("both deletes used the same cutoff")
	}
}

func TestZeroMaxAgeKeepsUndeliveredEvents(t *testing.T) {
	cfg := defaultConfig()
	cfg.MaxAge = 0
	uc, pg := harness(cfg)

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.stuckCutoffs) != 0 {
		t.Fatal("undelivered events were deleted with OUTBOX_MAX_AGE unset")
	}
	if len(pg.settledCutoffs) != 1 {
		t.Fatal("settled events should still be trimmed")
	}
}

func TestZeroRetentionKeepsSettledEvents(t *testing.T) {
	cfg := defaultConfig()
	cfg.Retention = 0
	uc, pg := harness(cfg)

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.settledCutoffs) != 0 {
		t.Fatal("settled events were deleted with WEBHOOK_RETENTION unset")
	}
}

func TestCountsAreReported(t *testing.T) {
	uc, pg := harness(defaultConfig())
	pg.settled, pg.stuck = 9, 2

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Settled != 9 || out.Stuck != 2 || out.Total() != 11 {
		t.Fatalf("out = %+v", out)
	}
}

func TestErrorsSurface(t *testing.T) {
	uc, pg := harness(defaultConfig())
	pg.err = errors.New("connection reset")

	if _, err := uc.Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected the storage error to surface")
	}
}

// The cleaner has to run even with no webhook configured — that is the case the
// dispatcher's own pruning could never reach.
func TestSchedulingDoesNotDependOnWebhooks(t *testing.T) {
	job := NewCronJob(nil, nil, defaultConfig())
	if job.Interval() != time.Hour {
		t.Fatalf("Interval() = %s, want 1h regardless of webhook configuration", job.Interval())
	}

	off := NewCronJob(nil, nil, Config{Interval: time.Hour})
	if off.Interval() != 0 {
		t.Fatalf("Interval() = %s with both windows unset, want 0", off.Interval())
	}

	noInterval := NewCronJob(nil, nil, Config{Retention: time.Hour})
	if noInterval.Interval() != 0 {
		t.Fatalf("Interval() = %s with no interval, want 0", noInterval.Interval())
	}
}
