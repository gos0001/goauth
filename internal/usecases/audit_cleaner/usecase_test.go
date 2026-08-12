package audit_cleaner

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePostgres struct {
	beforeCalls []time.Time
	beyondCalls []int

	deletedByAge int
	deletedByCap int
	err          error
}

func (f *fakePostgres) DeleteAuditEntriesBefore(_ context.Context, cutoff time.Time) (int, error) {
	f.beforeCalls = append(f.beforeCalls, cutoff)
	return f.deletedByAge, f.err
}

func (f *fakePostgres) DeleteAuditEntriesBeyond(_ context.Context, keep int) (int, error) {
	f.beyondCalls = append(f.beyondCalls, keep)
	return f.deletedByCap, f.err
}

func harness(cfg Config) (*Usecase, *fakePostgres) {
	pg := &fakePostgres{}
	return &Usecase{postgres: pg, cfg: cfg}, pg
}

// The failure that matters most: an unset retention must keep everything. The
// opposite reading would quietly erase the audit trail of every installation
// that never configured one.
func TestZeroRetentionDeletesNothing(t *testing.T) {
	uc, pg := harness(Config{Retention: 0, MaxRows: 0, Interval: time.Hour})

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.beforeCalls) != 0 {
		t.Fatalf("deleted by age with retention unset: %v", pg.beforeCalls)
	}
	if len(pg.beyondCalls) != 0 {
		t.Fatalf("trimmed by cap with MaxRows unset: %v", pg.beyondCalls)
	}
	if out.Total() != 0 {
		t.Fatalf("reported %d deletions with both limits off", out.Total())
	}
}

func TestRetentionPassesTheRightCutoff(t *testing.T) {
	uc, pg := harness(Config{Retention: 48 * time.Hour, Interval: time.Hour})

	before := time.Now()
	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	after := time.Now()

	if len(pg.beforeCalls) != 1 {
		t.Fatalf("expected one delete-by-age call, got %d", len(pg.beforeCalls))
	}

	// The cutoff is now-48h, and "now" was taken somewhere between the two
	// samples, so it must land inside that window shifted back by the retention.
	cutoff := pg.beforeCalls[0]
	earliest := before.Add(-48 * time.Hour)
	latest := after.Add(-48 * time.Hour)
	if cutoff.Before(earliest) || cutoff.After(latest) {
		t.Fatalf("cutoff %s outside [%s, %s]", cutoff, earliest, latest)
	}
}

func TestMaxRowsTrimsIndependently(t *testing.T) {
	uc, pg := harness(Config{Retention: 0, MaxRows: 5000, Interval: time.Hour})
	pg.deletedByCap = 12

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.beforeCalls) != 0 {
		t.Fatal("a row cap alone must not delete by age")
	}
	if len(pg.beyondCalls) != 1 || pg.beyondCalls[0] != 5000 {
		t.Fatalf("beyond calls = %v, want [5000]", pg.beyondCalls)
	}
	if out.DeletedByCap != 12 || out.Total() != 12 {
		t.Fatalf("out = %+v, want 12 deleted by cap", out)
	}
}

func TestBothLimitsApplyInOrder(t *testing.T) {
	uc, pg := harness(Config{Retention: time.Hour, MaxRows: 100, Interval: time.Hour})
	pg.deletedByAge, pg.deletedByCap = 7, 3

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.beforeCalls) != 1 || len(pg.beyondCalls) != 1 {
		t.Fatal("expected both limits to be applied")
	}
	if out.Total() != 10 {
		t.Fatalf("Total() = %d, want 10", out.Total())
	}
}

func TestErrorsSurface(t *testing.T) {
	uc, pg := harness(Config{Retention: time.Hour, Interval: time.Hour})
	pg.err = errors.New("connection reset")

	if _, err := uc.Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected the storage error to surface")
	}
}

func TestEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"retention only", Config{Retention: time.Hour, Interval: time.Hour}, true},
		{"cap only", Config{MaxRows: 10, Interval: time.Hour}, true},
		{"no limits", Config{Interval: time.Hour}, false},
		{"no interval", Config{Retention: time.Hour}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A disabled job reports a zero interval, which is what stops the runner from
// scheduling it at all.
func TestCronJobIntervalReflectsConfig(t *testing.T) {
	off := NewCronJob(nil, nil, Config{Interval: time.Hour})
	if off.Interval() != 0 {
		t.Fatalf("Interval() = %s with both limits off, want 0", off.Interval())
	}

	on := NewCronJob(nil, nil, Config{Interval: 6 * time.Hour, Retention: 720 * time.Hour})
	if on.Interval() != 6*time.Hour {
		t.Fatalf("Interval() = %s, want 6h", on.Interval())
	}
}
