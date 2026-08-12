package cron

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

type stubJob struct {
	name     string
	interval time.Duration

	runs    atomic.Int32
	err     error
	panics  bool
	blockOn chan struct{}
}

func (s *stubJob) Name() string            { return s.name }
func (s *stubJob) Interval() time.Duration { return s.interval }

func (s *stubJob) Run(_ context.Context) error {
	s.runs.Add(1)
	if s.panics {
		panic("boom")
	}
	if s.blockOn != nil {
		// Deliberately ignores ctx: the property under test is that Stop waits
		// for Run to return, and a stub that exits on cancellation would prove
		// nothing.
		<-s.blockOn
	}
	return s.err
}

// newCron bypasses the wire constructor, which is typed to the two real jobs.
func newCron(jobs ...Job) *Cron {
	return &Cron{jobs: jobs, logger: zap.NewNop().Sugar(), firstRun: time.Millisecond}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestJobWithZeroIntervalIsNotScheduled(t *testing.T) {
	job := &stubJob{name: "disabled", interval: 0}

	c := newCron(job)
	c.Start(context.Background())
	defer c.Stop()

	time.Sleep(50 * time.Millisecond)
	if job.runs.Load() != 0 {
		t.Fatalf("a job with a zero interval ran %d times", job.runs.Load())
	}
}

// A failing cleanup must not stop the loop — housekeeping cannot be allowed to
// take down a service that is otherwise serving correctly.
func TestFailingJobKeepsRunning(t *testing.T) {
	job := &stubJob{name: "failing", interval: 10 * time.Millisecond, err: errors.New("nope")}

	c := newCron(job)
	c.Start(context.Background())
	defer c.Stop()

	waitFor(t, func() bool { return job.runs.Load() >= 3 },
		"the job stopped after returning an error")
}

func TestPanickingJobIsContained(t *testing.T) {
	job := &stubJob{name: "panicking", interval: 10 * time.Millisecond, panics: true}

	c := newCron(job)
	c.Start(context.Background())
	defer c.Stop()

	waitFor(t, func() bool { return job.runs.Load() >= 2 },
		"a panicking job took the loop down with it")
}

// Stop has to outlive an in-flight run: it returns before the caller closes the
// database pool, and a job still mid-query would then hit a closed pool.
func TestStopWaitsForRunningJob(t *testing.T) {
	release := make(chan struct{})
	job := &stubJob{name: "slow", interval: time.Hour, blockOn: release}

	c := newCron(job)
	c.Start(context.Background())

	waitFor(t, func() bool { return job.runs.Load() == 1 }, "the job never started")

	var stopped sync.WaitGroup
	stopped.Add(1)
	returned := make(chan struct{})
	go func() {
		defer stopped.Done()
		c.Stop()
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("Stop returned while the job was still running")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the job finished")
	}
	stopped.Wait()
}

func TestStopIsSafeBeforeStart(t *testing.T) {
	newCron().Stop() // must not panic on a nil cancel
}
