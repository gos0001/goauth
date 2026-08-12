// Package cron runs background housekeeping on a schedule.
//
// A ticker per job rather than a cron library: the requirement is "every N",
// never "at 03:00 on Tuesdays", and a dependency would be larger than the code
// it replaced.
package cron

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/usecases/audit_cleaner"
	"github.com/gos0001/goauth/internal/usecases/session_cleaner"
	"github.com/gos0001/goauth/internal/usecases/webhook_dispatcher"
)

// Job is what a use case's cron.go adapts it to.
type Job interface {
	Name() string

	// Interval of zero or less means "do not schedule me", which is how a job
	// is switched off by configuration rather than by removing it from the graph.
	Interval() time.Duration

	Run(ctx context.Context) error
}

// firstRunDelay keeps startup clear of housekeeping: the listeners are already
// accepting traffic by the time the first sweep runs.
const firstRunDelay = 30 * time.Second

type Cron struct {
	jobs   []Job
	logger *zap.SugaredLogger

	// firstRun is a field rather than the constant directly so tests do not
	// have to wait out the startup delay.
	firstRun time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(
	audit *audit_cleaner.CronJob,
	sessions *session_cleaner.CronJob,
	webhooks *webhook_dispatcher.CronJob,
	logger *zap.SugaredLogger,
) *Cron {
	return &Cron{
		jobs:     []Job{audit, sessions, webhooks},
		logger:   logger,
		firstRun: firstRunDelay,
	}
}

// Start launches one goroutine per enabled job and returns immediately.
func (c *Cron) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)

	for _, job := range c.jobs {
		interval := job.Interval()
		if interval <= 0 {
			c.logger.Infow("cron job disabled", "job", job.Name())
			continue
		}

		c.wg.Add(1)
		go c.loop(ctx, job, interval)

		c.logger.Infow("cron job scheduled", "job", job.Name(), "interval", interval.String())
	}
}

func (c *Cron) loop(ctx context.Context, job Job, interval time.Duration) {
	defer c.wg.Done()

	timer := time.NewTimer(c.firstRun)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.run(ctx, job)
			timer.Reset(interval)
		}
	}
}

// run isolates one execution. A failing cleanup is logged and the loop carries
// on: housekeeping must never be able to take down a service that is otherwise
// serving requests correctly.
func (c *Cron) run(ctx context.Context, job Job) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.Errorw("cron job panicked", "job", job.Name(), "panic", r)
		}
	}()

	if err := job.Run(ctx); err != nil {
		c.logger.Errorw("cron job failed", "job", job.Name(), "error", err)
	}
}

// Stop cancels the jobs and waits for any run already in progress.
//
// The wait is the point: it must return before the caller closes the database
// pool, or a job mid-query hits a closed pool on the way out.
func (c *Cron) Stop() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	c.wg.Wait()
}
