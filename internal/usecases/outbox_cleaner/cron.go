package outbox_cleaner

import (
	"context"
	"time"

	"go.uber.org/zap"
)

type CronJob struct {
	uc     *Usecase
	logger *zap.SugaredLogger
	cfg    Config
}

func NewCronJob(uc *Usecase, logger *zap.SugaredLogger, cfg Config) *CronJob {
	return &CronJob{uc: uc, logger: logger, cfg: cfg}
}

func (j *CronJob) Name() string { return "outbox_cleaner" }

func (j *CronJob) Interval() time.Duration {
	if !j.cfg.Enabled() {
		return 0
	}
	return j.cfg.Interval
}

func (j *CronJob) Run(ctx context.Context) error {
	out, err := j.uc.Execute(ctx, Input{})
	if err != nil {
		return err
	}

	if out.Settled > 0 {
		j.logger.Infow("outbox trimmed", "settled", out.Settled)
	}
	// Warn, not info: these were never delivered to anyone, so their removal is
	// a loss rather than housekeeping, and it means delivery has been broken or
	// switched off for a month.
	if out.Stuck > 0 {
		j.logger.Warnw("undelivered outbox events abandoned",
			"count", out.Stuck, "max_age", j.cfg.MaxAge.String())
	}

	return nil
}
