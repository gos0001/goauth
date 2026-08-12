package webhook_dispatcher

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

func (j *CronJob) Name() string { return "webhook_dispatcher" }

func (j *CronJob) Interval() time.Duration { return j.cfg.Interval }

func (j *CronJob) Run(ctx context.Context) error {
	out, err := j.uc.Execute(ctx, Input{})
	if err != nil {
		return err
	}

	// Quiet when there is nothing to deliver: this job runs every ten seconds
	// and would otherwise be the loudest thing in the log.
	if out.Touched() > 0 {
		j.logger.Infow("webhook events processed",
			"delivered", out.Delivered, "failed", out.Failed, "gave_up", out.GaveUp)
	}
	// Giving up loses an event permanently, so it is worth its own line.
	if out.GaveUp > 0 {
		j.logger.Warnw("webhook events abandoned after the attempt limit",
			"count", out.GaveUp, "max_attempts", j.cfg.MaxAttempts)
	}

	return nil
}
