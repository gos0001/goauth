package webhook_dispatcher

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/gos0001/goauth/pkg/webhook"
)

type CronJob struct {
	uc     *Usecase
	sender Sender
	logger *zap.SugaredLogger
	cfg    Config
}

func NewCronJob(uc *Usecase, sender *webhook.Sender, logger *zap.SugaredLogger, cfg Config) *CronJob {
	return &CronJob{uc: uc, sender: sender, logger: logger, cfg: cfg}
}

func (j *CronJob) Name() string { return "webhook_dispatcher" }

// Zero when no webhook is configured, so the runner does not schedule a job
// that would wake every ten seconds only to report itself skipped.
func (j *CronJob) Interval() time.Duration {
	if !j.sender.Enabled() {
		return 0
	}
	return j.cfg.Interval
}

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
