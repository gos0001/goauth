package audit_cleaner

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// CronJob is the scheduled entry point, in the same way http_v1.go is the HTTP
// one: the use case knows nothing about how often it runs.
type CronJob struct {
	uc     *Usecase
	logger *zap.SugaredLogger
	cfg    Config
}

func NewCronJob(uc *Usecase, logger *zap.SugaredLogger, cfg Config) *CronJob {
	return &CronJob{uc: uc, logger: logger, cfg: cfg}
}

func (j *CronJob) Name() string { return "audit_cleaner" }

// Interval of zero tells the runner not to schedule this job at all, which is
// how both limits being off switches it off entirely.
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

	// Silence when there was nothing to do: a job this frequent would otherwise
	// become the log noise it exists to prevent.
	if out.Total() > 0 {
		j.logger.Infow("audit log trimmed",
			"by_age", out.DeletedByAge, "by_cap", out.DeletedByCap)
	}

	return nil
}
