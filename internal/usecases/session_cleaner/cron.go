package session_cleaner

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

func (j *CronJob) Name() string { return "session_cleaner" }

func (j *CronJob) Interval() time.Duration { return j.cfg.Interval }

func (j *CronJob) Run(ctx context.Context) error {
	out, err := j.uc.Execute(ctx, Input{})
	if err != nil {
		return err
	}
	if out.Deleted > 0 {
		j.logger.Infow("expired sessions removed", "count", out.Deleted)
	}
	return nil
}
