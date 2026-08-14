package outbox_cleaner

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Interval is how often the sweep runs. Zero disables the job.
	Interval time.Duration `envconfig:"OUTBOX_CLEANUP_INTERVAL" default:"1h"`

	// Retention is how long a settled event — delivered, or given up on — is
	// kept. Reads the same variable the webhook block already uses rather than
	// inventing a second name for one window.
	Retention time.Duration `envconfig:"WEBHOOK_RETENTION" default:"168h"`

	// MaxAge bounds events that were never delivered and never abandoned.
	// Deliberately far wider than Retention: deleting one loses it for good, and
	// it only ever applies to events nothing is going to deliver — delivery
	// switched off, or an interval of zero. Zero disables it.
	MaxAge time.Duration `envconfig:"OUTBOX_MAX_AGE" default:"720h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

func (c Config) Enabled() bool {
	return c.Interval > 0 && (c.Retention > 0 || c.MaxAge > 0)
}
