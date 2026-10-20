package outbox_cleaner

import (
	"time"

	"github.com/gos0001/goauth/v2/pkg/appconfig"
)

type Config struct {
	// Interval is how often the sweep runs. Zero disables the job.
	Interval time.Duration `json:"cleanup_interval"`

	// Retention is how long a settled event — delivered, or given up on — is
	// kept.
	Retention time.Duration `json:"retention"`

	// MaxAge bounds events that were never delivered and never abandoned.
	// Deliberately far wider than Retention: deleting one loses it for good, and
	// it only ever applies to events nothing is going to deliver — delivery
	// switched off, or an interval of zero. Zero disables it.
	MaxAge time.Duration `json:"max_age"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		Interval:  time.Hour,
		Retention: 168 * time.Hour,
		MaxAge:    720 * time.Hour,
	}
	if err := root.Section("outbox", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Enabled() bool {
	return c.Interval > 0 && (c.Retention > 0 || c.MaxAge > 0)
}
