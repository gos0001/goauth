package audit_cleaner

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Retention is how long an audit entry is kept. Zero disables deletion by
	// age entirely — the zero value has to mean "keep everything", because the
	// alternative reading would silently erase the audit trail of anyone who
	// left the variable unset.
	Retention time.Duration `envconfig:"AUDIT_RETENTION" default:"720h"`

	// MaxRows caps the table regardless of age, keeping the newest entries.
	// Off by default; useful where the log has to fit a fixed disk rather than
	// a fixed window.
	MaxRows int `envconfig:"AUDIT_MAX_ROWS" default:"0"`

	// Interval is how often the cleanup runs. Zero stops the job from being
	// scheduled at all.
	Interval time.Duration `envconfig:"AUDIT_CLEANUP_INTERVAL" default:"6h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

// Enabled reports whether there is anything for the job to do.
func (c Config) Enabled() bool {
	return c.Interval > 0 && (c.Retention > 0 || c.MaxRows > 0)
}
