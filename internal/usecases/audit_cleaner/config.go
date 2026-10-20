package audit_cleaner

import (
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// Retention is how long an audit entry is kept. Zero disables deletion by
	// age entirely — the zero value has to mean "keep everything", because the
	// alternative reading would silently erase the audit trail of anyone who
	// left the setting unset.
	Retention time.Duration `json:"retention"`

	// MaxRows caps the table regardless of age, keeping the newest entries.
	// Off by default; useful where the log has to fit a fixed disk rather than
	// a fixed window.
	MaxRows int `json:"max_rows"`

	// Interval is how often the cleanup runs. Zero stops the job from being
	// scheduled at all.
	Interval time.Duration `json:"cleanup_interval"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		Retention: 720 * time.Hour,
		MaxRows:   0,
		Interval:  6 * time.Hour,
	}
	if err := root.Section("audit", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Enabled reports whether there is anything for the job to do.
func (c Config) Enabled() bool {
	return c.Interval > 0 && (c.Retention > 0 || c.MaxRows > 0)
}
