package session_cleaner

import (
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// Interval is how often expired sessions are swept. Zero disables the job.
	//
	// There is no retention setting to go with it: a session already carries its
	// own expires_at, so "expired" is not a policy decision to be configured
	// twice.
	Interval time.Duration `json:"cleanup_interval"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{Interval: time.Hour}
	if err := root.Section("sessions", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
