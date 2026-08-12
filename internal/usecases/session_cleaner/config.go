package session_cleaner

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Interval is how often expired sessions are swept. Zero disables the job.
	//
	// There is no retention setting to go with it: a session already carries its
	// own expires_at, so "expired" is not a policy decision to be configured
	// twice.
	Interval time.Duration `envconfig:"SESSION_CLEANUP_INTERVAL" default:"1h"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
