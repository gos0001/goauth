package webhook_dispatcher

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// Interval is how often the outbox is drained. Zero stops the job being
	// scheduled at all.
	Interval time.Duration `envconfig:"WEBHOOK_INTERVAL" default:"10s"`

	// BatchSize bounds one drain, so a large backlog is worked through steadily
	// instead of in one long run holding a connection.
	BatchSize int `envconfig:"WEBHOOK_BATCH_SIZE" default:"50"`

	// MaxAttempts before an event is given up on. With the default backoff that
	// spans several hours — long enough to cover a receiver's deploy, short
	// enough that a permanently wrong URL stops being retried.
	MaxAttempts int `envconfig:"WEBHOOK_MAX_ATTEMPTS" default:"10"`

	BackoffBase time.Duration `envconfig:"WEBHOOK_BACKOFF_BASE" default:"10s"`
	BackoffMax  time.Duration `envconfig:"WEBHOOK_BACKOFF_MAX"  default:"1h"`

	// Retention removes settled rows — delivered or given up on. Pending events
	// are never pruned, however old.
	Retention time.Duration `envconfig:"WEBHOOK_RETENTION" default:"168h"`

	// Timeout mirrors the sender's, used to size the claim lease.
	Timeout time.Duration `envconfig:"WEBHOOK_TIMEOUT" default:"10s"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
