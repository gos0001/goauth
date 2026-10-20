package webhook_dispatcher

import (
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// Interval is how often the outbox is drained. Zero stops the job being
	// scheduled at all.
	Interval time.Duration `json:"interval"`

	// BatchSize bounds one drain, so a large backlog is worked through steadily
	// instead of in one long run holding a connection.
	BatchSize int `json:"batch_size"`

	// MaxAttempts before an event is given up on. With the default backoff that
	// spans several hours — long enough to cover a receiver's deploy, short
	// enough that a permanently wrong URL stops being retried.
	MaxAttempts int `json:"max_attempts"`

	BackoffBase time.Duration `json:"backoff_base"`
	BackoffMax  time.Duration `json:"backoff_max"`

	// Timeout mirrors the sender's, used to size the claim lease.
	Timeout time.Duration `json:"timeout"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		Interval:    10 * time.Second,
		BatchSize:   50,
		MaxAttempts: 10,
		BackoffBase: 10 * time.Second,
		BackoffMax:  time.Hour,
		Timeout:     10 * time.Second,
	}
	if err := root.Section("webhook", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
