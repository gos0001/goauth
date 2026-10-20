package webhook

import (
	"time"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// URL receives the events. Empty disables webhooks entirely — events are
	// then not even written to the outbox, so nothing accumulates.
	URL string `json:"url"`

	// Secret signs each request. Strongly recommended: without it a receiver
	// cannot tell an event from goauth apart from a POST by anyone who learned
	// the URL.
	Secret string `json:"secret"`

	// APIKey is sent verbatim as X-Goauth-Api-Key. It is a convenience for
	// receivers sitting behind a gateway that filters on a header, so the
	// request never reaches application code without it.
	//
	// It is not a substitute for Secret. A static key proves only that the
	// sender knows it: anyone who captures one request — from a log, a proxy, a
	// debug dump — can replay it verbatim and send any payload they like. The
	// signature covers the body and the timestamp, so neither is possible.
	APIKey string `json:"api_key"`

	// Timeout for one delivery attempt. Kept short: a slow receiver must not
	// hold up the queue behind it.
	Timeout time.Duration `json:"timeout"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{Timeout: 10 * time.Second}
	if err := root.Section("webhook", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Enabled() bool { return c.URL != "" }
