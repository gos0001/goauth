package webhook

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	// URL receives the events. Empty disables webhooks entirely — events are
	// then not even written to the outbox, so nothing accumulates.
	URL string `envconfig:"WEBHOOK_URL"`

	// Secret signs each request. Strongly recommended: without it a receiver
	// cannot tell an event from goauth apart from a POST by anyone who learned
	// the URL.
	Secret string `envconfig:"WEBHOOK_SECRET"`

	// APIKey is sent verbatim as X-Goauth-Api-Key. It is a convenience for
	// receivers sitting behind a gateway that filters on a header, so the
	// request never reaches application code without it.
	//
	// It is not a substitute for Secret. A static key proves only that the
	// sender knows it: anyone who captures one request — from a log, a proxy, a
	// debug dump — can replay it verbatim and send any payload they like. The
	// signature covers the body and the timestamp, so neither is possible.
	APIKey string `envconfig:"WEBHOOK_API_KEY"`

	// Timeout for one delivery attempt. Kept short: a slow receiver must not
	// hold up the queue behind it.
	Timeout time.Duration `envconfig:"WEBHOOK_TIMEOUT" default:"10s"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

func (c Config) Enabled() bool { return c.URL != "" }
