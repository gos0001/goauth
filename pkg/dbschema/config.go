package dbschema

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// AutoSchema creates missing tables at startup. On by default so that
	// `docker run` against an empty database just works — which is the point of
	// shipping an image. Set false where a deployment pipeline owns schema
	// changes; the service then refuses to serve against absent tables rather
	// than creating them itself.
	AutoSchema bool `envconfig:"DB_AUTO_SCHEMA" default:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
