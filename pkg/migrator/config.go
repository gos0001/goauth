package migrator

import "github.com/kelseyhightower/envconfig"

type Config struct {
	// URL is the same connection string the pool uses; the migrator opens its
	// own short-lived connection and closes it when done.
	URL string `envconfig:"POSTGRES_URL" required:"true"`

	// AutoMigrate applies pending migrations at startup. On by default so that
	// `docker run` against an empty database just works — which is the whole
	// point of shipping an image. Set false where a deployment pipeline owns
	// schema changes explicitly.
	AutoMigrate bool `envconfig:"AUTO_MIGRATE" default:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
