package postgres

import "github.com/kelseyhightower/envconfig"

type Config struct {
	DSN string `envconfig:"POSTGRES_URL" required:"true"`

	// AutoCreate creates the database named in POSTGRES_URL when connecting
	// shows it is missing. Only that path needs the CREATEDB privilege, and it
	// is never taken when the database already exists.
	AutoCreate bool `envconfig:"DB_AUTO_CREATE" default:"true"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}
