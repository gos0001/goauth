package postgres

import (
	"errors"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	DSN string `json:"url"`

	// AutoCreate creates the database named in the url when connecting shows
	// it is missing. Only that path needs the CREATEDB privilege, and it is
	// never taken when the database already exists.
	AutoCreate bool `json:"auto_create"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{AutoCreate: true}
	if err := root.Section("db", &cfg); err != nil {
		return Config{}, err
	}
	if cfg.DSN == "" {
		return Config{}, errors.New("db.url is required")
	}
	return cfg, nil
}
