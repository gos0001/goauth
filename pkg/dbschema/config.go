package dbschema

import (
	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	// AutoSchema creates missing tables at startup. On by default so that
	// `docker run` against an empty database just works — which is the point of
	// shipping an image. Set false where a deployment pipeline owns schema
	// changes; the service then refuses to serve against absent tables rather
	// than creating them itself.
	AutoSchema bool `json:"auto_schema"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{AutoSchema: true}
	if err := root.Section("db", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
