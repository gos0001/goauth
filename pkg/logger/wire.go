package logger

import (
	"github.com/google/wire"
	"github.com/gos0001/goauth/pkg/appconfig"
)

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{ENV: root.Env}
	return cfg, nil
}

var Set = wire.NewSet(LoadConfig, New)
