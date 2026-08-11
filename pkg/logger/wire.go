package logger

import (
	"github.com/google/wire"
	"github.com/kelseyhightower/envconfig"
)

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

var Set = wire.NewSet(LoadConfig, New)
