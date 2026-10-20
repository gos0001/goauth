package logger

import (
	"go.uber.org/zap"
)

type Config struct {
	ENV string `json:"-"`
}

func New(cfg Config) (*zap.SugaredLogger, error) {
	var l *zap.Logger
	var err error
	if cfg.ENV == "production" {
		l, err = zap.NewProduction()
	} else {
		l, err = zap.NewDevelopment()
	}
	if err != nil {
		return nil, err
	}
	return l.Sugar(), nil
}
