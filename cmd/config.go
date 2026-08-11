package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Addr string `envconfig:"APP_ADDR" default:":8080"`
	ENV  string `envconfig:"APP_ENV"  default:"development"`

	// AdminAddr is the machine-facing admin listener. It binds to loopback by
	// default: a port that does not listen on a public interface cannot be
	// exposed by a mistaken ingress rule, which a path prefix on the shared
	// port could be.
	//
	// Inside Docker, 127.0.0.1 is the container's own loopback and unreachable
	// from sibling containers — set 0.0.0.0:8081 there and simply do not
	// publish the port.
	AdminAddr string `envconfig:"ADMIN_ADDR" default:"127.0.0.1:8081"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

func waitForShutdown(fn func()) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fn()
}
