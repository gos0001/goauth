package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gos0001/goauth/pkg/appconfig"
)

type Config struct {
	Addr string `json:"addr"`
	ENV  string `json:"-"`

	// AdminAddr is the machine-facing admin listener. It binds to loopback by
	// default: a port that does not listen on a public interface cannot be
	// exposed by a mistaken ingress rule, which a path prefix on the shared
	// port could be.
	//
	// Inside Docker, 127.0.0.1 is the container's own loopback and unreachable
	// from sibling containers — set 0.0.0.0:8081 there and simply do not
	// publish the port.
	AdminAddr string `json:"admin_addr"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{
		Addr:      ":8080",
		AdminAddr: "127.0.0.1:8081",
		ENV:       root.Env,
	}
	if err := root.Section("app", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func waitForShutdown(fn func()) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fn()
}
