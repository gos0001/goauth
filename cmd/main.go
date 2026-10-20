package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
)

// Build information, injected at link time:
//
//	-ldflags "-X main.version=v1.2.3 -X main.commit=abc1234 -X main.buildDate=..."
//
// It is what ties a running container back to a commit; without it, "which
// build is this" has no answer once an image is retagged.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	// The whole service is configured from one JSON file; -config says where
	// it is. A flag rather than a hardcoded path, so several instances can
	// share a binary with different files.
	configPath := flag.String("config", "config.json", "path to config.json")
	flag.Parse()

	// A version subcommand rather than a flag, so `docker run <image> version`
	// works without an entrypoint override.
	if len(flag.Args()) > 0 && flag.Args()[0] == "version" {
		fmt.Printf("goauth %s (commit %s, built %s, %s %s/%s)\n",
			version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	app, err := InitializeApp(*configPath)
	if err != nil {
		log.Fatalf("init app: %v", err)
	}
	app.Run(BuildInfo{Version: version, Commit: commit, Date: buildDate})
}
