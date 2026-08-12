package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/controller/admin_v1"
	"github.com/gos0001/goauth/internal/orchestrators/bootstrap"
	"github.com/gos0001/goauth/internal/orchestrators/cron"
	pkgpostgres "github.com/gos0001/goauth/pkg/postgres"
	pkgredis "github.com/gos0001/goauth/pkg/redis"
)

type App struct {
	logger    *zap.SugaredLogger
	bootstrap *bootstrap.Bootstrap
	cron      *cron.Cron

	httpServer  *http.Server
	adminServer *http.Server

	pg  *pkgpostgres.Pool
	rdb *pkgredis.Client
}

func NewApp(
	logger *zap.SugaredLogger,
	router *gin.Engine,
	adminRouter *admin_v1.Router,
	boot *bootstrap.Bootstrap,
	scheduler *cron.Cron,
	cfg Config,
	pg *pkgpostgres.Pool,
	rdb *pkgredis.Client,
) *App {
	app := &App{
		logger:    logger,
		bootstrap: boot,
		cron:      scheduler,
		httpServer: &http.Server{
			Addr:    cfg.Addr,
			Handler: router,
		},
		pg:  pg,
		rdb: rdb,
	}

	// The private listener exists only when ADMIN_TOKEN is configured. No
	// token means no machine-facing admin surface at all — never a default
	// credential, never an unauthenticated one.
	if adminRouter.Enabled() {
		app.adminServer = &http.Server{
			Addr:    cfg.AdminAddr,
			Handler: adminRouter.Engine,
		}
	}

	return app
}

// BuildInfo is stamped into the binary at link time and logged once at startup.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

func (a *App) Run(build BuildInfo) {
	a.logger.Infow("goauth starting",
		"version", build.Version, "commit", build.Commit, "built", build.Date)

	// Startup work — migrations, then the bootstrap admin — runs before the
	// listeners open, so no request can observe a half-initialised installation.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := a.bootstrap.Run(ctx)
	cancel()
	if err != nil {
		a.logger.Fatalw("bootstrap failed", "error", err)
	}

	a.logger.Infow("starting server", "addr", a.httpServer.Addr)
	go a.serve(a.httpServer, "public")

	if a.adminServer != nil {
		a.logger.Infow("starting admin server", "addr", a.adminServer.Addr)
		go a.serve(a.adminServer, "admin")
	} else {
		a.logger.Info("admin listener disabled: ADMIN_TOKEN is not set")
	}

	// Housekeeping starts only once the listeners are up, so a slow first sweep
	// cannot delay the service becoming available.
	a.cron.Start(context.Background())

	waitForShutdown(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Stop accepting requests before tearing down what they depend on.
		if err := a.httpServer.Shutdown(ctx); err != nil {
			a.logger.Errorw("shutdown error", "error", err)
		}
		if a.adminServer != nil {
			if err := a.adminServer.Shutdown(ctx); err != nil {
				a.logger.Errorw("admin shutdown error", "error", err)
			}
		}

		// Before the pool closes: a job mid-query would otherwise find it shut.
		a.cron.Stop()

		a.pg.Close()
		if err := a.rdb.Close(); err != nil {
			a.logger.Errorw("redis close error", "error", err)
		}

		a.logger.Info("server stopped")
	})
}

func (a *App) serve(s *http.Server, name string) {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.logger.Fatalw("server error", "listener", name, "addr", s.Addr, "error", err)
	}
}
