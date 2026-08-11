// Package sys_health answers the container orchestrator's liveness probe.
package sys_health

import (
	"context"
	"fmt"

	pkgpostgres "github.com/gos0001/goauth/pkg/postgres"
	pkgredis "github.com/gos0001/goauth/pkg/redis"
)

type Usecase struct {
	pg  *pkgpostgres.Pool
	rdb *pkgredis.Client
}

func New(pg *pkgpostgres.Pool, rdb *pkgredis.Client) *Usecase {
	return &Usecase{pg: pg, rdb: rdb}
}

// Execute pings both backends. Redis being down is reported but does not fail
// the check: authentication still works without it, only rate limiting is
// degraded, and failing the probe would have the orchestrator restart a service
// that is doing its job.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	out := Output{Status: "ok", Postgres: "ok", Redis: "ok"}

	if err := uc.pg.Ping(ctx); err != nil {
		out.Status = "degraded"
		out.Postgres = "down"
		return out, fmt.Errorf("sys_health: postgres: %w", err)
	}

	if err := uc.rdb.Ping(ctx).Err(); err != nil {
		out.Status = "degraded"
		out.Redis = "down"
	}

	return out, nil
}

type Input struct{}

type Output struct {
	Status   string `json:"status"`
	Postgres string `json:"postgres"`
	Redis    string `json:"redis"`
}
