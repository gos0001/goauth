// Package postgres is a thin wrapper over pgxpool. Zero domain imports —
// mapping rows to domain types is the adapter's job, not this package's.
package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pool struct {
	*pgxpool.Pool
}

// New opens the pool and pings it, so a bad DSN fails at startup rather than on
// the first request.
func New(cfg Config) (*Pool, error) {
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return &Pool{Pool: pool}, nil
}

func (p *Pool) Close() {
	p.Pool.Close()
}
