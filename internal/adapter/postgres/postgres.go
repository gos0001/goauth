// Package postgres adapts the database to domain types.
//
// Rules this package must keep:
//   - every method returns domain types, never sqlc's generated.* structs
//   - storage errors are mapped to domain errors (pgx.ErrNoRows →
//     domain.ErrNotFound, pgconn code 23505 → domain.ErrAlreadyExists)
//   - queries live in queries/*.sql and are compiled by `sqlc generate`;
//     never hand-write SQL strings in Go, and never edit generated/
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
	pkgpostgres "github.com/gos0001/goauth/pkg/postgres"
)

// uniqueViolation is Postgres' SQLSTATE for a duplicate key.
const uniqueViolation = "23505"

type Adapter struct {
	pool *pkgpostgres.Pool
	q    *generated.Queries
}

func New(pool *pkgpostgres.Pool) *Adapter {
	return &Adapter{pool: pool, q: generated.New(pool.Pool)}
}

// MapError translates a storage error into a domain error. Repository methods
// should funnel their errors through this so use cases only ever see domain
// errors and can branch on them with errors.Is.
func MapError(err error, notFound error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		if notFound != nil {
			return notFound
		}
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return domain.ErrAlreadyExists
	}
	return err
}

// withTx runs fn inside a transaction with a transaction-scoped Queries. Used
// where two writes must not be observable apart — rotating a refresh token,
// or blocking a user and killing their sessions.
func (a *Adapter) withTx(ctx context.Context, fn func(q *generated.Queries) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(a.q.WithTx(tx)); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}
