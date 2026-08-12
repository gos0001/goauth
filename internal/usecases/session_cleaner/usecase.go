// Package session_cleaner removes expired rows from ga_sessions.
//
// Refresh sessions are never deleted on expiry — rotation marks them used and
// the row stays — so without this the table keeps every session the service has
// ever issued.
package session_cleaner

import (
	"context"
	"fmt"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
)

type Postgres interface {
	DeleteExpiredSessions(ctx context.Context) (int, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

// Execute deletes every session past its expiry.
//
// Deleting them costs nothing in security terms: an expired session is already
// refused by auth_token, which checks expires_at before it checks anything else.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	n, err := uc.postgres.DeleteExpiredSessions(ctx)
	if err != nil {
		return Output{}, fmt.Errorf("session_cleaner: delete expired: %w", err)
	}
	return Output{Deleted: n}, nil
}

type Input struct{}

type Output struct {
	Deleted int
}
