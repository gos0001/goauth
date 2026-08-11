package auth_logout_all

import (
	"context"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	DeleteUserSessions(ctx context.Context, userID string) (int, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	auditor  Auditor
}

func New(pg *postgresadapter.Adapter, auditor *audit.Recorder) *Usecase {
	return &Usecase{postgres: pg, auditor: auditor}
}

// Execute drops every session of the caller, this one included. Used from the
// "log out everywhere" button, the correct move after losing a device.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	n, err := uc.postgres.DeleteUserSessions(ctx, in.UserID)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(in.UserID), domain.ActionSessionsRevoked, in.UserID, in.IP,
		map[string]any{"count": n}))

	return Output{Revoked: n}, nil
}

type Input struct {
	UserID string `json:"-"`
	IP     string `json:"-"`
}

type Output struct {
	Revoked int `json:"revoked"`
}
