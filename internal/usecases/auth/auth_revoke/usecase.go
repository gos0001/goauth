package auth_revoke

import (
	"context"
	"errors"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	GetSessionByID(ctx context.Context, id string) (domain.Session, error)
	DeleteSessionFamily(ctx context.Context, familyID string) (int, error)
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

// Execute logs the caller out of the current device.
//
// It deletes the whole family, not just the current row: the family is one
// login's rotation chain, so leaving the rest of it alive would let a refresh
// token issued earlier in that chain carry on producing new sessions.
//
// The access token itself outlives this call by up to its TTL. That is inherent
// to stateless tokens and is why the TTL is minutes — anything needing instant
// revocation checks the database, as the admin guard does.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	if in.SessionID == "" {
		return Output{}, domain.ErrSessionNotFound
	}

	session, err := uc.postgres.GetSessionByID(ctx, in.SessionID)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			// Already gone: logging out twice is not an error worth reporting.
			return Output{Revoked: 0}, nil
		}
		return Output{}, err
	}

	if session.UserID != in.UserID {
		// The session id came from the caller's own verified token, so this
		// can only mean tampering.
		return Output{}, domain.ErrForbidden
	}

	n, err := uc.postgres.DeleteSessionFamily(ctx, session.FamilyID)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(in.UserID), domain.ActionSessionRevoked, in.UserID, in.IP,
		map[string]any{"family_id": session.FamilyID}))

	return Output{Revoked: n}, nil
}

type Input struct {
	UserID    string `json:"-"`
	SessionID string `json:"-"`
	IP        string `json:"-"`
}

type Output struct {
	Revoked int `json:"revoked"`
}
