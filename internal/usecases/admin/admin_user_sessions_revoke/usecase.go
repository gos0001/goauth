package admin_user_sessions_revoke

import (
	"context"
	"strings"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/audit"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetRole(ctx context.Context, name string) (domain.Role, error)
	DeleteUserSessions(ctx context.Context, userID string) (int, error)
}

type Guard interface {
	Actor(ctx context.Context, actorUserID string) (domain.Role, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	guard    Guard
	auditor  Auditor
}

func New(pg *postgresadapter.Adapter, guard *roleguard.Guard, auditor *audit.Recorder) *Usecase {
	return &Usecase{postgres: pg, guard: guard, auditor: auditor}
}

// Execute logs a user out everywhere without touching their credentials — the
// right response to "their laptop was stolen" when the password itself is fine.
//
// Access tokens already issued survive until they expire; only the refresh
// chain is cut. Blocking the account is the stronger action, because the admin
// guard and every login re-read status from the database.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.UserID)
	if err != nil {
		return Output{}, err
	}

	// Logging a peer out everywhere is a denial-of-service against them;
	// the same strict rank rule as every other management action applies.
	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}
	targetRole, err := uc.postgres.GetRole(ctx, user.Role)
	if err != nil {
		return Output{}, err
	}
	if err := roleguard.CanActOnUser(actor, targetRole.Rank); err != nil {
		return Output{}, err
	}

	n, err := uc.postgres.DeleteUserSessions(ctx, user.ID)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionSessionsRevoked, user.ID, in.IP,
		map[string]any{"count": n}))

	return Output{Revoked: n}, nil
}

type Input struct {
	UserID string `json:"-"`

	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.UserID) == "" {
		return domain.ErrUserNotFound
	}
	return nil
}

type Output struct {
	Revoked int `json:"revoked"`
}
