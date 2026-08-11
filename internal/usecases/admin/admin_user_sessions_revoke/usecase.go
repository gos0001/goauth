package admin_user_sessions_revoke

import (
	"context"
	"strings"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
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
	Actor  string `json:"-"`
	IP     string `json:"-"`
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
