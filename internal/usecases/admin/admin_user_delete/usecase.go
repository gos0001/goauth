package admin_user_delete

import (
	"context"
	"strings"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	CountActiveAdmins(ctx context.Context) (int, error)
	SoftDeleteUser(ctx context.Context, id string) (domain.User, error)
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

// Execute soft-deletes an account: the row stays, its identifiers are cleared,
// and its sessions are revoked.
//
// The row survives because other services hold this user_id in their own tables
// with no foreign key back here — a hard delete would leave those references
// pointing at nothing. Clearing the identifiers is what frees the address for
// reuse and satisfies an erasure request without breaking referential sanity.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
		return Output{}, err
	}

	if user.Status == domain.StatusDeleted {
		return Output{ID: user.ID, Status: string(user.Status)}, nil
	}

	if in.ActorUserID == user.ID {
		return Output{}, domain.ErrSelfDemote
	}

	if user.IsAdmin && user.Active() {
		admins, err := uc.postgres.CountActiveAdmins(ctx)
		if err != nil {
			return Output{}, err
		}
		if admins <= 1 {
			return Output{}, domain.ErrLastAdmin
		}
	}

	deleted, err := uc.postgres.SoftDeleteUser(ctx, user.ID)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserDeleted, deleted.ID, in.IP,
		map[string]any{"previous_identifier": user.Identifier()}))

	return Output{ID: deleted.ID, Status: string(deleted.Status)}, nil
}

type Input struct {
	ID          string `json:"-"`
	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.ID) == "" {
		return domain.ErrUserNotFound
	}
	return nil
}

type Output struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}
