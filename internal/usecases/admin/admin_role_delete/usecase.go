// Package admin_role_delete removes a custom role nobody holds. System roles
// are refused, and so is any role still assigned: the database's foreign key
// would block it anyway, but as a raw constraint error the caller could not
// answer for.
package admin_role_delete

import (
	"context"
	"strings"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/roleguard"
)

type Postgres interface {
	GetRole(ctx context.Context, name string) (domain.Role, error)
	DeleteRole(ctx context.Context, name string) error
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

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))

	current, err := uc.postgres.GetRole(ctx, name)
	if err != nil {
		return Output{}, err
	}
	if current.IsSystem {
		return Output{}, domain.ErrRoleProtected
	}

	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}
	if err := roleguard.CanActOnRole(actor, current.Rank); err != nil {
		return Output{}, err
	}

	if err := uc.postgres.DeleteRole(ctx, name); err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionRoleDeleted, "", in.IP,
		map[string]any{"role": name, "rank": current.Rank}))

	return Output{Deleted: name}, nil
}

type Input struct {
	Name string `json:"-"`

	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return domain.ErrRoleNotFound
	}
	return nil
}

type Output struct {
	Deleted string `json:"deleted"`
}
