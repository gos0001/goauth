// Package admin_role_update edits a custom role: its rank and its permission
// set. System roles are refused outright — the floor the service boots with
// must not be re-laid from inside the building — and every change keeps the
// guard's rules: the target rank strictly below the actor's, both before and
// after the edit, and no permission the actor does not hold.
package admin_role_update

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/roleguard"
)

type Postgres interface {
	GetRole(ctx context.Context, name string) (domain.Role, error)
	UpdateRole(ctx context.Context, p postgresadapter.UpdateRoleParams) (domain.Role, error)
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
	// Against the current rank first: an admin must not be able to edit the
	// admin role even to lower it, and then against the new one, so nobody
	// lifts a role to their own level by editing it.
	if err := roleguard.CanActOnRole(actor, current.Rank); err != nil {
		return Output{}, err
	}

	p := postgresadapter.UpdateRoleParams{Name: name}
	if in.Rank != nil {
		if !domain.ValidCustomRank(*in.Rank) {
			return Output{}, domain.ErrInvalidInput
		}
		if err := roleguard.CanActOnRole(actor, *in.Rank); err != nil {
			return Output{}, err
		}
		p.Rank = in.Rank
	}
	if in.Permissions != nil {
		if err := roleguard.MayPlaceInRole(actor, in.Permissions); err != nil {
			return Output{}, err
		}
		p.Permissions = in.Permissions
	}

	updated, err := uc.postgres.UpdateRole(ctx, p)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionRoleUpdated, "", in.IP,
		map[string]any{"role": name, "rank": updated.Rank, "permissions": permStrings(updated.Permissions)}))

	return Output{Role: roleView(updated)}, nil
}

// Input uses pointers so "field omitted" and "field set to zero" stay
// distinguishable in a PATCH.
type Input struct {
	Name        string              `json:"-"`
	Rank        *int                `json:"rank"`
	Permissions []domain.Permission `json:"permissions"`

	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return domain.ErrRoleNotFound
	}
	if in.Rank == nil && in.Permissions == nil {
		return domain.ErrInvalidInput
	}
	if in.Rank != nil && !domain.ValidCustomRank(*in.Rank) {
		return domain.ErrInvalidInput
	}
	return domain.ValidatePermissions(in.Permissions)
}

type Output struct {
	Role RoleView `json:"role"`
}

type RoleView struct {
	Name        string    `json:"name"`
	Rank        int       `json:"rank"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

func roleView(r domain.Role) RoleView {
	return RoleView{
		Name:        r.Name,
		Rank:        r.Rank,
		IsSystem:    r.IsSystem,
		Permissions: permStrings(r.Permissions),
		CreatedAt:   r.CreatedAt,
	}
}

func permStrings(perms []domain.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}
