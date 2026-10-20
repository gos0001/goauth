// Package admin_role_create makes a new administrative role. The rules are
// the guard's: the new rank sits strictly below the actor's own, every granted
// permission is one the actor holds, and ranks 0 and 100 stay reserved for
// the built-in floor.
package admin_role_create

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/audit"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
)

// Reserved names are the built-ins plus anything that would read as one.
// Seeding owns these; the API cannot overwrite the floor.
var reservedNames = map[string]struct{}{
	domain.RoleUser:       {},
	domain.RoleManager:    {},
	domain.RoleAdmin:      {},
	domain.RoleSuperAdmin: {},
}

type Postgres interface {
	CreateRole(ctx context.Context, r domain.Role) (domain.Role, error)
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
	if _, reserved := reservedNames[name]; reserved || !domain.ValidRoleName(name) {
		return Output{}, domain.ErrInvalidInput
	}
	if !domain.ValidCustomRank(in.Rank) {
		return Output{}, domain.ErrInvalidInput
	}

	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}
	if err := roleguard.CanActOnRole(actor, in.Rank); err != nil {
		return Output{}, err
	}
	if err := roleguard.MayPlaceInRole(actor, in.Permissions); err != nil {
		return Output{}, err
	}

	// is_system is not an input: the API cannot mint a role the seed owns,
	// because the floor must stay beneath every operator's feet.
	created, err := uc.postgres.CreateRole(ctx, domain.Role{
		Name:        name,
		Rank:        in.Rank,
		Permissions: in.Permissions,
	})
	if err != nil {
		return Output{}, err
	}

	// Permissions land in the same call as the row; the audit entry names
	// them so a grant is readable without joining the role tables.
	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionRoleCreated, "", in.IP,
		map[string]any{"role": created.Name, "rank": created.Rank, "permissions": permStrings(in.Permissions)}))

	return Output{Role: roleView(created)}, nil
}

type Input struct {
	Name        string              `json:"name"`
	Rank        int                 `json:"rank"`
	Permissions []domain.Permission `json:"permissions"`

	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	if _, reserved := reservedNames[name]; reserved || !domain.ValidRoleName(name) {
		return domain.ErrInvalidInput
	}
	if !domain.ValidCustomRank(in.Rank) {
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
