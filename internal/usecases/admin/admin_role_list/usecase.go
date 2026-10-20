// Package admin_role_list answers "which roles exist and what do they carry".
// It is what a panel renders the assignment dropdown from, and what an
// operator reads before granting anything.
package admin_role_list

import (
	"context"
	"time"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
)

type Postgres interface {
	ListRoles(ctx context.Context) ([]domain.Role, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	roles, err := uc.postgres.ListRoles(ctx)
	if err != nil {
		return Output{}, err
	}

	out := make([]RoleView, 0, len(roles))
	for _, r := range roles {
		perms := make([]string, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			perms = append(perms, string(p))
		}
		out = append(out, RoleView{
			Name:        r.Name,
			Rank:        r.Rank,
			IsSystem:    r.IsSystem,
			Permissions: perms,
			CreatedAt:   r.CreatedAt,
		})
	}
	return Output{Roles: out}, nil
}

type Input struct{}

type Output struct {
	Roles []RoleView `json:"roles"`
}

type RoleView struct {
	Name        string    `json:"name"`
	Rank        int       `json:"rank"`
	IsSystem    bool      `json:"is_system"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}
