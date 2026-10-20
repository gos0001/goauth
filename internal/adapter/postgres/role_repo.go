package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
)

// CreateRole inserts the role and attaches its permission set in one
// transaction, so no observer can ever see a role that exists but is missing
// its grants.
func (a *Adapter) CreateRole(ctx context.Context, r domain.Role) (domain.Role, error) {
	var out domain.Role
	err := a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.CreateRole(ctx, generated.CreateRoleParams{
			Name:     r.Name,
			Rank:     int32(r.Rank),
			IsSystem: r.IsSystem,
		})
		if err != nil {
			// 23505 covers both a taken name and a taken rank; the caller has
			// usually already distinguished them, so the generic mapping only
			// fires as the race backstop.
			return MapError(err, domain.ErrRoleAlreadyExists)
		}
		if err := replaceRolePermissions(ctx, q, r.Name, r.Permissions); err != nil {
			return err
		}
		out = toDomainRole(row, permissionStrings(r.Permissions))
		return nil
	})
	if err != nil {
		return domain.Role{}, err
	}
	return out, nil
}

func (a *Adapter) GetRole(ctx context.Context, name string) (domain.Role, error) {
	row, err := a.q.GetRole(ctx, name)
	if err != nil {
		return domain.Role{}, MapError(err, domain.ErrRoleNotFound)
	}
	perms, err := a.q.ListRolePermissions(ctx, name)
	if err != nil {
		return domain.Role{}, MapError(err, nil)
	}
	return toDomainRole(row, perms), nil
}

func (a *Adapter) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := a.q.ListRoles(ctx)
	if err != nil {
		return nil, MapError(err, nil)
	}

	out := make([]domain.Role, 0, len(rows))
	for _, row := range rows {
		perms, err := a.q.ListRolePermissions(ctx, row.Name)
		if err != nil {
			return nil, MapError(err, nil)
		}
		out = append(out, toDomainRole(row, perms))
	}
	return out, nil
}

// UpdateRoleParams uses pointers so "not supplied" and "set to zero" stay
// distinguishable; a nil field leaves the column untouched.
type UpdateRoleParams struct {
	Name     string
	Rank     *int
	IsSystem *bool
	// Permissions, when non-nil, replaces the whole set.
	Permissions []domain.Permission
}

func (a *Adapter) UpdateRole(ctx context.Context, p UpdateRoleParams) (domain.Role, error) {
	arg := generated.UpdateRoleParams{Name: p.Name}
	if p.Rank != nil {
		arg.Rank = int32Ptr(p.Rank)
	}
	if p.IsSystem != nil {
		arg.IsSystem = boolIn(p.IsSystem)
	}

	var out domain.Role
	err := a.withTx(ctx, func(q *generated.Queries) error {
		row, err := q.UpdateRole(ctx, arg)
		if err != nil {
			return MapError(err, domain.ErrRoleNotFound)
		}

		perms := p.Permissions
		if perms != nil {
			if err := replaceRolePermissions(ctx, q, p.Name, perms); err != nil {
				return err
			}
		} else {
			existing, err := q.ListRolePermissions(ctx, p.Name)
			if err != nil {
				return MapError(err, nil)
			}
			perms = make([]domain.Permission, 0, len(existing))
			for _, e := range existing {
				perms = append(perms, domain.Permission(e))
			}
		}
		out = toDomainRole(row, permissionStrings(perms))
		return nil
	})
	if err != nil {
		return domain.Role{}, err
	}
	return out, nil
}

// DeleteRole refuses through ErrRoleInUse when users still hold it: the
// foreign key would reject the delete anyway, but as a raw constraint error
// the caller cannot answer for.
func (a *Adapter) DeleteRole(ctx context.Context, name string) error {
	n, err := a.q.CountUsersWithRole(ctx, name)
	if err != nil {
		return MapError(err, nil)
	}
	if n > 0 {
		return domain.ErrRoleInUse
	}
	err = a.q.DeleteRole(ctx, name)
	return MapError(err, domain.ErrRoleNotFound)
}

// ActorRole is the authorisation snapshot the middleware asks for on every
// admin request: the actor's role with its rank and permissions.
func (a *Adapter) ActorRole(ctx context.Context, userID string) (domain.Role, error) {
	id, err := parseUUID(userID)
	if err != nil {
		return domain.Role{}, domain.ErrUserNotFound
	}

	row, err := a.q.GetUserRole(ctx, id)
	if err != nil {
		return domain.Role{}, MapError(err, domain.ErrUserNotFound)
	}
	perms, err := a.q.GetUserRolePermissions(ctx, id)
	if err != nil {
		return domain.Role{}, MapError(err, nil)
	}

	r := domain.Role{
		Name:     row.Name,
		Rank:     int(row.Rank),
		IsSystem: row.IsSystem,
	}
	for _, p := range perms {
		r.Permissions = append(r.Permissions, domain.Permission(p))
	}
	return r, nil
}

// SeedRole inserts the role only when absent. The database is the truth; the
// seed never overwrites a rank or a permission an operator changed at runtime.
// ON CONFLICT DO NOTHING returns no row, which reads here as ErrNoRows.
func (a *Adapter) SeedRole(ctx context.Context, r domain.Role) (bool, error) {
	_, err := a.q.SeedRole(ctx, generated.SeedRoleParams{
		Name:     r.Name,
		Rank:     int32(r.Rank),
		IsSystem: r.IsSystem,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, MapError(err, nil)
	}

	for _, p := range r.Permissions {
		if err := a.q.SeedRolePermission(ctx, generated.SeedRolePermissionParams{
			Role:       r.Name,
			Permission: string(p),
		}); err != nil {
			return false, MapError(err, nil)
		}
	}
	return true, nil
}

func replaceRolePermissions(ctx context.Context, q *generated.Queries, role string, perms []domain.Permission) error {
	if err := q.DeleteRolePermissions(ctx, role); err != nil {
		return MapError(err, nil)
	}
	for _, p := range perms {
		if err := q.AddRolePermission(ctx, generated.AddRolePermissionParams{
			Role:       role,
			Permission: string(p),
		}); err != nil {
			return MapError(err, nil)
		}
	}
	return nil
}

func permissionStrings(perms []domain.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}

func toDomainRole(r generated.GaRole, perms []string) domain.Role {
	out := domain.Role{
		Name:      r.Name,
		Rank:      int(r.Rank),
		IsSystem:  r.IsSystem,
		CreatedAt: tsOut(r.CreatedAt),
	}
	for _, p := range perms {
		out.Permissions = append(out.Permissions, domain.Permission(p))
	}
	return out
}
