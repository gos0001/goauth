// Package roleguard centralises the rank discipline every role-touching use
// case needs: who may act on which role, and which permissions may be placed
// into one. One place, because the rules must not drift between create,
// update and delete.
package roleguard

import (
	"context"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type Postgres interface {
	ActorRole(ctx context.Context, userID string) (domain.Role, error)
}

type Guard struct {
	postgres Postgres
}

// New takes the concrete adapter: the guard is the one service every admin
// use case leans on, and an interface parameter here would force a wire.Bind
// into every consumer's set.
func New(pg *postgresadapter.Adapter) *Guard {
	return &Guard{postgres: pg}
}

// Actor resolves the acting party's role. An empty userID is the machine
// caller holding the static token on the private listener: it is trusted with
// the whole surface, so it is modelled as a superadmin rather than given
// parallel code paths in every use case.
func (g *Guard) Actor(ctx context.Context, actorUserID string) (domain.Role, error) {
	if actorUserID == "" {
		all := domain.AllPermissions()
		return domain.Role{
			Name:        domain.RoleSuperAdmin,
			Rank:        domain.RankSuperAdmin,
			IsSystem:    true,
			Permissions: all,
		}, nil
	}
	return g.postgres.ActorRole(ctx, actorUserID)
}

// CanActOnRole answers whether the actor may create, edit or delete a role
// with the given rank. Strictly below, always: an admin must not be able to
// edit the admin role, because "edit" includes the permissions other admins
// hold.
func CanActOnRole(actor domain.Role, targetRank int) error {
	if !domain.MayAssign(actor.Rank, targetRank) {
		return domain.ErrInsufficientRank
	}
	return nil
}

// CanActOnUser answers whether the actor may manage a user holding the given
// rank. Same strict rule as roles: an equal is out of reach both ways, which
// is what stops two admins from deleting each other.
func CanActOnUser(actor domain.Role, targetRank int) error {
	if !domain.CanManage(actor.Rank, targetRank) {
		return domain.ErrInsufficientRank
	}
	return nil
}

// MayPlaceInRole answers whether the actor may put exactly this set of
// permissions into a role. Two rules in one: names must be part of the
// vocabulary, and the actor must hold everything granted — you cannot hand
// out what you were not given, or roles:manage alone becomes full escalation.
func MayPlaceInRole(actor domain.Role, perms []domain.Permission) error {
	if err := domain.ValidatePermissions(perms); err != nil {
		return err
	}
	if !domain.HoldsAll(actor.Permissions, perms) {
		return domain.ErrPermissionNotHeld
	}
	return nil
}
