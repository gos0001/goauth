// Package roleguard centralises the rank discipline every role-touching use
// case needs: who may act on which role, and which permissions may be placed
// into one. One place, because the rules must not drift between create,
// update and delete.
package roleguard

import (
	"context"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
)

type Postgres interface {
	ActorRole(ctx context.Context, userID string) (domain.Role, error)
}

type Guard struct {
	postgres Postgres
	cfg      Config
}

// New takes the concrete adapter: the guard is the one service every admin
// use case leans on, and an interface parameter here would force a wire.Bind
// into every consumer's set. cfg carries the ownership mode; ModeOff leaves
// every check exactly where it was.
func New(pg *postgresadapter.Adapter, cfg Config) *Guard {
	return &Guard{postgres: pg, cfg: cfg}
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

// Delegated reports whether delegated ownership is switched on for this
// deployment. Every ownership check in the service is gated on it, so "off"
// keeps the pre-ownership behaviour byte for byte.
func (g *Guard) Delegated() bool {
	return g.cfg.Ownership == ModeDelegated
}

// CanActOnUser answers whether the actor may manage the target user. Rank is
// always domain.CanManage — strictly above, so an equal is out of reach both
// ways. In delegated mode a non-superadmin is additionally confined to users
// they created, unless they hold users:manage_all. The machine caller is
// modelled as a superadmin by Actor, so ownership never binds it.
func (g *Guard) CanActOnUser(actor domain.Role, actorID string, target domain.User, targetRole domain.Role) error {
	if !domain.CanManage(actor.Rank, targetRole.Rank) {
		return domain.ErrInsufficientRank
	}
	if g.Delegated() && actor.Rank < domain.RankSuperAdmin {
		if target.CreatedBy != actorID && !actor.Has(domain.PermUsersManageAll) {
			return domain.ErrUserNotOwned
		}
	}
	return nil
}

// CanSeeUser is CanActOnUser's read-side twin, with two differences: the
// exception permission is users:read_all, and every way out of scope is
// ErrUserNotFound rather than ErrUserNotOwned — a 404 hides equals and
// superiors instead of confirming they exist.
func (g *Guard) CanSeeUser(actor domain.Role, actorID string, target domain.User, targetRole domain.Role) error {
	if !domain.CanManage(actor.Rank, targetRole.Rank) {
		return domain.ErrUserNotFound
	}
	if g.Delegated() && actor.Rank < domain.RankSuperAdmin {
		if target.CreatedBy != actorID && !actor.Has(domain.PermUsersReadAll) {
			return domain.ErrUserNotFound
		}
	}
	return nil
}

// UserVisibility turns the actor into list/count filters. apply false means
// no filtering at all: mode off, or the actor at superadmin rank (the machine
// caller included). Otherwise minRank keeps users strictly below the actor
// and owner keeps users the actor created — unless they hold users:read_all,
// which drops the owner filter and leaves the rank ceiling.
func (g *Guard) UserVisibility(actor domain.Role, actorID string) (apply bool, minRank int, owner string) {
	if !g.Delegated() || actor.Rank >= domain.RankSuperAdmin {
		return false, 0, ""
	}
	if actor.Has(domain.PermUsersReadAll) {
		return true, actor.Rank, ""
	}
	return true, actor.Rank, actorID
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
