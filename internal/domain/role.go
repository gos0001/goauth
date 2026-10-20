package domain

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Permission is a scope on goauth's own admin surface. The set is fixed by the
// code that checks it — middleware keys on these values, so a permission the
// binary does not recognise cannot be enforced no matter what the database
// says. Anything product-specific (subscriptions, entitlements) belongs to the
// consuming application, not here.
type Permission string

const (
	PermUsersRead      Permission = "users:read"
	PermUsersCreate    Permission = "users:create"
	PermUsersUpdate    Permission = "users:update"
	PermUsersDelete    Permission = "users:delete"
	PermPasswordSet    Permission = "password:set"
	PermSessionsRead   Permission = "sessions:read"
	PermSessionsRevoke Permission = "sessions:revoke"
	PermAuditRead      Permission = "audit:read"
	PermRolesRead      Permission = "roles:read"
	PermRolesManage    Permission = "roles:manage"
)

// knownPermissions is the vocabulary the whole service agrees on. Role CRUD
// validates against it, so a typo in a granted permission fails the request
// instead of silently producing a right nothing checks.
var knownPermissions = map[Permission]struct{}{
	PermUsersRead:      {},
	PermUsersCreate:    {},
	PermUsersUpdate:    {},
	PermUsersDelete:    {},
	PermPasswordSet:    {},
	PermSessionsRead:   {},
	PermSessionsRevoke: {},
	PermAuditRead:      {},
	PermRolesRead:      {},
	PermRolesManage:    {},
}

// KnownPermission reports whether p is part of the fixed vocabulary.
func KnownPermission(p Permission) bool {
	_, ok := knownPermissions[p]
	return ok
}

// AllPermissions lists the vocabulary in its declaration order. The machine
// actor (the static token on the private listener) is modelled as holding all
// of them, so the guard logic has one shape instead of two.
func AllPermissions() []Permission {
	return []Permission{
		PermUsersRead,
		PermUsersCreate,
		PermUsersUpdate,
		PermUsersDelete,
		PermPasswordSet,
		PermSessionsRead,
		PermSessionsRevoke,
		PermAuditRead,
		PermRolesRead,
		PermRolesManage,
	}
}

// ValidatePermissions rejects any name outside the vocabulary. Empty input is
// fine: a role with no permissions is a valid way to say "rank only".
func ValidatePermissions(perms []Permission) error {
	for _, p := range perms {
		if !KnownPermission(p) {
			return fmt.Errorf("%w: unknown permission %q", ErrPermissionUnknown, p)
		}
	}
	return nil
}

// Role names the administrative tiers goauth ships with. Custom roles created
// through the API are first-class rows beside them; these constants are only
// the floor the service needs to boot — 'user' because ga_users.role defaults
// to it, 'superadmin' because someone has to outrank everyone else.
const (
	RoleUser       = "user"
	RoleManager    = "manager"
	RoleAdmin      = "admin"
	RoleSuperAdmin = "superadmin"
)

// Ranks of the built-in roles. Custom roles may take any rank between 1 and
// 99; 0 and 100 are the two ends and stay reserved so "lower than everyone"
// and "higher than everyone" remain speakable.
const (
	RankUser       = 0
	RankManager    = 10
	RankAdmin      = 50
	RankSuperAdmin = 100
)

// Role is one row of the administration hierarchy: a name, a rank, and the
// permissions every holder of the name carries.
type Role struct {
	Name        string
	Rank        int
	IsSystem    bool
	Permissions []Permission
	CreatedAt   time.Time
}

// Has reports whether the role carries a permission.
func (r Role) Has(p Permission) bool {
	for _, own := range r.Permissions {
		if own == p {
			return true
		}
	}
	return false
}

// CanManage is the one rule the whole hierarchy reduces to: an actor may act
// on a target only from strictly above. Equal rank is deliberately on the
// wrong side of the line — two admins must not be able to delete each other,
// because nothing an admin holds would then be safe from another admin.
//
// The single exception is the top: a superadmin may act on other superadmins,
// because somebody has to be able to demote a redundant one, and the
// last-superadmin guard is what keeps that from ever bricking the install.
func CanManage(actorRank, targetRank int) bool {
	if actorRank >= RankSuperAdmin {
		return true
	}
	return actorRank > targetRank
}

// MayAssign governs both handing a role to a user and creating or editing a
// role: only strictly below the actor's own rank, with the same top-of-the-
// ladder exception as CanManage — otherwise nobody could ever appoint a
// second superadmin. It is CanManage applied to the role itself rather than
// to a user holding it — the point is the same, that nobody can manufacture
// a peer or a superior.
func MayAssign(actorRank, roleRank int) bool { return CanManage(actorRank, roleRank) }

// ValidCustomRank keeps 0 and 100 out of the API's reach. The two ends of the
// ladder belong to the built-in roles: "lower than everyone" and "higher than
// everyone" must stay speakable no matter what an operator creates.
func ValidCustomRank(rank int) bool { return rank >= 1 && rank <= 99 }

// roleNameRe keeps role names usable in URLs and logs: lowercase letters,
// digits and dashes.
var roleNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// ValidRoleName is the shared shape for a role's name, whether it arrives from
// the config file or the admin API.
func ValidRoleName(name string) bool { return roleNameRe.MatchString(name) }

// HoldsAll is the Kubernetes rule: you cannot grant a permission you do not
// hold yourself. Without it, roles:manage alone is full escalation — build a
// role with every permission and step into it.
func HoldsAll(actorPerms, granted []Permission) bool {
	for _, g := range granted {
		found := false
		for _, a := range actorPerms {
			if a == g {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// DefaultRoles is the set seeded at every startup, existing rows left alone.
// They are is_system because a deployment must not be able to delete its own
// floor: 'user' is the DEFAULT of ga_users.role, and 'superadmin' is the only
// role permitted to outrank 'admin'.
func DefaultRoles() []Role {
	return []Role{
		{
			Name:     RoleUser,
			Rank:     RankUser,
			IsSystem: true,
		},
		{
			Name:     RoleManager,
			Rank:     RankManager,
			IsSystem: true,
			Permissions: []Permission{
				PermUsersRead,
				PermSessionsRead,
			},
		},
		{
			Name:     RoleAdmin,
			Rank:     RankAdmin,
			IsSystem: true,
			Permissions: []Permission{
				PermUsersRead,
				PermUsersCreate,
				PermUsersUpdate,
				PermUsersDelete,
				PermPasswordSet,
				PermSessionsRead,
				PermSessionsRevoke,
				PermAuditRead,
				PermRolesRead,
			},
		},
		{
			Name:     RoleSuperAdmin,
			Rank:     RankSuperAdmin,
			IsSystem: true,
			Permissions: []Permission{
				PermUsersRead,
				PermUsersCreate,
				PermUsersUpdate,
				PermUsersDelete,
				PermPasswordSet,
				PermSessionsRead,
				PermSessionsRevoke,
				PermAuditRead,
				PermRolesRead,
				PermRolesManage,
			},
		},
	}
}

// Role errors. Rank discipline is enforced in use cases from these sentinels;
// the database's UNIQUE on rank is the backstop, not the check.
var (
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("role already exists")
	ErrRoleInUse         = errors.New("role is still assigned to users")
	ErrRoleProtected     = errors.New("system role cannot be modified or deleted")
	ErrRankTaken         = errors.New("rank is already taken by another role")
	ErrInsufficientRank  = errors.New("actor rank is not above target rank")
	ErrPermissionUnknown = errors.New("unknown permission")
	ErrPermissionNotHeld = errors.New("cannot grant a permission the actor does not hold")
)
