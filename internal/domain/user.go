package domain

import (
	"errors"
	"time"
)

// UserStatus mirrors the ga_users.status check constraint.
type UserStatus string

const (
	StatusActive  UserStatus = "active"
	StatusBlocked UserStatus = "blocked"
	// StatusDeleted is a soft delete: the row survives so that user_id values
	// held by other services never become dangling references.
	StatusDeleted UserStatus = "deleted"
)

// User is the whole of goauth's identity model. Anything that means something
// only inside a consuming product — subscriptions, product roles, entitlements —
// belongs to that product's own database, keyed by ID.
//
// Role is goauth's own administration tier (see role.go): it governs who may
// manage whom on this service's admin surface and nothing else. One role per
// user, deliberately — a set of roles would need a merge rule for ranks, and
// "the highest of them" is an escalation waiting to happen.
type User struct {
	ID string

	// Username and Email are normalised (trimmed, lowercased) identifiers.
	// An empty string means the identifier is absent; at least one is present.
	Username string
	Email    string

	PasswordHash string
	Role         string
	Status       UserStatus

	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsSuperAdmin reports whether the account sits at the top of the
// administration hierarchy: the only rank permitted to manage admins and to
// grant anything. Used by the last-superadmin guard among others.
func (u User) IsSuperAdmin() bool { return u.Role == RoleSuperAdmin }

// Active reports whether the account may authenticate at all.
func (u User) Active() bool { return u.Status == StatusActive }

// Identifier returns the value a human would type to log in.
func (u User) Identifier() string {
	if u.Username != "" {
		return u.Username
	}
	return u.Email
}

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrInvalidCredentials is returned for both an unknown identifier and a
	// wrong password. Distinguishing them would disclose which accounts exist.
	ErrInvalidCredentials = errors.New("invalid credentials")

	ErrUserBlocked = errors.New("user is blocked")
	ErrUserDeleted = errors.New("user is deleted")

	ErrPasswordTooWeak    = errors.New("password too weak")
	ErrInvalidIdentifier  = errors.New("invalid identifier")
	ErrNoIdentifier       = errors.New("username or email is required")
	ErrRegistrationClosed = errors.New("registration is closed")

	// ErrLastAdmin and ErrSelfDemote keep an installation from being locked out
	// of its own admin surface, which is only repairable with manual SQL.
	ErrLastAdmin  = errors.New("cannot remove the last active admin")
	ErrSelfDemote = errors.New("cannot remove your own admin rights")
)
