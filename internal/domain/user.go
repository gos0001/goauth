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
// IsAdmin governs goauth's own /admin endpoints and nothing else. It is a bool
// rather than a role list on purpose: the moment it becomes a set of
// product-scoped roles, this service needs to know which product a role belongs
// to, and that is the realm concept it exists to avoid.
type User struct {
	ID string

	// Username and Email are normalised (trimmed, lowercased) identifiers.
	// An empty string means the identifier is absent; at least one is present.
	Username string
	Email    string

	PasswordHash       string
	IsAdmin            bool
	Status             UserStatus
	MustChangePassword bool

	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

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

	ErrUserBlocked        = errors.New("user is blocked")
	ErrUserDeleted        = errors.New("user is deleted")
	ErrMustChangePassword = errors.New("password change required")

	ErrPasswordTooWeak    = errors.New("password too weak")
	ErrInvalidIdentifier  = errors.New("invalid identifier")
	ErrNoIdentifier       = errors.New("username or email is required")
	ErrRegistrationClosed = errors.New("registration is closed")

	// ErrLastAdmin and ErrSelfDemote keep an installation from being locked out
	// of its own admin surface, which is only repairable with manual SQL.
	ErrLastAdmin  = errors.New("cannot remove the last active admin")
	ErrSelfDemote = errors.New("cannot remove your own admin rights")
)
