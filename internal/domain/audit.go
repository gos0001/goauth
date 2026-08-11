package domain

import "time"

// AuditEntry records who changed what. The admin surface mutates other people's
// accounts, so every such change leaves a row — without it, "who blocked this
// user" has no answer.
type AuditEntry struct {
	ID           int64
	Actor        string
	Action       string
	TargetUserID string
	IP           string
	Meta         map[string]any
	CreatedAt    time.Time
}

// Actor prefixes. A human admin is identifiable; a machine holding the static
// admin token is not, which is exactly why the token is for machines only.
const (
	ActorSystem     = "system"
	ActorAdminToken = "admin_token"
	ActorUserPrefix = "user:"
)

func ActorUser(id string) string { return ActorUserPrefix + id }

// Audit actions.
const (
	ActionUserCreated        = "user.created"
	ActionUserUpdated        = "user.updated"
	ActionUserDeleted        = "user.deleted"
	ActionUserLogin          = "user.login"
	ActionUserLoginFailed    = "user.login_failed"
	ActionUserRegistered     = "user.registered"
	ActionPasswordChanged    = "user.password_changed"
	ActionPasswordSetByAdmin = "user.password_set_by_admin"
	ActionAdminGranted       = "user.admin_granted"
	ActionAdminRevoked       = "user.admin_revoked"
	ActionUserBlocked        = "user.blocked"
	ActionUserUnblocked      = "user.unblocked"

	ActionTokenRefreshed  = "session.refreshed"
	ActionSessionRevoked  = "session.revoked"
	ActionSessionsRevoked = "session.revoked_all"
	ActionRefreshReuse    = "session.reuse_detected"
)
