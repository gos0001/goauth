package domain

import "time"

// OutboxEvent is an account lifecycle change, written in the same transaction as
// the change itself and delivered to a webhook afterwards.
//
// Only lifecycle events are emitted — creation, modification, deletion. Login
// and refresh are deliberately absent: they happen orders of magnitude more
// often and carry nothing a consumer needs to keep its own copy of a user
// correct.
type OutboxEvent struct {
	ID      string
	Event   string
	Payload map[string]any

	// RawPayload is the bytes as stored. Delivery signs and sends these rather
	// than re-marshalling Payload, so the signature covers exactly what the
	// receiver reads and map ordering cannot change the body between attempts.
	RawPayload []byte

	Attempts  int
	CreatedAt time.Time
}

// Event names. Stable strings — a receiver switches on them, so renaming one
// breaks every consumer.
const (
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserBlocked         = "user.blocked"
	EventUserUnblocked       = "user.unblocked"
	EventUserDeleted         = "user.deleted"
	EventUserPasswordChanged = "user.password_changed"
	EventAdminGranted        = "user.admin_granted"
	EventAdminRevoked        = "user.admin_revoked"
)

// NewUserEvent builds the payload every consumer needs to maintain its own copy
// of a user: who it is, how to reach them, and whether they may sign in.
//
// The password hash is never included. Neither is anything a consumer could not
// already read from the admin API.
func NewUserEvent(event string, u User) OutboxEvent {
	return OutboxEvent{
		Event: event,
		Payload: map[string]any{
			"user_id":    u.ID,
			"username":   u.Username,
			"email":      u.Email,
			"status":     string(u.Status),
			"is_admin":   u.IsAdmin,
			"created_at": u.CreatedAt,
			"updated_at": u.UpdatedAt,
		},
	}
}
