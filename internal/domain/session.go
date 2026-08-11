package domain

import (
	"errors"
	"time"
)

// Session is one refresh token. The token itself is never stored — only its
// SHA-256 — so a database leak does not hand over live sessions.
//
// FamilyID ties together every rotation descended from one login. Presenting a
// refresh token that was already spent means the token leaked and two parties
// now hold it, so the entire family is destroyed rather than just that link.
type Session struct {
	ID       string
	UserID   string
	FamilyID string

	// UsedAt is set the moment the token is exchanged. A non-nil value on a
	// presented token is the reuse signal.
	UsedAt    *time.Time
	ExpiresAt time.Time

	IP        string
	UserAgent string
	CreatedAt time.Time
}

func (s Session) Spent() bool { return s.UsedAt != nil }

func (s Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// Live reports whether the session can still be exchanged.
func (s Session) Live(now time.Time) bool { return !s.Spent() && !s.Expired(now) }

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")

	// ErrRefreshReused means a spent token was presented again; the caller has
	// already destroyed the family by the time this surfaces.
	ErrRefreshReused = errors.New("refresh token reuse detected")
)
