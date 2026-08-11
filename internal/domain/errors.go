// Package domain holds pure models and the sentinel errors they raise.
// No struct tags, no adapter imports, no transport concerns.
package domain

import "errors"

// Generic sentinel errors. Adapters map storage failures onto these; handlers
// map these onto HTTP status codes with errors.Is. Entity-specific errors live
// next to their entity — see user.go, session.go and audit.go.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrForbidden     = errors.New("forbidden")
)
