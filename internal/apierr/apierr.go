// Package apierr maps domain errors onto HTTP responses.
//
// The architecture contract puts this mapping in the handler, and it stays there —
// a handler with an error the generic table gets wrong still branches on it
// first and calls Write only as the fallback. What this package removes is the
// twenty-times-repeated tail of that switch, where every handler in the service
// agrees that ErrUserNotFound is a 404.
package apierr

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/domain"
	httpserver "github.com/gos0001/goauth/pkg/http_server"
)

// Write maps err onto a response. Unrecognised errors are logged with their
// detail and answered with a flat 500 — the client never sees err.Error().
func Write(c *gin.Context, logger *zap.SugaredLogger, op string, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound), errors.Is(err, domain.ErrNotFound):
		httpserver.NotFound(c, "not found")

	case errors.Is(err, domain.ErrUserAlreadyExists), errors.Is(err, domain.ErrAlreadyExists):
		httpserver.Conflict(c, "already exists")

	// Credentials, missing sessions and expired sessions collapse to one
	// message on purpose: distinguishing them tells an attacker which half of
	// the guess was right.
	case errors.Is(err, domain.ErrInvalidCredentials):
		httpserver.Unauthorized(c, "invalid credentials")
	case errors.Is(err, domain.ErrSessionNotFound), errors.Is(err, domain.ErrSessionExpired):
		httpserver.Unauthorized(c, "invalid or expired session")

	case errors.Is(err, domain.ErrRefreshReused):
		// The whole family is already gone; say so plainly so a client with a
		// stale token stops retrying and sends the user back to login.
		httpserver.Unauthorized(c, "refresh token reuse detected, all sessions revoked")

	case errors.Is(err, domain.ErrUserBlocked):
		httpserver.Forbidden(c, "account is blocked")
	case errors.Is(err, domain.ErrUserDeleted):
		httpserver.Forbidden(c, "account is deleted")
	case errors.Is(err, domain.ErrMustChangePassword):
		httpserver.Forbidden(c, "password change required")

	case errors.Is(err, domain.ErrLastAdmin):
		httpserver.Conflict(c, "cannot remove the last active admin")
	case errors.Is(err, domain.ErrSelfDemote):
		httpserver.Conflict(c, "cannot remove your own admin rights")

	case errors.Is(err, domain.ErrPasswordTooWeak):
		httpserver.BadRequest(c, "password is too short")
	case errors.Is(err, domain.ErrInvalidIdentifier):
		httpserver.BadRequest(c, "invalid username or email")
	case errors.Is(err, domain.ErrNoIdentifier):
		httpserver.BadRequest(c, "username or email is required")
	case errors.Is(err, domain.ErrInvalidInput):
		httpserver.BadRequest(c, "invalid request")

	case errors.Is(err, domain.ErrRegistrationClosed), errors.Is(err, domain.ErrForbidden):
		// 404 rather than 403: a disabled feature should not advertise that it
		// exists and is merely switched off.
		httpserver.NotFound(c, "not found")

	default:
		logger.Errorw(op+" failed", "error", err)
		httpserver.InternalServerError(c, "internal server error")
	}
}
