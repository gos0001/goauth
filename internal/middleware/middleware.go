// Package middleware holds the transport-level guards: client IP resolution,
// rate limiting, and the two ways of proving admin rights.
//
// It sits beside the controller rather than inside it so that
// controller/http_v1 stays routing-only, and outside pkg/ because these guards
// read domain state.
package middleware

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	httpserver "github.com/gos0001/goauth/pkg/http_server"
	"github.com/gos0001/goauth/pkg/ratelimit"
	"github.com/gos0001/goauth/pkg/realip"
	"github.com/gos0001/goauth/pkg/token"
)

type Middleware struct {
	resolver *realip.Resolver
	limiter  *ratelimit.Limiter
	signer   *token.Signer
	postgres *postgresadapter.Adapter
	logger   *zap.SugaredLogger
	cfg      Config
}

func New(
	resolver *realip.Resolver,
	limiter *ratelimit.Limiter,
	signer *token.Signer,
	pg *postgresadapter.Adapter,
	logger *zap.SugaredLogger,
	cfg Config,
) *Middleware {
	return &Middleware{
		resolver: resolver,
		limiter:  limiter,
		signer:   signer,
		postgres: pg,
		logger:   logger,
		cfg:      cfg,
	}
}

// RealIP resolves the client address once per request. Everything downstream —
// rate limiting, session records, audit rows — reads the resolved value rather
// than re-deriving it, so they cannot disagree.
func (m *Middleware) RealIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := m.resolver.ClientIP(c.Request)
		if ip.IsValid() {
			httpserver.SetClientIP(c, ip.String())
		}
		c.Set(ctxIPBucket, realip.Bucket(ip))
		c.Next()
	}
}

const ctxIPBucket = "goauth.ip_bucket"

// RateLimit throttles by IP bucket.
//
// On a Redis failure the configured FailClosed decides: for the password
// endpoints it must reject, because letting every attempt through while the
// counter store is down is exactly the window a brute-forcer wants.
func (m *Middleware) RateLimit(rule ratelimit.Rule, name string) gin.HandlerFunc {
	failClosed := m.limiter.Config().FailClosed

	return func(c *gin.Context) {
		bucket, _ := c.Get(ctxIPBucket)
		key := name + ":ip:" + toString(bucket)

		res, err := m.limiter.Allow(c.Request.Context(), key, rule)
		if err != nil {
			m.logger.Errorw("rate limiter unavailable", "endpoint", name, "error", err)
			if failClosed {
				httpserver.ServiceUnavailable(c, "service temporarily unavailable")
				c.Abort()
				return
			}
			c.Next()
			return
		}

		if !res.Allowed {
			httpserver.TooManyRequests(c, "too many requests")
			c.Abort()
			return
		}

		c.Next()
	}
}

// Auth verifies the bearer token and publishes the caller's identity.
func (m *Middleware) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := bearer(c)
		if !ok {
			httpserver.Unauthorized(c, "missing bearer token")
			c.Abort()
			return
		}

		claims, err := m.signer.Verify(raw)
		if err != nil {
			switch {
			case errors.Is(err, token.ErrExpired):
				httpserver.Unauthorized(c, "token expired")
			default:
				httpserver.Unauthorized(c, "invalid token")
			}
			c.Abort()
			return
		}

		httpserver.SetIdentity(c, claims.Subject, claims.SessionID, claims.Admin, time.Unix(claims.AuthTime, 0))
		httpserver.SetActor(c, domain.ActorUser(claims.Subject))
		c.Next()
	}
}

// AuthSilent verifies the bearer token but answers 404 on every failure instead
// of 401.
//
// It guards the admin surface on the public listener, where a 401 would confirm
// that /admin exists and merely needs credentials. Paired with AdminJWT, every
// rejection — no token, bad token, valid token without rights — is
// indistinguishable from a route that was never registered.
func (m *Middleware) AuthSilent() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := bearer(c)
		if !ok {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		claims, err := m.signer.Verify(raw)
		if err != nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		httpserver.SetIdentity(c, claims.Subject, claims.SessionID, claims.Admin, time.Unix(claims.AuthTime, 0))
		httpserver.SetActor(c, domain.ActorUser(claims.Subject))
		c.Next()
	}
}

// AdminJWT authorises the panel's own admin calls.
//
// It re-reads is_admin and status from the database rather than trusting the
// token's adm claim. An access token cannot be revoked before it expires, so a
// claim-based check would leave a demoted or blocked admin in full power for the
// remainder of its lifetime. goauth owns this database, so the read is local and
// costs nothing worth saving.
//
// Failures answer 404 rather than 403: an unauthorised caller learns nothing
// about whether this surface exists.
func (m *Middleware) AdminJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := httpserver.UserID(c)
		if userID == "" {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		user, err := m.postgres.GetUserByID(c.Request.Context(), userID)
		if err != nil {
			if !errors.Is(err, domain.ErrUserNotFound) {
				m.logger.Errorw("admin guard lookup failed", "user_id", userID, "error", err)
			}
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if !user.IsAdmin || !user.Active() {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		c.Next()
	}
}

// AdminToken authorises machine callers on the private listener.
//
// The comparison is constant-time: a plain == returns as soon as two bytes
// differ, and that timing difference leaks the length of the matching prefix,
// which is enough to recover the token byte by byte.
func (m *Middleware) AdminToken() gin.HandlerFunc {
	want := []byte(m.cfg.AdminToken)

	return func(c *gin.Context) {
		raw, ok := bearer(c)
		if !ok {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if subtle.ConstantTimeCompare([]byte(raw), want) != 1 {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		httpserver.SetActor(c, domain.ActorAdminToken)
		c.Next()
	}
}

// RequireRecentAuth is sudo mode: destructive admin operations demand that the
// password was presented recently, not merely that a valid session exists. It
// is what stops a hijacked admin tab from deleting accounts.
//
// Machine callers are exempt: they hold no session and re-authenticate on every
// request by presenting the token itself.
func (m *Middleware) RequireRecentAuth() gin.HandlerFunc {
	window := m.cfg.ReauthWindow

	return func(c *gin.Context) {
		if httpserver.UserID(c) == "" {
			c.Next() // machine caller
			return
		}

		authTime := httpserver.AuthTime(c)
		if authTime.IsZero() || time.Since(authTime) > window {
			httpserver.Forbidden(c, "reauthentication required")
			c.Abort()
			return
		}

		c.Next()
	}
}

func bearer(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return "", false
	}
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	value := strings.TrimSpace(header[len(prefix):])
	return value, value != ""
}

func toString(v any) string {
	s, _ := v.(string)
	if s == "" {
		return "unknown"
	}
	return s
}
