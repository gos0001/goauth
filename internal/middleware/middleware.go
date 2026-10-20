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

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/pkg/authcookie"
	httpserver "github.com/gos0001/goauth/v2/pkg/http_server"
	"github.com/gos0001/goauth/v2/pkg/ratelimit"
	"github.com/gos0001/goauth/v2/pkg/realip"
	"github.com/gos0001/goauth/v2/pkg/token"
)

type Middleware struct {
	resolver *realip.Resolver
	limiter  *ratelimit.Limiter
	signer   *token.Signer
	postgres *postgresadapter.Adapter
	cookies  *authcookie.Cookies
	logger   *zap.SugaredLogger
	cfg      Config
}

func New(
	resolver *realip.Resolver,
	limiter *ratelimit.Limiter,
	signer *token.Signer,
	pg *postgresadapter.Adapter,
	cookies *authcookie.Cookies,
	logger *zap.SugaredLogger,
	cfg Config,
) *Middleware {
	return &Middleware{
		resolver: resolver,
		limiter:  limiter,
		signer:   signer,
		postgres: pg,
		cookies:  cookies,
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
		raw, ok := m.credential(c)
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

		httpserver.SetIdentity(c, claims.Subject, claims.SessionID, claims.Role, time.Unix(claims.AuthTime, 0))
		httpserver.SetActor(c, domain.ActorUser(claims.Subject))
		c.Next()
	}
}

// AuthSilent verifies the bearer token for the admin surface, answering 404
// rather than 401 so that an unauthorised caller cannot confirm /admin exists
// and merely needs credentials. Paired with the permission guard, a missing token, a bad
// token and a valid token without rights are all indistinguishable from a route
// that was never registered.
//
// One deliberate exception: an **expired** token gets a 401.
//
// Without it there is no signal that a token needs refreshing, and since access
// tokens live minutes, a panel simply starts answering "not found" and cannot
// recover — its refresh flow keys on 401. Saying "expired" discloses nothing:
// the token is one this service issued and signed, so its holder already had a
// session and learns nothing new about themselves. What stays hidden is who is
// holds which permission, which is the scope guard's job — a valid token
// without the permission still gets 404.
func (m *Middleware) AuthSilent() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := m.credential(c)
		if !ok {
			// Nothing presented, so nothing can have expired: this is the pure
			// discovery case and stays silent.
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		claims, err := m.signer.Verify(raw)
		if err != nil {
			if errors.Is(err, token.ErrExpired) {
				// Same status and body as /auth/*, so a client needs one rule
				// rather than one per surface.
				httpserver.Unauthorized(c, "token expired")
				c.Abort()
				return
			}
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		httpserver.SetIdentity(c, claims.Subject, claims.SessionID, claims.Role, time.Unix(claims.AuthTime, 0))
		httpserver.SetActor(c, domain.ActorUser(claims.Subject))
		c.Next()
	}
}

// RequirePermission authorises the panel's admin calls by scope. Domain
// permissions are strings at this boundary so the controllers that wire routes
// never import the domain package — routing stays literals all the way down.
func (m *Middleware) RequireScope(scope string) gin.HandlerFunc {
	return m.RequirePermission(domain.Permission(scope))
}

// RequirePermission authorises the panel's admin calls by scope.
//
// It re-reads the actor's role — rank, permissions, and that the account is
// still active — from the database rather than trusting the token's role
// claim. An access token cannot be revoked before it expires, so a claim-based
// check would leave a demoted or blocked administrator in full power for the
// remainder of its lifetime. goauth owns this database, so the read is local
// and costs nothing worth saving.
//
// Failures answer 404 rather than 403: an unauthorised caller learns nothing
// about whether this surface exists.
func (m *Middleware) RequirePermission(p domain.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := httpserver.UserID(c)
		if userID == "" {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		role, err := m.postgres.ActorRole(c.Request.Context(), userID)
		if err != nil {
			if !errors.Is(err, domain.ErrUserNotFound) {
				m.logger.Errorw("permission guard lookup failed", "user_id", userID, "error", err)
			}
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if !role.Has(p) {
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

// credential resolves the presented access token: the Authorization header
// first, and only when the cookie channel is on, the access cookie as a
// fallback. The header keeps priority so an explicit credential always
// overrides whatever the browser attached — and AdminToken deliberately stays
// on bearer() alone, since the static admin token must never travel in a
// cookie a browser could hold.
func (m *Middleware) credential(c *gin.Context) (string, bool) {
	if raw, ok := bearer(c); ok {
		return raw, true
	}
	if m.cookies == nil || !m.cookies.Enabled() {
		return "", false
	}
	return m.cookies.AccessFromRequest(c.Request)
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
