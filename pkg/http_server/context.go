package httpserver

import (
	"time"

	"github.com/gin-gonic/gin"
)

// Request-scoped values that middleware resolves once and handlers read.
// Kept here rather than in a middleware package so that handlers — which live
// in use case packages — never have to import transport wiring.

const (
	ctxClientIP  = "goauth.client_ip"
	ctxUserID    = "goauth.user_id"
	ctxSessionID = "goauth.session_id"
	ctxRole      = "goauth.role"
	ctxAuthTime  = "goauth.auth_time"
	ctxActor     = "goauth.actor"
)

func SetClientIP(c *gin.Context, ip string) { c.Set(ctxClientIP, ip) }

func ClientIP(c *gin.Context) string { return str(c, ctxClientIP) }

func SetIdentity(c *gin.Context, userID, sessionID, role string, authTime time.Time) {
	c.Set(ctxUserID, userID)
	c.Set(ctxSessionID, sessionID)
	c.Set(ctxRole, role)
	c.Set(ctxAuthTime, authTime)
}

func UserID(c *gin.Context) string { return str(c, ctxUserID) }

func SessionID(c *gin.Context) string { return str(c, ctxSessionID) }

// Role is the token's role claim: a hint for the frontend, never an
// authorisation decision — the admin middleware re-reads the role from the
// database on every request.
func Role(c *gin.Context) string { return str(c, ctxRole) }

func AuthTime(c *gin.Context) time.Time {
	v, ok := c.Get(ctxAuthTime)
	if !ok {
		return time.Time{}
	}
	t, _ := v.(time.Time)
	return t
}

// SetActor records who is performing an admin action, for the audit trail:
// an identified user on the public port, or the shared machine token on the
// private one.
func SetActor(c *gin.Context, actor string) { c.Set(ctxActor, actor) }

func Actor(c *gin.Context) string { return str(c, ctxActor) }

func str(c *gin.Context, key string) string {
	v, ok := c.Get(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
