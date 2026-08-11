package authclient

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Gin middleware for consuming services.
//
//	mw, _ := authclient.New(authclient.Config{
//	    JWKSURL:  "https://auth.example.com/.well-known/jwks.json",
//	    Issuer:   "goauth",
//	    Audience: "my-app",
//	})
//	r.Use(mw.Require())
//	// in a handler: authclient.UserID(c)

const (
	ctxClaims = "authclient.claims"
)

// Require rejects unauthenticated requests.
func (v *Verifier) Require() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := v.Verify(c.Request.Context(), bearerToken(c.Request.Header.Get("Authorization")))
		if err != nil {
			status := http.StatusUnauthorized
			msg := "invalid token"
			switch {
			case errors.Is(err, ErrMissingToken):
				msg = "missing bearer token"
			case errors.Is(err, ErrExpired):
				msg = "token expired"
			}
			c.AbortWithStatusJSON(status, gin.H{"error": msg})
			return
		}

		c.Set(ctxClaims, claims)
		c.Next()
	}
}

// Optional attaches claims when a valid token is present and otherwise lets the
// request through unauthenticated. For endpoints that serve both.
func (v *Verifier) Optional() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := bearerToken(c.Request.Header.Get("Authorization"))
		if raw != "" {
			if claims, err := v.Verify(c.Request.Context(), raw); err == nil {
				c.Set(ctxClaims, claims)
			}
		}
		c.Next()
	}
}

// FromContext returns the verified claims, if any.
func FromContext(c *gin.Context) (Claims, bool) {
	v, ok := c.Get(ctxClaims)
	if !ok {
		return Claims{}, false
	}
	claims, ok := v.(Claims)
	return claims, ok
}

// UserID is the value a consuming service stores in its own tables.
func UserID(c *gin.Context) string {
	claims, _ := FromContext(c)
	return claims.UserID
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}
