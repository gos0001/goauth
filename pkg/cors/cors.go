// Package cors answers cross-origin requests from browser applications.
//
// Worth being clear about what this is: CORS is a *browser* policy. It decides
// whether JavaScript may read a response, and stops nothing from curl, a script
// or another server. ALLOW_DOMAINS is therefore not an access control —
// authentication and rate limiting are. It exists so a panel or SPA on another
// origin can talk to goauth at all.
//
// Zero domain imports.
package cors

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// Methods and request headers the API actually uses. Kept explicit rather than
// reflecting whatever a preflight asks for, which would make the allowlist
// meaningless in the other direction.
const (
	allowMethods = "GET, POST, PATCH, DELETE, OPTIONS"
	allowHeaders = "Authorization, Content-Type"
)

type Middleware struct {
	rules  []rule
	maxAge string
	any    bool
}

func New(cfg Config) (*Middleware, error) {
	rules, allowAny, err := parse(cfg.AllowDomains)
	if err != nil {
		return nil, err
	}

	return &Middleware{
		rules:  rules,
		any:    allowAny,
		maxAge: strconv.Itoa(int(cfg.MaxAge.Seconds())),
	}, nil
}

// Enabled reports whether any origin is configured. With none, no CORS headers
// are sent at all and browsers apply their default, which is to block.
func (m *Middleware) Enabled() bool { return m.any || len(m.rules) > 0 }

func (m *Middleware) Handler() gin.HandlerFunc {
	enabled := m.Enabled()

	return func(c *gin.Context) {
		if !enabled {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next() // not a browser cross-origin request
			return
		}

		allowed, ok := m.allow(origin)
		if !ok {
			// Deliberately no headers: an unmatched origin is refused by the
			// browser's own default. Answering the preflight anyway would tell
			// a caller which origins exist.
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}

		c.Header("Access-Control-Allow-Origin", allowed)
		if allowed != "*" {
			// Without this a shared cache can serve one origin's response, and
			// its Allow-Origin header, to a different origin.
			c.Header("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.Header("Access-Control-Allow-Methods", allowMethods)
			c.Header("Access-Control-Allow-Headers", allowHeaders)
			c.Header("Access-Control-Max-Age", m.maxAge)
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// allow returns the value to echo back, never the raw Origin header — echoing
// whatever arrives is what turns an allowlist into decoration.
func (m *Middleware) allow(origin string) (string, bool) {
	if m.any {
		return "*", true
	}

	normalized := strings.ToLower(strings.TrimSuffix(origin, "/"))
	for _, r := range m.rules {
		if r.matches(normalized) {
			return origin, true
		}
	}
	return "", false
}

type rule struct {
	// exact is the full origin, lowercased: "https://app.example.com".
	exact string

	// scheme and suffix hold a wildcard rule: scheme "https" and suffix
	// ".example.com".
	scheme string
	suffix string
}

func (r rule) matches(origin string) bool {
	if r.exact != "" {
		return origin == r.exact
	}

	host, ok := strings.CutPrefix(origin, r.scheme+"://")
	if !ok {
		return false
	}

	// The suffix carries its leading dot, so "evilexample.com" cannot match a
	// rule for "*.example.com", and the bare domain does not match either.
	return strings.HasSuffix(host, r.suffix) && len(host) > len(r.suffix)
}
