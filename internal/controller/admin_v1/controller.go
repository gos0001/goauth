// Package admin_v1 builds the private, machine-facing admin listener.
//
// It returns its own Router type rather than *gin.Engine: wire allows exactly
// one provider per type, and the public controller already supplies the engine.
package admin_v1

import (
	"github.com/gin-gonic/gin"

	"github.com/gos0001/goauth/internal/middleware"
)

// Router wraps the private engine. Engine is nil when ADMIN_TOKEN is unset, in
// which case the listener is never started — an admin surface with no
// credential must not exist rather than default to open.
type Router struct {
	Engine *gin.Engine
}

func (r *Router) Enabled() bool { return r != nil && r.Engine != nil }

func NewRouter(mw *middleware.Middleware, cfg middleware.Config, h Handlers) *Router {
	if !cfg.AdminTokenEnabled() {
		return &Router{}
	}

	e := gin.New()
	e.Use(gin.Recovery(), mw.RealIP())

	RegisterRoutes(e, []gin.HandlerFunc{mw.AdminToken()}, mw.RequireRecentAuth(), h)

	return &Router{Engine: e}
}
