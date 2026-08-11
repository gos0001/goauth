package http_v1

import (
	"github.com/gin-gonic/gin"

	"github.com/gos0001/goauth/internal/controller/admin_v1"
	"github.com/gos0001/goauth/internal/middleware"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_jwks"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_logout_all"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_me"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_password_change"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_register"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_revoke"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_settings"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_token"
	"github.com/gos0001/goauth/internal/usecases/auth/session_list"
	"github.com/gos0001/goauth/internal/usecases/sys/sys_health"
	// codegen:imports
)

// New builds the public router and registers every JSON API route.
// Routing only — no business logic, no adapters, no domain types.
func New(
	mw *middleware.Middleware,
	limits Limits,
	health *sys_health.HTTPv1,
	jwks *auth_jwks.HTTPv1,
	settings *auth_settings.HTTPv1,
	tokenH *auth_token.HTTPv1,
	register *auth_register.HTTPv1,
	me *auth_me.HTTPv1,
	sessions *session_list.HTTPv1,
	passwordChange *auth_password_change.HTTPv1,
	revoke *auth_revoke.HTTPv1,
	logoutAll *auth_logout_all.HTTPv1,
	adminHandlers admin_v1.Handlers,
	// codegen:params
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), mw.RealIP())

	r.GET("/healthz", health.Handle)
	r.GET("/.well-known/jwks.json", jwks.Handle)

	auth := r.Group("/auth")
	{
		auth.GET("/settings", settings.Handle)

		// The only endpoints that check a password, and so the only ones that
		// carry an IP rate limit.
		auth.POST("/token", mw.RateLimit(limits.Login, "login"), tokenH.Handle)

		// Registration is not merely refused when closed — the route is never
		// created, so a disabled feature does not announce itself.
		if register.Enabled() {
			auth.POST("/register", mw.RateLimit(limits.Register, "register"), register.Handle)
		}

		authed := auth.Group("", mw.Auth())
		authed.GET("/me", me.Handle)
		authed.GET("/sessions", sessions.Handle)
		authed.POST("/password", passwordChange.Handle)
		authed.POST("/revoke", revoke.Handle)
		authed.POST("/logout-all", logoutAll.Handle)
	}

	// The same admin handlers the private listener serves, reached here with a
	// JWT whose is_admin flag is re-read from the database on every request.
	// This is the path the panel frontend uses; the static admin token is never
	// accepted on the public listener, because a browser cannot hold one safely.
	admin_v1.RegisterRoutes(r,
		[]gin.HandlerFunc{mw.AuthSilent(), mw.AdminJWT()},
		mw.RequireRecentAuth(),
		adminHandlers,
	)

	// codegen:routes

	return r
}
