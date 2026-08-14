//go:build wireinject

package main

import (
	"github.com/google/wire"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/controller/admin_v1"
	"github.com/gos0001/goauth/internal/controller/http_v1"
	"github.com/gos0001/goauth/internal/middleware"
	"github.com/gos0001/goauth/internal/orchestrators/bootstrap"
	"github.com/gos0001/goauth/internal/orchestrators/cron"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/tokens"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_audit_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_create"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_delete"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_get"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_sessions_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_sessions_revoke"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_set_password"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_update"
	"github.com/gos0001/goauth/internal/usecases/audit_cleaner"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_jwks"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_logout_all"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_me"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_password_change"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_register"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_revoke"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_settings"
	"github.com/gos0001/goauth/internal/usecases/auth/auth_token"
	"github.com/gos0001/goauth/internal/usecases/auth/session_list"
	"github.com/gos0001/goauth/internal/usecases/outbox_cleaner"
	"github.com/gos0001/goauth/internal/usecases/seed_super_admin"
	"github.com/gos0001/goauth/internal/usecases/session_cleaner"
	"github.com/gos0001/goauth/internal/usecases/sys/sys_health"
	"github.com/gos0001/goauth/internal/usecases/webhook_dispatcher"
	"github.com/gos0001/goauth/pkg/cors"
	"github.com/gos0001/goauth/pkg/dbschema"
	"github.com/gos0001/goauth/pkg/logger"
	"github.com/gos0001/goauth/pkg/passwordhash"
	pkgpostgres "github.com/gos0001/goauth/pkg/postgres"
	"github.com/gos0001/goauth/pkg/ratelimit"
	"github.com/gos0001/goauth/pkg/realip"
	pkgredis "github.com/gos0001/goauth/pkg/redis"
	"github.com/gos0001/goauth/pkg/token"
	"github.com/gos0001/goauth/pkg/webhook"
	"github.com/gos0001/goauth/schema"
	// codegen:imports
)

func InitializeApp() (*App, error) {
	wire.Build(
		LoadConfig,
		logger.Set,
		pkgpostgres.Set,
		pkgredis.Set,
		schema.Set,
		dbschema.Set,

		// pkg primitives
		passwordhash.Set,
		token.Set,
		realip.Set,
		cors.Set,
		ratelimit.Set,
		webhook.Set,

		// adapters and shared services
		postgresadapter.Set,
		tokens.Set,
		audit.Set,

		// use cases
		sys_health.Set,
		auth_jwks.Set,
		auth_settings.Set,
		auth_token.Set,
		auth_register.Set,
		auth_me.Set,
		session_list.Set,
		auth_password_change.Set,
		auth_revoke.Set,
		auth_logout_all.Set,
		seed_super_admin.Set,
		audit_cleaner.Set,
		session_cleaner.Set,
		outbox_cleaner.Set,
		webhook_dispatcher.Set,

		admin_user_create.Set,
		admin_user_list.Set,
		admin_user_get.Set,
		admin_user_update.Set,
		admin_user_delete.Set,
		admin_user_set_password.Set,
		admin_user_sessions_list.Set,
		admin_user_sessions_revoke.Set,
		admin_audit_list.Set,

		// transport
		middleware.Set,
		admin_v1.Set,
		http_v1.Set,

		bootstrap.Set,
		cron.Set,
		// codegen:providers
		NewApp,
	)
	return nil, nil
}
