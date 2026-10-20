package admin_v1

import (
	"github.com/gin-gonic/gin"

	"github.com/gos0001/goauth/internal/usecases/admin/admin_audit_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_role_create"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_role_delete"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_role_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_role_update"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_create"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_delete"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_get"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_sessions_list"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_sessions_revoke"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_set_password"
	"github.com/gos0001/goauth/internal/usecases/admin/admin_user_update"
)

// Handlers is the admin surface, gathered once so that the same set of routes
// can be mounted on both listeners without being written out twice.
type Handlers struct {
	UserCreate      *admin_user_create.HTTPv1
	UserList        *admin_user_list.HTTPv1
	UserGet         *admin_user_get.HTTPv1
	UserUpdate      *admin_user_update.HTTPv1
	UserDelete      *admin_user_delete.HTTPv1
	UserSetPassword *admin_user_set_password.HTTPv1
	SessionsList    *admin_user_sessions_list.HTTPv1
	SessionsRevoke  *admin_user_sessions_revoke.HTTPv1
	AuditList       *admin_audit_list.HTTPv1
	RoleList        *admin_role_list.HTTPv1
	RoleCreate      *admin_role_create.HTTPv1
	RoleUpdate      *admin_role_update.HTTPv1
	RoleDelete      *admin_role_delete.HTTPv1
}

func NewHandlers(
	userCreate *admin_user_create.HTTPv1,
	userList *admin_user_list.HTTPv1,
	userGet *admin_user_get.HTTPv1,
	userUpdate *admin_user_update.HTTPv1,
	userDelete *admin_user_delete.HTTPv1,
	userSetPassword *admin_user_set_password.HTTPv1,
	sessionsList *admin_user_sessions_list.HTTPv1,
	sessionsRevoke *admin_user_sessions_revoke.HTTPv1,
	auditList *admin_audit_list.HTTPv1,
	roleList *admin_role_list.HTTPv1,
	roleCreate *admin_role_create.HTTPv1,
	roleUpdate *admin_role_update.HTTPv1,
	roleDelete *admin_role_delete.HTTPv1,
) Handlers {
	return Handlers{
		UserCreate:      userCreate,
		UserList:        userList,
		UserGet:         userGet,
		UserUpdate:      userUpdate,
		UserDelete:      userDelete,
		UserSetPassword: userSetPassword,
		SessionsList:    sessionsList,
		SessionsRevoke:  sessionsRevoke,
		AuditList:       auditList,
		RoleList:        roleList,
		RoleCreate:      roleCreate,
		RoleUpdate:      roleUpdate,
		RoleDelete:      roleDelete,
	}
}

// RegisterRoutes mounts the admin surface under g.
//
// auth is how the caller proved they may be here — a JWT on the public
// listener, the static token on the private one. requireScope adds the
// per-route permission check and is nil on the private listener, whose
// machine caller already holds the whole surface. They are passed as a chain
// rather than composed by the caller because gin middleware drives the chain
// itself through c.Next(); invoking one inside another runs the remaining
// handlers early and silently breaks the ordering.
//
// sudo is the extra re-authentication demanded by the destructive half; it is a
// no-op for machine callers, which present their credential on every request
// anyway.
func RegisterRoutes(g gin.IRouter, auth gin.HandlerFunc, requireScope func(string) gin.HandlerFunc, sudo gin.HandlerFunc, h Handlers) {
	scope := func(p string) gin.HandlerFunc {
		if requireScope == nil {
			return func(c *gin.Context) {}
		}
		return requireScope(p)
	}

	admin := g.Group("/admin", auth)

	// Read-only.
	admin.GET("/users", scope("users:read"), h.UserList.Handle)
	admin.GET("/users/:id", scope("users:read"), h.UserGet.Handle)
	admin.GET("/users/:id/sessions", scope("sessions:read"), h.SessionsList.Handle)
	admin.GET("/audit", scope("audit:read"), h.AuditList.Handle)
	admin.GET("/roles", scope("roles:read"), h.RoleList.Handle)

	// Mutating, but not account-destroying.
	admin.POST("/users", scope("users:create"), h.UserCreate.Handle)
	admin.DELETE("/users/:id/sessions", scope("sessions:revoke"), h.SessionsRevoke.Handle)

	// Role management. Creating or editing a role is as powerful as editing
	// every user that holds it, so it sits behind roles:manage and the rank
	// rules in the use case — not the sudo window, which is about proving the
	// operator is still the human who signed in.
	admin.POST("/roles", scope("roles:manage"), h.RoleCreate.Handle)
	admin.PATCH("/roles/:name", scope("roles:manage"), h.RoleUpdate.Handle)
	admin.DELETE("/roles/:name", scope("roles:manage"), h.RoleDelete.Handle)

	// Destructive: these can lock a user out or take over their account, so
	// they additionally require a recent password.
	destructive := admin.Group("", sudo)
	destructive.PATCH("/users/:id", scope("users:update"), h.UserUpdate.Handle)
	destructive.DELETE("/users/:id", scope("users:delete"), h.UserDelete.Handle)
	destructive.POST("/users/:id/password", scope("password:set"), h.UserSetPassword.Handle)
}
