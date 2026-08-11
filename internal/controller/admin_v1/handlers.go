package admin_v1

import (
	"github.com/gin-gonic/gin"

	"github.com/gos0001/goauth/internal/usecases/admin/admin_audit_list"
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
	}
}

// RegisterRoutes mounts the admin surface under g.
//
// guards is how the caller proved they may be here — a JWT plus a live is_admin
// read on the public listener, or the static token on the private one. They are
// passed as a chain rather than composed by the caller because gin middleware
// drives the chain itself through c.Next(); invoking one inside another runs the
// remaining handlers early and silently breaks the ordering.
//
// sudo is the extra re-authentication demanded by the destructive half; it is a
// no-op for machine callers, which present their credential on every request
// anyway.
func RegisterRoutes(g gin.IRouter, guards []gin.HandlerFunc, sudo gin.HandlerFunc, h Handlers) {
	admin := g.Group("/admin", guards...)

	// Read-only.
	admin.GET("/users", h.UserList.Handle)
	admin.GET("/users/:id", h.UserGet.Handle)
	admin.GET("/users/:id/sessions", h.SessionsList.Handle)
	admin.GET("/audit", h.AuditList.Handle)

	// Mutating, but not account-destroying.
	admin.POST("/users", h.UserCreate.Handle)
	admin.DELETE("/users/:id/sessions", h.SessionsRevoke.Handle)

	// Destructive: these can lock a user out or take over their account, so
	// they additionally require a recent password.
	destructive := admin.Group("", sudo)
	destructive.PATCH("/users/:id", h.UserUpdate.Handle)
	destructive.DELETE("/users/:id", h.UserDelete.Handle)
	destructive.POST("/users/:id/password", h.UserSetPassword.Handle)
}
