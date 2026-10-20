package auth_revoke

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/v2/internal/apierr"
	"github.com/gos0001/goauth/v2/pkg/authcookie"
	httpserver "github.com/gos0001/goauth/v2/pkg/http_server"
)

type HTTPv1 struct {
	uc      *Usecase
	cookies *authcookie.Cookies
	logger  *zap.SugaredLogger
}

func NewHTTPv1(uc *Usecase, cookies *authcookie.Cookies, logger *zap.SugaredLogger) *HTTPv1 {
	return &HTTPv1{uc: uc, cookies: cookies, logger: logger}
}

func (h *HTTPv1) Handle(c *gin.Context) {
	out, err := h.uc.Execute(c.Request.Context(), Input{
		UserID:    httpserver.UserID(c),
		SessionID: httpserver.SessionID(c),
		IP:        httpserver.ClientIP(c),
	})
	if err != nil {
		apierr.Write(c, h.logger, "revoke session", err)
		return
	}

	// The session this request spent is dead; a browser holding it as a cookie
	// must not keep presenting the corpse on every call.
	h.cookies.Clear(c.Writer)
	httpserver.OK(c, out)
}
