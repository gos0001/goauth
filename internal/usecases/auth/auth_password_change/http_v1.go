package auth_password_change

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/apierr"
	"github.com/gos0001/goauth/pkg/authcookie"
	httpserver "github.com/gos0001/goauth/pkg/http_server"
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
	var in Input
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.BadRequest(c, "invalid request body")
		return
	}

	in.UserID = httpserver.UserID(c)
	in.IP = httpserver.ClientIP(c)
	in.UserAgent = c.Request.UserAgent()

	if err := in.Validate(); err != nil {
		apierr.Write(c, h.logger, "change password", err)
		return
	}

	out, err := h.uc.Execute(c.Request.Context(), in)
	if err != nil {
		apierr.Write(c, h.logger, "change password", err)
		return
	}

	c.Header("Cache-Control", "no-store")

	// The old session family is dead after a password change, so any cookie
	// holding its refresh token is worthless — these are the successor's.
	h.cookies.Set(c.Writer,
		out.AccessToken, out.RefreshToken,
		time.Duration(out.ExpiresIn)*time.Second,
		time.Until(out.RefreshExpiresAt))

	httpserver.OK(c, out)
}
