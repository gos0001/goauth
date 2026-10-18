package auth_logout_all

import (
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
	out, err := h.uc.Execute(c.Request.Context(), Input{
		UserID: httpserver.UserID(c),
		IP:     httpserver.ClientIP(c),
	})
	if err != nil {
		apierr.Write(c, h.logger, "logout all", err)
		return
	}

	// Every session of this user is dead — whichever one the cookie holds, it
	// is among them.
	h.cookies.Clear(c.Writer)
	httpserver.OK(c, out)
}
