package auth_password_change

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/apierr"
	httpserver "github.com/gos0001/goauth/pkg/http_server"
)

type HTTPv1 struct {
	uc     *Usecase
	logger *zap.SugaredLogger
}

func NewHTTPv1(uc *Usecase, logger *zap.SugaredLogger) *HTTPv1 {
	return &HTTPv1{uc: uc, logger: logger}
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
	httpserver.OK(c, out)
}
