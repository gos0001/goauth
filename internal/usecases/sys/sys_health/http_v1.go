package sys_health

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

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
	out, err := h.uc.Execute(c.Request.Context(), Input{})
	if err != nil {
		h.logger.Errorw("health check failed", "error", err)
		httpserver.ServiceUnavailable(c, "unhealthy")
		return
	}
	httpserver.OK(c, out)
}
