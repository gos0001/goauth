package session_list

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
	out, err := h.uc.Execute(c.Request.Context(), Input{
		UserID:           httpserver.UserID(c),
		CurrentSessionID: httpserver.SessionID(c),
	})
	if err != nil {
		apierr.Write(c, h.logger, "list sessions", err)
		return
	}
	httpserver.OK(c, out)
}
