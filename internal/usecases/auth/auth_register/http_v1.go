package auth_register

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

// Enabled tells the controller whether to register the route at all. When
// registration is closed the path simply does not exist, rather than existing
// and refusing — a 404 does not disclose that the feature is merely switched off.
func (h *HTTPv1) Enabled() bool { return h.uc.cfg.Open() }

func (h *HTTPv1) Handle(c *gin.Context) {
	var in Input
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.BadRequest(c, "invalid request body")
		return
	}

	in.IP = httpserver.ClientIP(c)
	in.UserAgent = c.Request.UserAgent()

	if err := in.Validate(); err != nil {
		apierr.Write(c, h.logger, "register", err)
		return
	}

	out, err := h.uc.Execute(c.Request.Context(), in)
	if err != nil {
		apierr.Write(c, h.logger, "register", err)
		return
	}

	c.Header("Cache-Control", "no-store")
	httpserver.Created(c, out)
}
