package auth_jwks

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/internal/apierr"
)

type HTTPv1 struct {
	uc     *Usecase
	logger *zap.SugaredLogger
}

func NewHTTPv1(uc *Usecase, logger *zap.SugaredLogger) *HTTPv1 {
	return &HTTPv1{uc: uc, logger: logger}
}

// Handle is the one endpoint that does not use the {"data": ...} envelope.
//
// RFC 7517 defines this document's shape, and the generic JWKS clients that
// consume it — including pkg/authclient — expect {"keys": [...]} at the top
// level. Wrapping it would make the service unusable by any standard library,
// so the envelope contract yields to the standard here.
func (h *HTTPv1) Handle(c *gin.Context) {
	out, err := h.uc.Execute(c.Request.Context(), Input{})
	if err != nil {
		apierr.Write(c, h.logger, "jwks", err)
		return
	}

	// Public keys change only on rotation, and retired keys stay published, so
	// a long cache is safe and keeps consumers off this endpoint.
	c.Header("Cache-Control", "public, max-age=86400")
	c.Data(http.StatusOK, "application/jwk-set+json", out.Document)
}
