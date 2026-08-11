package auth_token

import (
	"errors"
	"net/http"

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

	in.IP = httpserver.ClientIP(c)
	in.UserAgent = c.Request.UserAgent()

	if err := in.Validate(); err != nil {
		apierr.Write(c, h.logger, "auth token", err)
		return
	}

	out, err := h.uc.Execute(c.Request.Context(), in)
	if err != nil {
		if errors.Is(err, ErrTooManyAttempts) {
			// Deliberately no Retry-After header: telling a brute-forcer exactly
			// when to resume is free scheduling help.
			httpserver.TooManyRequests(c, "too many attempts, try again later")
			return
		}
		apierr.Write(c, h.logger, "auth token", err)
		return
	}

	// Tokens must never be cached by a proxy or written to disk by a browser.
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	c.Status(http.StatusOK)
	httpserver.OK(c, out)
}
