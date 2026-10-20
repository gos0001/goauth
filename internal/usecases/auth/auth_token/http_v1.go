package auth_token

import (
	"errors"
	"net/http"
	"strings"
	"time"

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
	var in Input
	if err := c.ShouldBindJSON(&in); err != nil {
		httpserver.BadRequest(c, "invalid request body")
		return
	}

	in.IP = httpserver.ClientIP(c)
	in.UserAgent = c.Request.UserAgent()

	// A browser rotating its session spends the cookie it was given, never a
	// token it can read. The body stays the authority when it names one, so
	// non-browser clients are unaffected.
	if strings.TrimSpace(in.GrantType) == GrantRefresh && strings.TrimSpace(in.RefreshToken) == "" {
		if raw, ok := h.cookies.RefreshFromRequest(c.Request); ok {
			in.RefreshToken = raw
		}
	}

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

	// The cookie channel, when on, mirrors the pair into HttpOnly cookies —
	// both grants, so a rotation rewrites them with its fresh tokens. A no-op
	// while the channel is disabled.
	h.cookies.Set(c.Writer,
		out.AccessToken, out.RefreshToken,
		time.Duration(out.ExpiresIn)*time.Second,
		time.Until(out.RefreshExpiresAt))

	c.Status(http.StatusOK)
	httpserver.OK(c, out)
}
