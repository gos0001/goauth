package auth_register

import (
	"strings"
	"time"

	"github.com/gos0001/goauth/internal/domain"
)

type Input struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`

	// Filled by the handler from the request, never from the body.
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

func (in *Input) Validate() error {
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)

	if in.Username == "" && in.Email == "" {
		return domain.ErrNoIdentifier
	}
	if in.Password == "" {
		return domain.ErrPasswordTooWeak
	}
	return nil
}

type Output struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`
	User         UserView  `json:"user"`
}

type UserView struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	IsAdmin  bool   `json:"is_admin"`
}
