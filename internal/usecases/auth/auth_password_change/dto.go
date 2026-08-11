package auth_password_change

import (
	"time"

	"github.com/gos0001/goauth/internal/domain"
)

type Input struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`

	UserID    string `json:"-"`
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

func (in *Input) Validate() error {
	if in.CurrentPassword == "" {
		return domain.ErrInvalidCredentials
	}
	if in.NewPassword == "" {
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
}
