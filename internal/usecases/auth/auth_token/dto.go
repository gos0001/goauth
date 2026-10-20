package auth_token

import (
	"strings"
	"time"

	"github.com/gos0001/goauth/internal/domain"
)

// Grant types, following the OAuth2 naming so that adding
// client_credentials or authorization_code later is a new branch rather than a
// new endpoint.
const (
	GrantPassword = "password"
	GrantRefresh  = "refresh_token"
)

type Input struct {
	GrantType string `json:"grant_type"`

	// Password grant.
	Identifier string `json:"identifier"`
	Password   string `json:"password"`

	// Refresh grant.
	RefreshToken string `json:"refresh_token"`

	// Filled by the handler from the request, never from the body.
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

func (in *Input) Validate() error {
	in.GrantType = strings.TrimSpace(in.GrantType)

	switch in.GrantType {
	case GrantPassword:
		if strings.TrimSpace(in.Identifier) == "" || in.Password == "" {
			return domain.ErrInvalidCredentials
		}
	case GrantRefresh:
		if strings.TrimSpace(in.RefreshToken) == "" {
			return domain.ErrSessionNotFound
		}
	default:
		return domain.ErrInvalidInput
	}

	return nil
}

type Output struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token"`

	// RefreshExpiresAt is never serialised: the cookie channel needs the
	// refresh lifetime for Max-Age, and no JSON client has ever asked for it.
	RefreshExpiresAt time.Time `json:"-"`

	User UserView `json:"user"`
}

type UserView struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role"`
}

func viewOf(u domain.User) UserView {
	return UserView{ID: u.ID, Username: u.Username, Email: u.Email, Role: u.Role}
}
