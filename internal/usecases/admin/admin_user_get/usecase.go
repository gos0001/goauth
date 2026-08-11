package admin_user_get

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
		return Output{}, err
	}

	// PasswordHash is deliberately not exposed. It is not directly reversible,
	// but handing it out turns a read-only admin view into an offline cracking
	// target.
	return Output{
		ID:                 user.ID,
		Username:           user.Username,
		Email:              user.Email,
		IsAdmin:            user.IsAdmin,
		Status:             string(user.Status),
		MustChangePassword: user.MustChangePassword,
		LastLoginAt:        user.LastLoginAt,
		CreatedAt:          user.CreatedAt,
		UpdatedAt:          user.UpdatedAt,
	}, nil
}

type Input struct {
	ID string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.ID) == "" {
		return domain.ErrUserNotFound
	}
	return nil
}

type Output struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username,omitempty"`
	Email              string     `json:"email,omitempty"`
	IsAdmin            bool       `json:"is_admin"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}
