package admin_user_list

import (
	"context"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

type Postgres interface {
	ListUsers(ctx context.Context, p postgresadapter.ListUsersParams) ([]domain.User, error)
	CountUsers(ctx context.Context, p postgresadapter.ListUsersParams) (int, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	p := postgresadapter.ListUsersParams{
		Query:  in.Query,
		Status: domain.UserStatus(in.Status),
		Limit:  in.Limit,
		Offset: in.Offset,
	}

	users, err := uc.postgres.ListUsers(ctx, p)
	if err != nil {
		return Output{}, err
	}

	total, err := uc.postgres.CountUsers(ctx, p)
	if err != nil {
		return Output{}, err
	}

	items := make([]UserView, 0, len(users))
	for _, u := range users {
		items = append(items, UserView{
			ID:                 u.ID,
			Username:           u.Username,
			Email:              u.Email,
			IsAdmin:            u.IsAdmin,
			Status:             string(u.Status),
			MustChangePassword: u.MustChangePassword,
			LastLoginAt:        u.LastLoginAt,
			CreatedAt:          u.CreatedAt,
		})
	}

	return Output{Users: items, Total: total, Limit: in.Limit, Offset: in.Offset}, nil
}

type Input struct {
	Query  string `json:"-"`
	Status string `json:"-"`
	Limit  int    `json:"-"`
	Offset int    `json:"-"`
}

// Validate clamps paging rather than rejecting it: an oversized limit is a
// client bug, not an attack, and a hard error there breaks the caller for no
// benefit.
func (in *Input) Validate() error {
	if in.Limit <= 0 {
		in.Limit = defaultLimit
	}
	if in.Limit > maxLimit {
		in.Limit = maxLimit
	}
	if in.Offset < 0 {
		in.Offset = 0
	}
	if in.Status != "" {
		switch domain.UserStatus(in.Status) {
		case domain.StatusActive, domain.StatusBlocked, domain.StatusDeleted:
		default:
			return domain.ErrInvalidInput
		}
	}
	return nil
}

type Output struct {
	Users  []UserView `json:"users"`
	Total  int        `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

type UserView struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username,omitempty"`
	Email              string     `json:"email,omitempty"`
	IsAdmin            bool       `json:"is_admin"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}
