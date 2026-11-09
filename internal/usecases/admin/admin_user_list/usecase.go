package admin_user_list

import (
	"context"
	"time"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

type Postgres interface {
	ListUsers(ctx context.Context, p postgresadapter.ListUsersParams) ([]domain.User, error)
	CountUsers(ctx context.Context, p postgresadapter.ListUsersParams) (int, error)
}

type Guard interface {
	Actor(ctx context.Context, actorUserID string) (domain.Role, error)
	UserVisibility(actor domain.Role, actorID string) (apply bool, minRank int, owner string)
}

type Usecase struct {
	postgres Postgres
	guard    Guard
}

func New(pg *postgresadapter.Adapter, guard *roleguard.Guard) *Usecase {
	return &Usecase{postgres: pg, guard: guard}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}

	// Delegated visibility: in mode "off" (and for superadmins) UserVisibility
	// reports apply=false and the query runs unfiltered, exactly as before.
	apply, minRank, owner := uc.guard.UserVisibility(actor, in.ActorUserID)

	p := postgresadapter.ListUsersParams{
		Query:  in.Query,
		Status: domain.UserStatus(in.Status),
		Limit:  in.Limit,
		Offset: in.Offset,
	}
	if apply {
		rank := int32(minRank)
		p.MinRank = &rank
		if owner != "" {
			p.Owner = &owner
		}
	}

	users, err := uc.postgres.ListUsers(ctx, p)
	if err != nil {
		return Output{}, err
	}

	total, err := uc.postgres.CountUsers(ctx, p)
	if err != nil {
		return Output{}, err
	}

	// created_by goes to superadmins only — the same rule on every row, so
	// it is decided once here rather than per item.
	showOwner := actor.Rank >= domain.RankSuperAdmin

	items := make([]UserView, 0, len(users))
	for _, u := range users {
		v := UserView{
			ID:          u.ID,
			Username:    u.Username,
			Email:       u.Email,
			Role:        u.Role,
			Status:      string(u.Status),
			LastLoginAt: u.LastLoginAt,
			CreatedAt:   u.CreatedAt,
		}
		if showOwner {
			v.CreatedBy = u.CreatedBy
		}
		items = append(items, v)
	}

	return Output{Users: items, Total: total, Limit: in.Limit, Offset: in.Offset}, nil
}

type Input struct {
	Query  string `json:"-"`
	Status string `json:"-"`
	Limit  int    `json:"-"`
	Offset int    `json:"-"`

	ActorUserID string `json:"-"`
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
	ID          string     `json:"id"`
	Username    string     `json:"username,omitempty"`
	Email       string     `json:"email,omitempty"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`

	// CreatedBy is exposed to superadmins only; omitted for everyone else,
	// so the field never confirms whose accounts exist above them.
	CreatedBy string `json:"created_by,omitempty"`
}
