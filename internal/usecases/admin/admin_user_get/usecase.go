package admin_user_get

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetRole(ctx context.Context, name string) (domain.Role, error)
}

type Guard interface {
	Actor(ctx context.Context, actorUserID string) (domain.Role, error)
	Delegated() bool
	CanSeeUser(actor domain.Role, actorID string, target domain.User, targetRole domain.Role) error
}

type Usecase struct {
	postgres Postgres
	guard    Guard
}

func New(pg *postgresadapter.Adapter, guard *roleguard.Guard) *Usecase {
	return &Usecase{postgres: pg, guard: guard}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
		return Output{}, err
	}

	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}

	// Delegated visibility for the single-row read. Only in delegated mode —
	// in "off" every holder of users:read may fetch any id, as before. Out
	// of scope collapses to ErrUserNotFound: a 404 hides equals and
	// superiors instead of confirming they exist.
	if uc.guard.Delegated() {
		targetRole, err := uc.postgres.GetRole(ctx, user.Role)
		if err != nil {
			return Output{}, err
		}
		if err := uc.guard.CanSeeUser(actor, in.ActorUserID, user, targetRole); err != nil {
			return Output{}, err
		}
	}

	out := Output{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Role:        user.Role,
		Status:      string(user.Status),
		LastLoginAt: user.LastLoginAt,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
	// created_by would tell a non-superadmin that superadmins exist; it is
	// superadmin-only in every response shape.
	if actor.Rank >= domain.RankSuperAdmin {
		out.CreatedBy = user.CreatedBy
	}
	return out, nil
}

type Input struct {
	ID string `json:"-"`

	ActorUserID string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.ID) == "" {
		return domain.ErrUserNotFound
	}
	return nil
}

type Output struct {
	ID          string     `json:"id"`
	Username    string     `json:"username,omitempty"`
	Email       string     `json:"email,omitempty"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`

	// CreatedBy is exposed to superadmins only; omitted for everyone else,
	// so the field never confirms whose accounts exist above them.
	CreatedBy string `json:"created_by,omitempty"`
}
