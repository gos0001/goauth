package admin_user_sessions_list

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
)

type Postgres interface {
	ListLiveUserSessions(ctx context.Context, userID string) ([]domain.Session, error)
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetRole(ctx context.Context, name string) (domain.Role, error)
}

type Guard interface {
	Actor(ctx context.Context, actorUserID string) (domain.Role, error)
	Delegated() bool
	CanActOnUser(actor domain.Role, actorID string, target domain.User, targetRole domain.Role) error
}

type Usecase struct {
	postgres Postgres
	guard    Guard
}

func New(pg *postgresadapter.Adapter, guard *roleguard.Guard) *Usecase {
	return &Usecase{postgres: pg, guard: guard}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	// Reading someone's sessions is reconnaissance for taking the account
	// over, so delegated mode scopes it like a mutation. Behind the mode
	// flag: in "off" the listing runs unguarded, as it always did.
	if uc.guard.Delegated() {
		user, err := uc.postgres.GetUserByID(ctx, in.UserID)
		if err != nil {
			return Output{}, err
		}
		actor, err := uc.guard.Actor(ctx, in.ActorUserID)
		if err != nil {
			return Output{}, err
		}
		targetRole, err := uc.postgres.GetRole(ctx, user.Role)
		if err != nil {
			return Output{}, err
		}
		if err := uc.guard.CanActOnUser(actor, in.ActorUserID, user, targetRole); err != nil {
			return Output{}, err
		}
	}

	sessions, err := uc.postgres.ListLiveUserSessions(ctx, in.UserID)
	if err != nil {
		return Output{}, err
	}

	items := make([]SessionView, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, SessionView{
			ID:        s.ID,
			FamilyID:  s.FamilyID,
			IP:        s.IP,
			UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		})
	}

	return Output{Sessions: items}, nil
}

type Input struct {
	UserID string `json:"-"`

	// Empty on the machine listener, where the caller is modelled as a
	// superadmin anyway.
	ActorUserID string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.UserID) == "" {
		return domain.ErrUserNotFound
	}
	return nil
}

type Output struct {
	Sessions []SessionView `json:"sessions"`
}

type SessionView struct {
	ID        string    `json:"id"`
	FamilyID  string    `json:"family_id"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
