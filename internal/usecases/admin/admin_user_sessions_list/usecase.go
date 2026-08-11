package admin_user_sessions_list

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type Postgres interface {
	ListLiveUserSessions(ctx context.Context, userID string) ([]domain.Session, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
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
