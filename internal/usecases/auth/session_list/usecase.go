package session_list

import (
	"context"
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

// Execute lists the caller's live sessions — the "my devices" view.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	sessions, err := uc.postgres.ListLiveUserSessions(ctx, in.UserID)
	if err != nil {
		return Output{}, err
	}

	items := make([]SessionView, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, SessionView{
			ID:        s.ID,
			IP:        s.IP,
			UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
			// Current marks the session this request arrived on, so the UI can
			// label it and warn before revoking it.
			Current: s.ID == in.CurrentSessionID,
		})
	}

	return Output{Sessions: items}, nil
}

type Input struct {
	UserID           string `json:"-"`
	CurrentSessionID string `json:"-"`
}

type Output struct {
	Sessions []SessionView `json:"sessions"`
}

type SessionView struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Current   bool      `json:"current"`
}
