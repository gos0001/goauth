package admin_audit_list

import (
	"context"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

const (
	defaultLimit = 100
	maxLimit     = 500
)

type Postgres interface {
	ListAuditEntries(ctx context.Context, p postgresadapter.ListAuditParams) ([]domain.AuditEntry, error)
}

type Usecase struct {
	postgres Postgres
}

func New(pg *postgresadapter.Adapter) *Usecase {
	return &Usecase{postgres: pg}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	entries, err := uc.postgres.ListAuditEntries(ctx, postgresadapter.ListAuditParams{
		TargetUserID: in.UserID,
		Action:       in.Action,
		Limit:        in.Limit,
		Offset:       in.Offset,
	})
	if err != nil {
		return Output{}, err
	}

	items := make([]EntryView, 0, len(entries))
	for _, e := range entries {
		items = append(items, EntryView{
			ID:           e.ID,
			Actor:        e.Actor,
			Action:       e.Action,
			TargetUserID: e.TargetUserID,
			IP:           e.IP,
			Meta:         e.Meta,
			CreatedAt:    e.CreatedAt,
		})
	}

	return Output{Entries: items, Limit: in.Limit, Offset: in.Offset}, nil
}

type Input struct {
	UserID string `json:"-"`
	Action string `json:"-"`
	Limit  int    `json:"-"`
	Offset int    `json:"-"`
}

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
	return nil
}

type Output struct {
	Entries []EntryView `json:"entries"`
	Limit   int         `json:"limit"`
	Offset  int         `json:"offset"`
}

type EntryView struct {
	ID           int64          `json:"id"`
	Actor        string         `json:"actor"`
	Action       string         `json:"action"`
	TargetUserID string         `json:"target_user_id,omitempty"`
	IP           string         `json:"ip,omitempty"`
	Meta         map[string]any `json:"meta,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}
