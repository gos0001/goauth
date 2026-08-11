package postgres

import (
	"context"
	"encoding/json"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
)

func (a *Adapter) InsertAuditEntry(ctx context.Context, e domain.AuditEntry) error {
	target, err := pgUUID(e.TargetUserID)
	if err != nil {
		return domain.ErrInvalidInput
	}

	meta := []byte("{}")
	if len(e.Meta) > 0 {
		encoded, err := json.Marshal(e.Meta)
		if err != nil {
			return err
		}
		meta = encoded
	}

	return MapError(a.q.InsertAuditEntry(ctx, generated.InsertAuditEntryParams{
		Actor:        e.Actor,
		Action:       e.Action,
		TargetUserID: target,
		Ip:           text(e.IP),
		Meta:         meta,
	}), nil)
}

type ListAuditParams struct {
	TargetUserID string
	Action       string
	Limit        int
	Offset       int
}

func (a *Adapter) ListAuditEntries(ctx context.Context, p ListAuditParams) ([]domain.AuditEntry, error) {
	target, err := pgUUID(p.TargetUserID)
	if err != nil {
		return nil, domain.ErrInvalidInput
	}

	rows, err := a.q.ListAuditEntries(ctx, generated.ListAuditEntriesParams{
		TargetUserID: target,
		Action:       text(p.Action),
		Lim:          int32(p.Limit),
		Off:          int32(p.Offset),
	})
	if err != nil {
		return nil, MapError(err, nil)
	}

	out := make([]domain.AuditEntry, 0, len(rows))
	for _, row := range rows {
		entry := domain.AuditEntry{
			ID:           row.ID,
			Actor:        row.Actor,
			Action:       row.Action,
			TargetUserID: pgUUIDOut(row.TargetUserID),
			IP:           textOut(row.Ip),
			CreatedAt:    tsOut(row.CreatedAt),
		}
		if len(row.Meta) > 0 {
			// A row with unreadable meta is still worth returning — the audit
			// trail matters more than one malformed payload.
			_ = json.Unmarshal(row.Meta, &entry.Meta)
		}
		out = append(out, entry)
	}
	return out, nil
}
