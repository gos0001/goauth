// Package audit records who changed what.
//
// Writes are best-effort by design: an audit failure is logged loudly but never
// turned into a request failure. Refusing a legitimate login because a log row
// would not insert trades a real outage for a bookkeeping gap.
package audit

import (
	"context"

	"go.uber.org/zap"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type Store interface {
	InsertAuditEntry(ctx context.Context, e domain.AuditEntry) error
}

type Recorder struct {
	store  Store
	logger *zap.SugaredLogger
}

func New(pg *postgresadapter.Adapter, logger *zap.SugaredLogger) *Recorder {
	return &Recorder{store: pg, logger: logger}
}

func (r *Recorder) Record(ctx context.Context, e domain.AuditEntry) {
	// Detached from the request context: a client that disconnects mid-request
	// must not cancel the record of what already happened.
	if err := r.store.InsertAuditEntry(context.WithoutCancel(ctx), e); err != nil {
		r.logger.Errorw("audit write failed",
			"action", e.Action, "actor", e.Actor, "target", e.TargetUserID, "error", err)
	}
}

// Event is a convenience constructor for the common shape.
func Event(actor, action, targetUserID, ip string, meta map[string]any) domain.AuditEntry {
	return domain.AuditEntry{
		Actor:        actor,
		Action:       action,
		TargetUserID: targetUserID,
		IP:           ip,
		Meta:         meta,
	}
}
