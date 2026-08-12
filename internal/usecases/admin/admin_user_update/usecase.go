package admin_user_update

import (
	"context"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	CountActiveAdmins(ctx context.Context) (int, error)
	UpdateUser(ctx context.Context, p postgresadapter.UpdateUserParams) (domain.User, error)
	UpdateUserAndRevokeSessions(ctx context.Context, p postgresadapter.UpdateUserParams) (domain.User, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	auditor  Auditor
}

func New(pg *postgresadapter.Adapter, auditor *audit.Recorder) *Usecase {
	return &Usecase{postgres: pg, auditor: auditor}
}

// Execute applies a partial update to another account: identifiers, status, and
// the admin flag.
//
// Two guards exist because their absence is unrecoverable through the API — an
// installation that demotes or blocks its only admin can then only be repaired
// with manual SQL against the database.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	current, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
		return Output{}, err
	}

	p := postgresadapter.UpdateUserParams{ID: current.ID}

	if in.Username != nil {
		v, err := domain.NormalizeUsername(*in.Username)
		if err != nil {
			return Output{}, err
		}
		p.Username = &v
	}
	if in.Email != nil {
		v, err := domain.NormalizeEmail(*in.Email)
		if err != nil {
			return Output{}, err
		}
		p.Email = &v
	}

	losesAdmin := in.IsAdmin != nil && current.IsAdmin && !*in.IsAdmin
	losesActive := in.Status != nil && current.Active() && domain.UserStatus(*in.Status) != domain.StatusActive

	if losesAdmin && in.ActorUserID == current.ID {
		// Self-demotion is refused rather than merely warned about: the actor
		// would lose the very rights needed to undo it.
		return Output{}, domain.ErrSelfDemote
	}

	if current.IsAdmin && current.Active() && (losesAdmin || losesActive) {
		admins, err := uc.postgres.CountActiveAdmins(ctx)
		if err != nil {
			return Output{}, err
		}
		if admins <= 1 {
			return Output{}, domain.ErrLastAdmin
		}
	}

	if in.IsAdmin != nil {
		v := *in.IsAdmin
		p.IsAdmin = &v
	}
	if in.Status != nil {
		v := domain.UserStatus(*in.Status)
		p.Status = &v
	}

	p.Event = &domain.OutboxEvent{Event: updateEventFor(current, in)}

	// A status change away from active must take effect immediately, so it goes
	// through the transactional variant that also drops the target's sessions.
	// Blocking someone whose live sessions keep working is not a block.
	var updated domain.User
	if losesActive {
		updated, err = uc.postgres.UpdateUserAndRevokeSessions(ctx, p)
	} else {
		updated, err = uc.postgres.UpdateUser(ctx, p)
	}
	if err != nil {
		return Output{}, err
	}

	uc.record(ctx, in, current, updated)

	return Output{
		ID:                 updated.ID,
		Username:           updated.Username,
		Email:              updated.Email,
		IsAdmin:            updated.IsAdmin,
		Status:             string(updated.Status),
		MustChangePassword: updated.MustChangePassword,
		UpdatedAt:          updated.UpdatedAt,
	}, nil
}

// updateEventFor names the change as specifically as it can. A consumer
// switching on "user.blocked" should not have to diff two payloads to discover
// that is what happened; "user.updated" is the fallback for a plain edit.
func updateEventFor(before domain.User, in Input) string {
	if in.IsAdmin != nil && *in.IsAdmin != before.IsAdmin {
		if *in.IsAdmin {
			return domain.EventAdminGranted
		}
		return domain.EventAdminRevoked
	}
	if in.Status != nil && domain.UserStatus(*in.Status) != before.Status {
		if domain.UserStatus(*in.Status) == domain.StatusActive {
			return domain.EventUserUnblocked
		}
		return domain.EventUserBlocked
	}
	return domain.EventUserUpdated
}

func (uc *Usecase) record(ctx context.Context, in Input, before, after domain.User) {
	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserUpdated, after.ID, in.IP,
		map[string]any{"status": string(after.Status), "is_admin": after.IsAdmin}))

	if before.IsAdmin != after.IsAdmin {
		action := domain.ActionAdminRevoked
		if after.IsAdmin {
			action = domain.ActionAdminGranted
		}
		uc.auditor.Record(ctx, audit.Event(in.Actor, action, after.ID, in.IP, nil))
	}

	if before.Status != after.Status {
		switch after.Status {
		case domain.StatusBlocked:
			uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserBlocked, after.ID, in.IP, nil))
		case domain.StatusActive:
			uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserUnblocked, after.ID, in.IP, nil))
		}
	}
}

// Input uses pointers throughout so that "field omitted" and "field set to the
// zero value" stay distinguishable in a PATCH.
type Input struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Status   *string `json:"status"`
	IsAdmin  *bool   `json:"is_admin"`

	ID string `json:"-"`

	// ActorUserID is empty when the caller is a machine holding the static
	// token; the self-demotion guard then does not apply, because there is no
	// "self" to lock out.
	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.ID) == "" {
		return domain.ErrUserNotFound
	}
	if in.Username == nil && in.Email == nil && in.Status == nil && in.IsAdmin == nil {
		return domain.ErrInvalidInput
	}
	if in.Status != nil {
		switch domain.UserStatus(*in.Status) {
		case domain.StatusActive, domain.StatusBlocked:
		default:
			// Deletion goes through DELETE, which also clears identifiers.
			return domain.ErrInvalidInput
		}
	}
	return nil
}

type Output struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username,omitempty"`
	Email              string    `json:"email,omitempty"`
	IsAdmin            bool      `json:"is_admin"`
	Status             string    `json:"status"`
	MustChangePassword bool      `json:"must_change_password"`
	UpdatedAt          time.Time `json:"updated_at"`
}
