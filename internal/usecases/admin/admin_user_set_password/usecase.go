package admin_user_set_password

import (
	"context"
	"fmt"
	"strings"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
	"github.com/gos0001/goauth/v2/internal/service/audit"
	"github.com/gos0001/goauth/v2/internal/service/roleguard"
	"github.com/gos0001/goauth/v2/pkg/appconfig"
	"github.com/gos0001/goauth/v2/pkg/passwordhash"
)

type Config struct {
	MinPasswordLength int `json:"min_password_len"`
}

func LoadConfig(root appconfig.Config) (Config, error) {
	cfg := Config{MinPasswordLength: 12}
	if err := root.Section("auth", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	GetRole(ctx context.Context, name string) (domain.Role, error)
	SetPasswordAndRevokeSessions(ctx context.Context, id, passwordHash string, ev *domain.OutboxEvent) (domain.User, error)
}

type Guard interface {
	Actor(ctx context.Context, actorUserID string) (domain.Role, error)
}

type Hasher interface {
	Hash(password string) (string, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	guard    Guard
	hasher   Hasher
	auditor  Auditor
	cfg      Config
}

func New(pg *postgresadapter.Adapter, guard *roleguard.Guard, hasher *passwordhash.Hasher, auditor *audit.Recorder, cfg Config) *Usecase {
	return &Usecase{postgres: pg, guard: guard, hasher: hasher, auditor: auditor, cfg: cfg}
}

// Execute sets a temporary password on someone else's account. It exists so an
// operator can recover a locked-out user while goauth has no mail delivery.
//
// This is the most dangerous operation in the service: whoever calls it can
// then log in as the target. Three things contain that:
//
//   - every existing session of the target is revoked, so the change cannot be
//     used to quietly join an existing session
//   - the call is always audited with the acting admin's id
//
// Note what is missing: nothing stops the admin from signing in as the target
// afterwards, and the owner has no signal that it happened. A one-time reset
// link would fix that, and needs mail delivery the service does not have.
//
// When a Mailer is added, this should be replaced by a one-time reset link that
// only the account owner can act on, and this endpoint removed.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
		return Output{}, err
	}

	// Taking over an account is rank-guarded like any other management
	// action: strictly above the target, always — this endpoint on a peer is
	// account theft with extra steps.
	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}
	targetRole, err := uc.postgres.GetRole(ctx, user.Role)
	if err != nil {
		return Output{}, err
	}
	if err := roleguard.CanActOnUser(actor, targetRole.Rank); err != nil {
		return Output{}, err
	}

	if err := domain.ValidatePassword(in.Password, uc.cfg.MinPasswordLength); err != nil {
		return Output{}, err
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return Output{}, fmt.Errorf("admin_user_set_password: hash: %w", err)
	}

	ev := domain.OutboxEvent{Event: domain.EventUserPasswordChanged}
	updated, err := uc.postgres.SetPasswordAndRevokeSessions(ctx, user.ID, hash, &ev)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionPasswordSetByAdmin, updated.ID, in.IP, nil))

	return Output{
		ID:              updated.ID,
		SessionsRevoked: true,
	}, nil
}

type Input struct {
	Password string `json:"password"`

	ID          string `json:"-"`
	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if strings.TrimSpace(in.ID) == "" {
		return domain.ErrUserNotFound
	}
	if in.Password == "" {
		return domain.ErrPasswordTooWeak
	}
	return nil
}

type Output struct {
	ID              string `json:"id"`
	SessionsRevoked bool   `json:"sessions_revoked"`
}
