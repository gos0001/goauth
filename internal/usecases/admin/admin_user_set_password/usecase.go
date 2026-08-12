package admin_user_set_password

import (
	"context"
	"fmt"
	"strings"

	"github.com/kelseyhightower/envconfig"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/pkg/passwordhash"
)

type Config struct {
	MinPasswordLength int `envconfig:"AUTH_MIN_PASSWORD_LEN" default:"12"`
}

func LoadConfig() (Config, error) {
	var cfg Config
	return cfg, envconfig.Process("", &cfg)
}

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	SetPasswordAndRevokeSessions(ctx context.Context, id, passwordHash string, mustChange bool, ev *domain.OutboxEvent) (domain.User, error)
}

type Hasher interface {
	Hash(password string) (string, error)
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Usecase struct {
	postgres Postgres
	hasher   Hasher
	auditor  Auditor
	cfg      Config
}

func New(pg *postgresadapter.Adapter, hasher *passwordhash.Hasher, auditor *audit.Recorder, cfg Config) *Usecase {
	return &Usecase{postgres: pg, hasher: hasher, auditor: auditor, cfg: cfg}
}

// Execute sets a temporary password on someone else's account. It exists so an
// operator can recover a locked-out user while goauth has no mail delivery.
//
// This is the most dangerous operation in the service: whoever calls it can
// then log in as the target. Three things contain that:
//
//   - must_change_password is forced on, so the temporary password stops
//     working the moment the real user logs in
//   - every existing session of the target is revoked, so the change cannot be
//     used to quietly join an existing session
//   - the call is always audited with the acting admin's id
//
// When a Mailer is added, this should be replaced by a one-time reset link that
// only the account owner can act on, and this endpoint removed.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.ID)
	if err != nil {
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
	updated, err := uc.postgres.SetPasswordAndRevokeSessions(ctx, user.ID, hash, true, &ev)
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionPasswordSetByAdmin, updated.ID, in.IP, nil))

	return Output{
		ID:                 updated.ID,
		MustChangePassword: updated.MustChangePassword,
		SessionsRevoked:    true,
	}, nil
}

type Input struct {
	Password string `json:"password"`

	ID    string `json:"-"`
	Actor string `json:"-"`
	IP    string `json:"-"`
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
	ID                 string `json:"id"`
	MustChangePassword bool   `json:"must_change_password"`
	SessionsRevoked    bool   `json:"sessions_revoked"`
}
