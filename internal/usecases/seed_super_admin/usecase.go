// Package seed_super_admin creates the first administrator at startup.
//
// The alternative — "whoever registers first becomes admin" — is a race: any
// visitor who reaches a freshly deployed instance before its owner takes it
// over. Reading the credential from the environment makes ownership a property
// of who controls the deployment.
package seed_super_admin

import (
	"context"
	"errors"
	"fmt"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/pkg/passwordhash"
)

type Postgres interface {
	CountActiveAdmins(ctx context.Context) (int, error)
	CreateUser(ctx context.Context, p postgresadapter.CreateUserParams) (domain.User, error)
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

// Execute creates the bootstrap administrator if the installation has none.
//
// The guard is "no active admin exists", not "no user with this username". The
// latter would create a second admin every time the first one is renamed and
// the service restarted.
//
// The credentials come from the environment and are used exactly as given —
// nothing is generated and nothing is printed. They apply only when there is no
// admin yet: afterwards the password lives in the database, so a change through
// /auth/password survives a restart rather than being reset from the
// environment on the next boot.
func (uc *Usecase) Execute(ctx context.Context, _ Input) (Output, error) {
	if !uc.cfg.Enabled() {
		return Output{Skipped: true, Reason: "not configured"}, nil
	}

	// Checked before anything touches the database: an account nobody can sign
	// into is worse than a service that refuses to start and says why.
	if err := domain.ValidatePassword(uc.cfg.Password, uc.cfg.MinPasswordLength); err != nil {
		return Output{}, fmt.Errorf(
			"seed_super_admin: SUPER_ADMIN_PASSWORD is required alongside SUPER_ADMIN_USERNAME "+
				"and must be at least %d characters: %w", uc.cfg.MinPasswordLength, err)
	}

	admins, err := uc.postgres.CountActiveAdmins(ctx)
	if err != nil {
		return Output{}, fmt.Errorf("seed_super_admin: count admins: %w", err)
	}
	if admins > 0 {
		return Output{Skipped: true, Reason: "an active admin already exists"}, nil
	}

	var username, email string
	if uc.cfg.Username != "" {
		if username, err = domain.NormalizeUsername(uc.cfg.Username); err != nil {
			return Output{}, fmt.Errorf("seed_super_admin: SUPER_ADMIN_USERNAME is invalid: %w", err)
		}
	}
	if uc.cfg.Email != "" {
		if email, err = domain.NormalizeEmail(uc.cfg.Email); err != nil {
			return Output{}, fmt.Errorf("seed_super_admin: SUPER_ADMIN_EMAIL is invalid: %w", err)
		}
	}

	hash, err := uc.hasher.Hash(uc.cfg.Password)
	if err != nil {
		return Output{}, fmt.Errorf("seed_super_admin: hash password: %w", err)
	}

	user, err := uc.postgres.CreateUser(ctx, postgresadapter.CreateUserParams{
		Event:        &domain.OutboxEvent{Event: domain.EventUserCreated},
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      true,
		Status:       domain.StatusActive,
	})
	if err != nil {
		// The admin-count check and this insert are not one atomic step, so two
		// replicas starting against the same empty database can both pass the
		// check and race here. The loser sees a unique violation — which means
		// the installation now has exactly the administrator it needed, so this
		// is success, not a reason to refuse to boot.
		if errors.Is(err, domain.ErrUserAlreadyExists) || errors.Is(err, domain.ErrAlreadyExists) {
			return Output{Skipped: true, Reason: "another instance seeded the admin first"}, nil
		}
		return Output{}, fmt.Errorf("seed_super_admin: create user: %w", err)
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorSystem, domain.ActionUserCreated, user.ID, "",
		map[string]any{"bootstrap": true, "is_admin": true}))
	uc.auditor.Record(ctx, audit.Event(domain.ActorSystem, domain.ActionAdminGranted, user.ID, "",
		map[string]any{"bootstrap": true}))

	return Output{
		Created:    true,
		UserID:     user.ID,
		Identifier: user.Identifier(),
	}, nil
}

type Input struct{}

type Output struct {
	Created    bool
	Skipped    bool
	Reason     string
	UserID     string
	Identifier string
}
