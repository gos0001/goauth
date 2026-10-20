package admin_user_create

import (
	"context"
	"fmt"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/roleguard"
	"github.com/gos0001/goauth/pkg/appconfig"
	"github.com/gos0001/goauth/pkg/passwordhash"
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
	CreateUser(ctx context.Context, p postgresadapter.CreateUserParams) (domain.User, error)
	GetRole(ctx context.Context, name string) (domain.Role, error)
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

// Execute provisions an account on someone's behalf. This is how users are
// created when registration is closed — by an operator, or by a payment webhook
// calling the private port after a purchase.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	var (
		username, email string
		err             error
	)

	if strings.TrimSpace(in.Username) != "" {
		if username, err = domain.NormalizeUsername(in.Username); err != nil {
			return Output{}, err
		}
	}
	if strings.TrimSpace(in.Email) != "" {
		if email, err = domain.NormalizeEmail(in.Email); err != nil {
			return Output{}, err
		}
	}
	if username == "" && email == "" {
		return Output{}, domain.ErrNoIdentifier
	}

	if err := domain.ValidatePassword(in.Password, uc.cfg.MinPasswordLength); err != nil {
		return Output{}, err
	}

	// The role must exist before the user can reference it, and placing
	// someone into it means sitting strictly above it: creating an account is
	// also assigning its rank. 'user' when the caller says nothing, so the
	// panel's simplest form still works.
	role := in.Role
	if role == "" {
		role = domain.RoleUser
	}
	assigned, err := uc.postgres.GetRole(ctx, role)
	if err != nil {
		return Output{}, err
	}
	actor, err := uc.guard.Actor(ctx, in.ActorUserID)
	if err != nil {
		return Output{}, err
	}
	if err := roleguard.CanActOnRole(actor, assigned.Rank); err != nil {
		return Output{}, err
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return Output{}, fmt.Errorf("admin_user_create: hash: %w", err)
	}

	status := domain.UserStatus(in.Status)
	if status == "" {
		status = domain.StatusActive
	}

	user, err := uc.postgres.CreateUser(ctx, postgresadapter.CreateUserParams{
		Event:        &domain.OutboxEvent{Event: domain.EventUserCreated},
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		Role:         role,
		Status:       status,
	})
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserCreated, user.ID, in.IP,
		map[string]any{"role": user.Role, "status": string(user.Status)}))

	if user.Role != domain.RoleUser {
		uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionRoleAssigned, user.ID, in.IP,
			map[string]any{"role": user.Role}))
	}

	return Output{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		Status:    string(user.Status),
		CreatedAt: user.CreatedAt,
	}, nil
}

type Input struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Status   string `json:"status"`

	ActorUserID string `json:"-"`
	Actor       string `json:"-"`
	IP          string `json:"-"`
}

func (in *Input) Validate() error {
	if in.Password == "" {
		return domain.ErrPasswordTooWeak
	}
	switch domain.UserStatus(in.Status) {
	case "", domain.StatusActive, domain.StatusBlocked:
	default:
		return domain.ErrInvalidInput
	}
	return nil
}

type Output struct {
	ID        string    `json:"id"`
	Username  string    `json:"username,omitempty"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}
