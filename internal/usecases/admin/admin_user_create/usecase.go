package admin_user_create

import (
	"context"
	"fmt"
	"strings"
	"time"

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

// Execute provisions an account on someone's behalf. This is how users are
// created when registration is closed — by an operator, or by a payment webhook
// calling the private port after a purchase.
//
// MustChangePassword defaults to true: the operator knows the password they
// just set, so leaving it in place would mean an account whose credentials two
// people hold.
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

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return Output{}, fmt.Errorf("admin_user_create: hash: %w", err)
	}

	status := domain.UserStatus(in.Status)
	if status == "" {
		status = domain.StatusActive
	}

	user, err := uc.postgres.CreateUser(ctx, postgresadapter.CreateUserParams{
		Event:              &domain.OutboxEvent{Event: domain.EventUserCreated},
		Username:           username,
		Email:              email,
		PasswordHash:       hash,
		IsAdmin:            in.IsAdmin,
		Status:             status,
		MustChangePassword: in.MustChangePassword,
	})
	if err != nil {
		return Output{}, err
	}

	uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionUserCreated, user.ID, in.IP,
		map[string]any{"is_admin": user.IsAdmin, "status": string(user.Status)}))

	if user.IsAdmin {
		uc.auditor.Record(ctx, audit.Event(in.Actor, domain.ActionAdminGranted, user.ID, in.IP, nil))
	}

	return Output{
		ID:                 user.ID,
		Username:           user.Username,
		Email:              user.Email,
		IsAdmin:            user.IsAdmin,
		Status:             string(user.Status),
		MustChangePassword: user.MustChangePassword,
		CreatedAt:          user.CreatedAt,
	}, nil
}

type Input struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
	Status   string `json:"status"`

	// MustChangePassword is a pointer so an explicit false is distinguishable
	// from an omitted field; omitted means true.
	MustChangePassword bool  `json:"-"`
	RawMustChange      *bool `json:"must_change_password"`

	Actor string `json:"-"`
	IP    string `json:"-"`
}

func (in *Input) Validate() error {
	in.MustChangePassword = true
	if in.RawMustChange != nil {
		in.MustChangePassword = *in.RawMustChange
	}

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
	ID                 string    `json:"id"`
	Username           string    `json:"username,omitempty"`
	Email              string    `json:"email,omitempty"`
	IsAdmin            bool      `json:"is_admin"`
	Status             string    `json:"status"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
}
