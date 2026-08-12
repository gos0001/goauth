package auth_register

import (
	"context"
	"fmt"
	"strings"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/tokens"
	"github.com/gos0001/goauth/pkg/passwordhash"
)

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
	issuer   *tokens.Issuer
	hasher   Hasher
	auditor  Auditor
	cfg      Config
}

func New(
	pg *postgresadapter.Adapter,
	issuer *tokens.Issuer,
	hasher *passwordhash.Hasher,
	auditor *audit.Recorder,
	cfg Config,
) *Usecase {
	return &Usecase{postgres: pg, issuer: issuer, hasher: hasher, auditor: auditor, cfg: cfg}
}

// Execute creates a self-service account and logs it straight in.
//
// The new account has no admin flag and no product entitlements — those live in
// the consuming service. An account that can authenticate but do nothing is the
// intended outcome, not an oversight: identity and authorisation are separate
// concerns, and a fresh identity simply has no grants yet.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	if !uc.cfg.Open() {
		return Output{}, domain.ErrRegistrationClosed
	}

	username, email, err := uc.identifiers(in)
	if err != nil {
		return Output{}, err
	}

	if err := domain.ValidatePassword(in.Password, uc.cfg.MinPasswordLength); err != nil {
		return Output{}, err
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return Output{}, fmt.Errorf("auth_register: hash password: %w", err)
	}

	user, err := uc.postgres.CreateUser(ctx, postgresadapter.CreateUserParams{
		Event:        &domain.OutboxEvent{Event: domain.EventUserCreated},
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		IsAdmin:      false,
		Status:       domain.StatusActive,
	})
	if err != nil {
		return Output{}, err
	}

	now := time.Now()
	pair, err := uc.issuer.Issue(ctx, user, tokens.Context{
		IP: in.IP, UserAgent: in.UserAgent, AuthTime: now, Now: now,
	})
	if err != nil {
		return Output{}, fmt.Errorf("auth_register: issue: %w", err)
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(user.ID), domain.ActionUserRegistered, user.ID, in.IP, nil))

	return Output{
		AccessToken:  pair.AccessToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		ExpiresAt:    pair.ExpiresAt,
		RefreshToken: pair.RefreshToken,
		User: UserView{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			IsAdmin:  user.IsAdmin,
		},
	}, nil
}

func (uc *Usecase) identifiers(in Input) (username, email string, err error) {
	hasUsername := strings.TrimSpace(in.Username) != ""
	hasEmail := strings.TrimSpace(in.Email) != ""

	if !hasUsername && !hasEmail {
		return "", "", domain.ErrNoIdentifier
	}
	if uc.cfg.RequireEmail && !hasEmail {
		return "", "", domain.ErrNoIdentifier
	}

	if hasUsername {
		if username, err = domain.NormalizeUsername(in.Username); err != nil {
			return "", "", err
		}
	}
	if hasEmail {
		if email, err = domain.NormalizeEmail(in.Email); err != nil {
			return "", "", err
		}
	}

	return username, email, nil
}
