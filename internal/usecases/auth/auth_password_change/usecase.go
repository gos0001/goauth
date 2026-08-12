package auth_password_change

import (
	"context"
	"fmt"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/tokens"
	"github.com/gos0001/goauth/pkg/passwordhash"
)

type Postgres interface {
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	SetPasswordAndRevokeSessions(ctx context.Context, id, passwordHash string, mustChange bool, ev *domain.OutboxEvent) (domain.User, error)
}

type Hasher interface {
	Hash(password string) (string, error)
	Verify(encoded, password string) (bool, error)
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

// Execute changes the caller's own password.
//
// Every existing session is destroyed, including the one this request arrived
// on, and a fresh pair is returned. Changing a password is usually a response to
// "someone else may have my credentials", and a change that leaves the other
// party's sessions alive does not answer that. Returning a new pair means the
// caller is not logged out by their own security action.
func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	user, err := uc.postgres.GetUserByID(ctx, in.UserID)
	if err != nil {
		return Output{}, err
	}

	ok, err := uc.hasher.Verify(user.PasswordHash, in.CurrentPassword)
	if err != nil {
		return Output{}, fmt.Errorf("auth_password_change: verify current: %w", err)
	}
	if !ok {
		return Output{}, domain.ErrInvalidCredentials
	}

	if err := domain.ValidatePassword(in.NewPassword, uc.cfg.MinPasswordLength); err != nil {
		return Output{}, err
	}

	hash, err := uc.hasher.Hash(in.NewPassword)
	if err != nil {
		return Output{}, fmt.Errorf("auth_password_change: hash: %w", err)
	}

	ev := domain.OutboxEvent{Event: domain.EventUserPasswordChanged}
	updated, err := uc.postgres.SetPasswordAndRevokeSessions(ctx, user.ID, hash, false, &ev)
	if err != nil {
		return Output{}, err
	}

	now := time.Now()
	pair, err := uc.issuer.Issue(ctx, updated, tokens.Context{
		IP: in.IP, UserAgent: in.UserAgent, AuthTime: now, Now: now,
	})
	if err != nil {
		return Output{}, fmt.Errorf("auth_password_change: issue: %w", err)
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(user.ID), domain.ActionPasswordChanged, user.ID, in.IP, nil))

	return Output{
		AccessToken:  pair.AccessToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		ExpiresAt:    pair.ExpiresAt,
		RefreshToken: pair.RefreshToken,
	}, nil
}
