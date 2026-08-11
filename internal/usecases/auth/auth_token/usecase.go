package auth_token

import (
	"context"
	"errors"
	"fmt"
	"time"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/audit"
	"github.com/gos0001/goauth/internal/service/tokens"
	"github.com/gos0001/goauth/pkg/passwordhash"
	"github.com/gos0001/goauth/pkg/ratelimit"
)

// ErrTooManyAttempts is returned while an account is inside its backoff window.
var ErrTooManyAttempts = errors.New("too many attempts")

type Postgres interface {
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	GetUserByID(ctx context.Context, id string) (domain.User, error)
	TouchUserLogin(ctx context.Context, id string) error

	GetSessionByRefreshHash(ctx context.Context, hash []byte) (domain.Session, error)
	DeleteSessionFamily(ctx context.Context, familyID string) (int, error)
}

type Hasher interface {
	Verify(encoded, password string) (bool, error)
	DummyVerify(password string)
}

type Limiter interface {
	Backoff(ctx context.Context, key string) (time.Duration, error)
	RegisterFailure(ctx context.Context, key string) (time.Duration, error)
	Reset(ctx context.Context, key string) error
}

type Auditor interface {
	Record(ctx context.Context, e domain.AuditEntry)
}

type Issuer interface {
	Issue(ctx context.Context, user domain.User, c tokens.Context) (tokens.Pair, error)
	Rotate(ctx context.Context, presentedHash []byte, user domain.User, familyID string, c tokens.Context) (tokens.Pair, error)
}

// Usecase issues token pairs. Both grants live here because they are one
// operation — exchange a credential for a session — reached through one
// endpoint; splitting them would put the dispatch in the controller, which is
// supposed to route and nothing else.
type Usecase struct {
	postgres Postgres
	issuer   Issuer
	hasher   Hasher
	limiter  Limiter
	auditor  Auditor
	cfg      Config
}

func New(
	pg *postgresadapter.Adapter,
	issuer *tokens.Issuer,
	hasher *passwordhash.Hasher,
	limiter *ratelimit.Limiter,
	auditor *audit.Recorder,
	cfg Config,
) *Usecase {
	return &Usecase{
		postgres: pg,
		issuer:   issuer,
		hasher:   hasher,
		limiter:  limiter,
		auditor:  auditor,
		cfg:      cfg,
	}
}

func (uc *Usecase) Execute(ctx context.Context, in Input) (Output, error) {
	now := time.Now()

	switch in.GrantType {
	case GrantPassword:
		return uc.passwordGrant(ctx, in, now)
	case GrantRefresh:
		return uc.refreshGrant(ctx, in, now)
	default:
		return Output{}, domain.ErrInvalidInput
	}
}

// passwordGrant resolves the identifier, verifies the password, and starts a
// new session family.
//
// Every failure path returns domain.ErrInvalidCredentials and performs the same
// argon2 work, so neither the response nor its timing reveals whether an account
// exists.
func (uc *Usecase) passwordGrant(ctx context.Context, in Input, now time.Time) (Output, error) {
	identifier, err := domain.NormalizeIdentifier(in.Identifier)
	if err != nil {
		uc.hasher.DummyVerify(in.Password)
		return Output{}, domain.ErrInvalidCredentials
	}

	// Backoff is keyed on the identifier rather than the resolved user id so an
	// attacker cannot probe whether the account exists by watching for it.
	if wait, err := uc.limiter.Backoff(ctx, "login:"+identifier); err != nil {
		if uc.cfg.FailClosed {
			return Output{}, fmt.Errorf("auth_token: backoff check: %w", err)
		}
	} else if wait > 0 {
		return Output{}, fmt.Errorf("%w: retry in %s", ErrTooManyAttempts, wait.Round(time.Second))
	}

	user, err := uc.lookup(ctx, identifier)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			uc.hasher.DummyVerify(in.Password)
			uc.penalise(ctx, identifier)
			uc.auditor.Record(ctx, audit.Event(domain.ActorSystem, domain.ActionUserLoginFailed, "", in.IP,
				map[string]any{"identifier": identifier, "reason": "unknown_identifier"}))
			return Output{}, domain.ErrInvalidCredentials
		}
		return Output{}, fmt.Errorf("auth_token: lookup: %w", err)
	}

	ok, err := uc.hasher.Verify(user.PasswordHash, in.Password)
	if err != nil {
		// A stored hash that cannot be parsed is an operational problem, not a
		// wrong password; surface it instead of silently locking the user out.
		return Output{}, fmt.Errorf("auth_token: verify password for %s: %w", user.ID, err)
	}
	if !ok {
		uc.penalise(ctx, identifier)
		uc.auditor.Record(ctx, audit.Event(domain.ActorUser(user.ID), domain.ActionUserLoginFailed, user.ID, in.IP,
			map[string]any{"reason": "bad_password"}))
		return Output{}, domain.ErrInvalidCredentials
	}

	// Status is checked only after the password verifies. Rejecting a blocked
	// account earlier would turn the endpoint into an account-status oracle.
	if err := statusError(user); err != nil {
		return Output{}, err
	}

	pair, err := uc.issuer.Issue(ctx, user, tokens.Context{
		IP: in.IP, UserAgent: in.UserAgent, AuthTime: now, Now: now,
	})
	if err != nil {
		return Output{}, fmt.Errorf("auth_token: issue: %w", err)
	}

	_ = uc.limiter.Reset(ctx, "login:"+identifier)
	if err := uc.postgres.TouchUserLogin(ctx, user.ID); err != nil {
		return Output{}, fmt.Errorf("auth_token: touch login: %w", err)
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(user.ID), domain.ActionUserLogin, user.ID, in.IP, nil))

	return output(pair, user), nil
}

// refreshGrant rotates a refresh token.
//
// Presenting a token that was already spent means two parties hold it, so the
// whole family is destroyed rather than just the presented link. That is the
// only signal available that a refresh token leaked.
func (uc *Usecase) refreshGrant(ctx context.Context, in Input, now time.Time) (Output, error) {
	hash := tokens.HashRefresh(in.RefreshToken)

	session, err := uc.postgres.GetSessionByRefreshHash(ctx, hash)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return Output{}, domain.ErrSessionNotFound
		}
		return Output{}, fmt.Errorf("auth_token: load session: %w", err)
	}

	if session.Spent() {
		if _, delErr := uc.postgres.DeleteSessionFamily(ctx, session.FamilyID); delErr != nil {
			return Output{}, fmt.Errorf("auth_token: destroy reused family: %w", delErr)
		}
		uc.auditor.Record(ctx, audit.Event(domain.ActorSystem, domain.ActionRefreshReuse, session.UserID, in.IP,
			map[string]any{"family_id": session.FamilyID}))
		return Output{}, domain.ErrRefreshReused
	}

	if session.Expired(now) {
		return Output{}, domain.ErrSessionExpired
	}

	user, err := uc.postgres.GetUserByID(ctx, session.UserID)
	if err != nil {
		return Output{}, fmt.Errorf("auth_token: load user: %w", err)
	}
	if err := statusError(user); err != nil {
		return Output{}, err
	}

	pair, err := uc.issuer.Rotate(ctx, hash, user, session.FamilyID, tokens.Context{
		IP: in.IP, UserAgent: in.UserAgent,
		// AuthTime is carried from the original login, not reset: rotating a
		// token is not re-authentication, and sudo-mode must not be renewable
		// without the password.
		AuthTime: session.CreatedAt, Now: now,
	})
	if err != nil {
		if errors.Is(err, domain.ErrRefreshReused) {
			// Lost the race against a concurrent rotation — same conclusion.
			if _, delErr := uc.postgres.DeleteSessionFamily(ctx, session.FamilyID); delErr != nil {
				return Output{}, fmt.Errorf("auth_token: destroy raced family: %w", delErr)
			}
			return Output{}, domain.ErrRefreshReused
		}
		return Output{}, fmt.Errorf("auth_token: rotate: %w", err)
	}

	uc.auditor.Record(ctx, audit.Event(domain.ActorUser(user.ID), domain.ActionTokenRefreshed, user.ID, in.IP, nil))

	return output(pair, user), nil
}

func (uc *Usecase) lookup(ctx context.Context, identifier string) (domain.User, error) {
	if domain.LooksLikeEmail(identifier) {
		return uc.postgres.GetUserByEmail(ctx, identifier)
	}
	return uc.postgres.GetUserByUsername(ctx, identifier)
}

func (uc *Usecase) penalise(ctx context.Context, identifier string) {
	// A limiter failure must not mask the authentication failure that caused
	// it; the IP-level limiter in the middleware is the backstop.
	_, _ = uc.limiter.RegisterFailure(ctx, "login:"+identifier)
}

func statusError(u domain.User) error {
	switch u.Status {
	case domain.StatusBlocked:
		return domain.ErrUserBlocked
	case domain.StatusDeleted:
		return domain.ErrUserDeleted
	default:
		return nil
	}
}

func output(p tokens.Pair, u domain.User) Output {
	return Output{
		AccessToken:        p.AccessToken,
		TokenType:          p.TokenType,
		ExpiresIn:          p.ExpiresIn,
		ExpiresAt:          p.ExpiresAt,
		RefreshToken:       p.RefreshToken,
		MustChangePassword: u.MustChangePassword,
		User:               viewOf(u),
	}
}
