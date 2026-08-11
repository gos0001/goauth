package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/gos0001/goauth/internal/adapter/postgres/generated"
	"github.com/gos0001/goauth/internal/domain"
)

type CreateSessionParams struct {
	UserID   string
	FamilyID string

	// RefreshHash is the SHA-256 of the token. The token itself never reaches
	// this package, so a database dump does not hand over live sessions.
	RefreshHash []byte

	ExpiresAt time.Time
	IP        string
	UserAgent string
}

func (a *Adapter) CreateSession(ctx context.Context, p CreateSessionParams) (domain.Session, error) {
	userID, err := uuid.Parse(p.UserID)
	if err != nil {
		return domain.Session{}, domain.ErrUserNotFound
	}
	familyID, err := uuid.Parse(p.FamilyID)
	if err != nil {
		return domain.Session{}, domain.ErrInvalidInput
	}

	row, err := a.q.CreateSession(ctx, generated.CreateSessionParams{
		UserID:      userID,
		FamilyID:    familyID,
		RefreshHash: p.RefreshHash,
		ExpiresAt:   ts(p.ExpiresAt),
		Ip:          text(p.IP),
		UserAgent:   text(p.UserAgent),
	})
	if err != nil {
		return domain.Session{}, MapError(err, nil)
	}
	return toDomainSession(row), nil
}

func (a *Adapter) GetSessionByID(ctx context.Context, id string) (domain.Session, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return domain.Session{}, domain.ErrSessionNotFound
	}

	row, err := a.q.GetSessionByID(ctx, parsed)
	if err != nil {
		return domain.Session{}, MapError(err, domain.ErrSessionNotFound)
	}
	return toDomainSession(row), nil
}

func (a *Adapter) GetSessionByRefreshHash(ctx context.Context, hash []byte) (domain.Session, error) {
	row, err := a.q.GetSessionByRefreshHash(ctx, hash)
	if err != nil {
		return domain.Session{}, MapError(err, domain.ErrSessionNotFound)
	}
	return toDomainSession(row), nil
}

// RotateSession spends the presented token and issues its successor inside one
// transaction, keyed on the same family.
//
// SpendSession's WHERE clause is the concurrency guard: it only matches a row
// that is still unused and unexpired. Two requests racing with the same token
// therefore produce exactly one winner, and the loser sees ErrRefreshReused —
// which is the correct reading, since a token in two places at once is a leaked
// token whether the second holder is an attacker or a retry.
func (a *Adapter) RotateSession(ctx context.Context, presented []byte, next CreateSessionParams) (domain.Session, error) {
	userID, err := uuid.Parse(next.UserID)
	if err != nil {
		return domain.Session{}, domain.ErrUserNotFound
	}
	familyID, err := uuid.Parse(next.FamilyID)
	if err != nil {
		return domain.Session{}, domain.ErrInvalidInput
	}

	var out domain.Session
	err = a.withTx(ctx, func(q *generated.Queries) error {
		if _, err := q.SpendSession(ctx, presented); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrRefreshReused
			}
			return MapError(err, nil)
		}

		row, err := q.CreateSession(ctx, generated.CreateSessionParams{
			UserID:      userID,
			FamilyID:    familyID,
			RefreshHash: next.RefreshHash,
			ExpiresAt:   ts(next.ExpiresAt),
			Ip:          text(next.IP),
			UserAgent:   text(next.UserAgent),
		})
		if err != nil {
			return MapError(err, nil)
		}

		out = toDomainSession(row)
		return nil
	})
	if err != nil {
		return domain.Session{}, err
	}
	return out, nil
}

// DeleteSessionFamily destroys every session descended from one login. Called
// when a spent refresh token is presented again.
func (a *Adapter) DeleteSessionFamily(ctx context.Context, familyID string) (int, error) {
	parsed, err := uuid.Parse(familyID)
	if err != nil {
		return 0, domain.ErrSessionNotFound
	}
	n, err := a.q.DeleteSessionFamily(ctx, parsed)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

func (a *Adapter) DeleteSession(ctx context.Context, id string) (int, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return 0, domain.ErrSessionNotFound
	}
	n, err := a.q.DeleteSession(ctx, parsed)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

func (a *Adapter) DeleteUserSessions(ctx context.Context, userID string) (int, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return 0, domain.ErrUserNotFound
	}
	n, err := a.q.DeleteUserSessions(ctx, parsed)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

func (a *Adapter) ListLiveUserSessions(ctx context.Context, userID string) ([]domain.Session, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	rows, err := a.q.ListLiveUserSessions(ctx, parsed)
	if err != nil {
		return nil, MapError(err, nil)
	}

	out := make([]domain.Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, toDomainSession(row))
	}
	return out, nil
}

func (a *Adapter) DeleteExpiredSessions(ctx context.Context) (int, error) {
	n, err := a.q.DeleteExpiredSessions(ctx)
	if err != nil {
		return 0, MapError(err, nil)
	}
	return int(n), nil
}

func toDomainSession(r generated.GaSession) domain.Session {
	return domain.Session{
		ID:        uuidText(r.ID),
		UserID:    uuidText(r.UserID),
		FamilyID:  uuidText(r.FamilyID),
		UsedAt:    tsOutPtr(r.UsedAt),
		ExpiresAt: tsOut(r.ExpiresAt),
		IP:        textOut(r.Ip),
		UserAgent: textOut(r.UserAgent),
		CreatedAt: tsOut(r.CreatedAt),
	}
}
