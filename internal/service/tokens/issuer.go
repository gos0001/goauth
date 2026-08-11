// Package tokens issues and rotates access/refresh pairs.
//
// This is a shared domain service rather than a use case: several use cases
// (login, refresh, register) all need to mint a pair, and duplicating the
// rotation rules across them is how those rules drift apart.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/pkg/token"
)

// refreshTokenBytes is the entropy of an opaque refresh token. Refresh tokens
// are random strings, not JWTs: they are checked against the database on every
// use, so they carry no claims and gain nothing from being self-describing.
const refreshTokenBytes = 32

type Store interface {
	CreateSession(ctx context.Context, p postgresadapter.CreateSessionParams) (domain.Session, error)
	RotateSession(ctx context.Context, presented []byte, next postgresadapter.CreateSessionParams) (domain.Session, error)
}

type Issuer struct {
	signer *token.Signer
	store  Store
}

func New(signer *token.Signer, pg *postgresadapter.Adapter) *Issuer {
	return &Issuer{signer: signer, store: pg}
}

// Pair is what a successful grant returns.
type Pair struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	ExpiresAt    time.Time
	SessionID    string
	FamilyID     string
}

// Context describes where the session is being created from, recorded for the
// "my devices" view and the audit trail.
type Context struct {
	IP        string
	UserAgent string
	AuthTime  time.Time
	Now       time.Time
}

// Issue starts a new session family. Used after a password is presented.
func (i *Issuer) Issue(ctx context.Context, user domain.User, c Context) (Pair, error) {
	familyID := uuid.NewString()

	refresh, hash, err := newRefreshToken()
	if err != nil {
		return Pair{}, err
	}

	session, err := i.store.CreateSession(ctx, postgresadapter.CreateSessionParams{
		UserID:      user.ID,
		FamilyID:    familyID,
		RefreshHash: hash,
		ExpiresAt:   c.Now.Add(i.signer.RefreshTTL()),
		IP:          c.IP,
		UserAgent:   c.UserAgent,
	})
	if err != nil {
		return Pair{}, fmt.Errorf("tokens: create session: %w", err)
	}

	return i.sign(user, session, refresh, c)
}

// Rotate spends the presented refresh token and issues its successor within the
// same family. The old token stops working the instant this returns.
func (i *Issuer) Rotate(ctx context.Context, presentedHash []byte, user domain.User, familyID string, c Context) (Pair, error) {
	refresh, hash, err := newRefreshToken()
	if err != nil {
		return Pair{}, err
	}

	session, err := i.store.RotateSession(ctx, presentedHash, postgresadapter.CreateSessionParams{
		UserID:      user.ID,
		FamilyID:    familyID,
		RefreshHash: hash,
		ExpiresAt:   c.Now.Add(i.signer.RefreshTTL()),
		IP:          c.IP,
		UserAgent:   c.UserAgent,
	})
	if err != nil {
		return Pair{}, err
	}

	return i.sign(user, session, refresh, c)
}

func (i *Issuer) sign(user domain.User, session domain.Session, refresh string, c Context) (Pair, error) {
	access, _, expiresAt, err := i.signer.Sign(user.ID, session.ID, user.IsAdmin, c.AuthTime, c.Now)
	if err != nil {
		return Pair{}, err
	}

	return Pair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(i.signer.AccessTTL().Seconds()),
		ExpiresAt:    expiresAt,
		SessionID:    session.ID,
		FamilyID:     session.FamilyID,
	}, nil
}

// HashRefresh is how a presented token is looked up. Only the digest is ever
// stored, so the database never holds anything that can be replayed.
func HashRefresh(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

func newRefreshToken() (string, []byte, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("tokens: read random: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashRefresh(raw), nil
}
