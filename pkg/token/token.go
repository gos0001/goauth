// Package token signs and verifies access tokens with Ed25519 (JWT alg EdDSA)
// and publishes the matching public keys as a JWKS.
//
// Asymmetric on purpose. With a symmetric algorithm every service that can
// verify a token can also mint one, so a single compromised consumer forges any
// identity, and rotating the secret means redeploying everything at once. Here
// goauth holds the only private key and consumers verify offline against the
// published public key.
//
// Zero domain imports.
package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("token: invalid")
	ErrExpired      = errors.New("token: expired")
	ErrUnknownKey   = errors.New("token: unknown key id")
)

// Claims is deliberately thin. Nothing that changes independently of the login
// belongs here: a token cannot be revoked before it expires, so any claim it
// carries is authoritative for up to AccessTTL after it stopped being true.
type Claims struct {
	// SessionID ties the access token to the refresh session that minted it,
	// so revoking the session can be enforced where it matters.
	SessionID string `json:"sid"`

	// Admin is a hint for the frontend — it decides whether to render the user
	// management screens. It is NOT an authorisation decision: goauth's own
	// admin middleware re-reads is_admin from the database, because a demoted
	// admin would otherwise keep power until this token expired.
	Admin bool `json:"adm"`

	// AuthTime is when the password was last presented, used for the sudo-mode
	// re-authentication window on destructive admin operations.
	AuthTime int64 `json:"auth_time"`

	jwt.RegisteredClaims
}

type Signer struct {
	cfg Config

	priv ed25519.PrivateKey
	kid  string

	// verifyKeys holds the active key plus every retired public key, indexed by
	// kid, so tokens issued before a rotation keep verifying until they expire.
	verifyKeys map[string]ed25519.PublicKey

	jwks []byte
}

func New(cfg Config) (*Signer, error) {
	seed, err := decodeKey(cfg.PrivateKey, ed25519.SeedSize, "JWT_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	s := &Signer{
		cfg:        cfg,
		priv:       priv,
		kid:        KeyID(pub),
		verifyKeys: map[string]ed25519.PublicKey{KeyID(pub): pub},
	}

	pubs := []ed25519.PublicKey{pub}
	for i, raw := range cfg.PreviousPublicKeys {
		if raw == "" {
			continue
		}
		b, err := decodeKey(raw, ed25519.PublicKeySize, fmt.Sprintf("JWT_PREVIOUS_PUBLIC_KEYS[%d]", i))
		if err != nil {
			return nil, err
		}
		old := ed25519.PublicKey(b)
		s.verifyKeys[KeyID(old)] = old
		pubs = append(pubs, old)
	}

	s.jwks, err = buildJWKS(pubs)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// KeyID derives the kid from the public key itself, so it can never drift from
// the key it names and needs no separate configuration.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func (s *Signer) AccessTTL() time.Duration  { return s.cfg.AccessTTL }
func (s *Signer) RefreshTTL() time.Duration { return s.cfg.RefreshTTL }
func (s *Signer) JWKS() []byte              { return s.jwks }

// PublicKeyBase64 is what an operator copies into JWT_PREVIOUS_PUBLIC_KEYS when
// rotating to a new signing key.
func (s *Signer) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))
}

// Sign issues an access token for a user and session.
func (s *Signer) Sign(userID, sessionID string, admin bool, authTime time.Time, now time.Time) (string, string, time.Time, error) {
	jti := uuid.NewString()
	expiresAt := now.Add(s.cfg.AccessTTL)

	claims := Claims{
		SessionID: sessionID,
		Admin:     admin,
		AuthTime:  authTime.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = s.kid

	signed, err := tok.SignedString(s.priv)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("token: sign: %w", err)
	}

	return signed, jti, expiresAt, nil
}

// Verify checks signature, issuer, audience and expiry, selecting the key by
// the token's kid header.
func (s *Signer) Verify(raw string) (Claims, error) {
	var claims Claims

	_, err := jwt.ParseWithClaims(raw, &claims, s.keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithAudience(s.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return Claims{}, ErrExpired
		case errors.Is(err, ErrUnknownKey):
			return Claims{}, ErrUnknownKey
		default:
			return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
	}

	return claims, nil
}

func (s *Signer) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if key, ok := s.verifyKeys[kid]; ok {
		return key, nil
	}
	return nil, ErrUnknownKey
}

func decodeKey(raw string, want int, name string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Tolerate the URL-safe alphabet too — operators paste both.
		b, err = base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("token: %s is not valid base64: %w", name, err)
		}
	}
	if len(b) != want {
		return nil, fmt.Errorf("token: %s must decode to %d bytes, got %d", name, want, len(b))
	}
	return b, nil
}
