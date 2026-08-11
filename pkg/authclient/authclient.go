// Package authclient verifies goauth-issued tokens inside a consuming service.
//
// This is the only coupling a consumer needs. It fetches the JWKS once, caches
// it by key id, and verifies offline from then on — no per-request call back to
// goauth, and goauth being unreachable does not invalidate tokens already
// issued. Key rotation needs no coordination: a token names its key in the kid
// header, and a kid never seen before triggers a single refresh.
//
// Consumers store the user id as a plain column. They do not foreign-key into
// goauth's tables, and they keep their own product roles and subscriptions —
// this package answers "who is calling", never "what may they do".
package authclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gos0001/goauth/pkg/token"
)

var (
	ErrMissingToken = errors.New("authclient: missing bearer token")
	ErrInvalidToken = errors.New("authclient: invalid token")
	ErrExpired      = errors.New("authclient: token expired")
)

type Config struct {
	// JWKSURL is goauth's published key set, e.g.
	// https://auth.example.com/.well-known/jwks.json
	JWKSURL string

	// Issuer and Audience must match what goauth is configured to mint.
	// Verifying them is what stops a token issued for another deployment — or
	// another audience within the same one — from being accepted here.
	Issuer   string
	Audience string

	// RefreshInterval bounds how stale the cached key set may get in the
	// absence of any signal. Rotation does not wait for it: an unrecognised kid
	// refreshes immediately.
	RefreshInterval time.Duration

	// MaxRefreshPerMinute caps refreshes triggered by unrecognised kids, so a
	// stream of forged tokens carrying random kids cannot be turned into a
	// stream of requests to goauth.
	MaxRefreshPerMinute int

	// MaxUnknownKids bounds the memo of kids already established as unknown.
	// Without a bound, the memo would itself be an unbounded allocation driven
	// by attacker input.
	MaxUnknownKids int

	HTTPClient *http.Client
}

func (c *Config) applyDefaults() {
	if c.RefreshInterval == 0 {
		c.RefreshInterval = time.Hour
	}
	if c.MaxRefreshPerMinute == 0 {
		c.MaxRefreshPerMinute = 10
	}
	if c.MaxUnknownKids == 0 {
		c.MaxUnknownKids = 256
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
}

// Claims is what a verified token carries.
type Claims struct {
	UserID    string
	SessionID string
	TokenID   string

	// Admin reflects goauth's own admin flag at the time the token was minted.
	// Treat it as a hint for rendering, not as an authorisation decision: the
	// token cannot be revoked before it expires, so a demoted admin still
	// carries a true value here until then.
	Admin bool

	ExpiresAt time.Time
	IssuedAt  time.Time
}

type Verifier struct {
	cfg Config

	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time

	// unknownKids remembers kids a refresh already failed to explain, so a
	// repeated forged token costs nothing after the first.
	unknownKids map[string]struct{}

	windowStart   time.Time
	windowRefresh int
}

func New(cfg Config) (*Verifier, error) {
	if cfg.JWKSURL == "" {
		return nil, errors.New("authclient: JWKSURL is required")
	}
	cfg.applyDefaults()

	return &Verifier{
		cfg:         cfg,
		keys:        map[string]ed25519.PublicKey{},
		unknownKids: map[string]struct{}{},
	}, nil
}

// Verify checks a raw token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if raw == "" {
		return Claims{}, ErrMissingToken
	}

	kid, err := peekKeyID(raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Cold start, or the cached set has aged out.
	if v.needsInitialFetch() {
		if err := v.refresh(ctx); err != nil && !v.hasAnyKey() {
			return Claims{}, err
		}
	}

	if !v.hasKey(kid) {
		if !v.mayRefreshFor(kid) {
			return Claims{}, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
		}
		if err := v.refresh(ctx); err != nil {
			return Claims{}, err
		}
		if !v.hasKey(kid) {
			v.rememberUnknown(kid)
			return Claims{}, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
		}
	}

	return v.parse(raw)
}

func (v *Verifier) parse(raw string) (Claims, error) {
	var parsed jwtClaims

	_, err := jwt.ParseWithClaims(raw, &parsed, v.keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Claims{}, ErrExpired
		}
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	out := Claims{
		UserID:    parsed.Subject,
		SessionID: parsed.SessionID,
		TokenID:   parsed.ID,
		Admin:     parsed.Admin,
	}
	if parsed.ExpiresAt != nil {
		out.ExpiresAt = parsed.ExpiresAt.Time
	}
	if parsed.IssuedAt != nil {
		out.IssuedAt = parsed.IssuedAt.Time
	}

	return out, nil
}

type jwtClaims struct {
	SessionID string `json:"sid"`
	Admin     bool   `json:"adm"`
	jwt.RegisteredClaims
}

func (v *Verifier) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)

	v.mu.RLock()
	key, ok := v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, token.ErrUnknownKey
	}
	return key, nil
}

// peekKeyID reads the kid from the unverified header. Reading an unverified
// header is safe here because the value is only used to *select* a key — the
// signature check that follows is what decides whether the token is genuine.
func peekKeyID(raw string) (string, error) {
	head, _, ok := strings.Cut(raw, ".")
	if !ok || head == "" {
		return "", errors.New("malformed token")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return "", errors.New("malformed token header")
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(decoded, &header); err != nil {
		return "", errors.New("malformed token header")
	}
	if header.Kid == "" {
		return "", errors.New("token has no key id")
	}

	return header.Kid, nil
}

func (v *Verifier) hasKey(kid string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.keys[kid]
	return ok
}

func (v *Verifier) hasAnyKey() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys) > 0
}

func (v *Verifier) needsInitialFetch() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys) == 0 || time.Since(v.fetchedAt) >= v.cfg.RefreshInterval
}

// mayRefreshFor decides whether an unrecognised kid is worth a network call.
// A kid already proven unknown never is; otherwise the per-minute budget
// applies.
func (v *Verifier) mayRefreshFor(kid string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, known := v.unknownKids[kid]; known {
		return false
	}

	now := time.Now()
	if now.Sub(v.windowStart) >= time.Minute {
		v.windowStart = now
		v.windowRefresh = 0
	}
	if v.windowRefresh >= v.cfg.MaxRefreshPerMinute {
		return false
	}
	v.windowRefresh++

	return true
}

func (v *Verifier) rememberUnknown(kid string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Bounded: drop the whole memo rather than grow without limit. Losing it
	// costs at most one extra fetch per kid, and the per-minute budget still
	// applies.
	if len(v.unknownKids) >= v.cfg.MaxUnknownKids {
		v.unknownKids = map[string]struct{}{}
	}
	v.unknownKids[kid] = struct{}{}
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("authclient: build jwks request: %w", err)
	}

	res, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authclient: fetch jwks: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("authclient: jwks returned %s", res.Status)
	}

	// Bounded read: a misconfigured URL pointing at something huge must not
	// exhaust the consumer's memory.
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("authclient: read jwks: %w", err)
	}

	keys, err := token.ParseJWKS(body)
	if err != nil {
		return err
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	// Keys that were unknown may have just arrived; forget the memo so a
	// rotated-in kid is not rejected from cache.
	v.unknownKids = map[string]struct{}{}
	v.mu.Unlock()

	return nil
}
