package authclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gos0001/goauth/pkg/token"
)

func signerWithSeed(t *testing.T, fill byte) *token.Signer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = fill + byte(i)
	}

	s, err := token.New(token.Config{
		PrivateKey: base64.StdEncoding.EncodeToString(seed),
		Issuer:     "goauth",
		Audience:   "my-app",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

// jwksServer serves whatever document the returned pointer currently holds and
// counts requests, so tests can observe caching and rotation behaviour.
func jwksServer(t *testing.T, doc *atomic.Pointer[[]byte]) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(*doc.Load())
	}))
	t.Cleanup(srv.Close)

	return srv, &hits
}

func verifier(t *testing.T, url string) *Verifier {
	t.Helper()

	v, err := New(Config{JWKSURL: url, Issuer: "goauth", Audience: "my-app"})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v
}

func TestVerifiesIssuedToken(t *testing.T) {
	s := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, _ := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	now := time.Now()
	raw, jti, _, err := s.Sign("user-1", "session-1", true, now, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", claims.UserID)
	}
	if claims.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want session-1", claims.SessionID)
	}
	if claims.TokenID != jti {
		t.Errorf("TokenID = %q, want %q", claims.TokenID, jti)
	}
	if !claims.Admin {
		t.Error("Admin flag lost")
	}
}

// The whole point of publishing a JWKS: consumers verify offline. goauth being
// unreachable must not invalidate tokens it already issued.
func TestVerifiesWithIssuerOffline(t *testing.T) {
	s := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, hits := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	now := time.Now()
	raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)

	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Take the issuer away entirely.
	srv.Close()
	before := hits.Load()

	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("verify %d with the issuer down: %v", i, err)
		}
	}

	if hits.Load() != before {
		t.Fatalf("the verifier called the issuer %d extra times; verification must be offline", hits.Load()-before)
	}
}

func TestKeySetIsCachedAcrossRequests(t *testing.T) {
	s := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, hits := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	now := time.Now()
	for i := 0; i < 10; i++ {
		raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("fetched the JWKS %d times for 10 verifications, want 1", got)
	}
}

// Rotation must need no coordination: an unknown kid triggers exactly one
// refresh, after which the new key works.
func TestUnknownKidTriggersRefresh(t *testing.T) {
	oldSigner := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := oldSigner.JWKS()
	doc.Store(&jwks)
	srv, hits := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	now := time.Now()
	rawOld, _, _, _ := oldSigner.Sign("user-1", "session-1", false, now, now)
	if _, err := v.Verify(context.Background(), rawOld); err != nil {
		t.Fatalf("verify with the original key: %v", err)
	}

	// goauth rotates; the retired key stays published.
	newSigner := signerWithSeed(t, 100)
	rotated, err := token.New(token.Config{
		PrivateKey:         base64.StdEncoding.EncodeToString(seedOf(t, 100)),
		PreviousPublicKeys: []string{oldSigner.PublicKeyBase64()},
		Issuer:             "goauth",
		Audience:           "my-app",
		AccessTTL:          15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotatedDoc := rotated.JWKS()
	doc.Store(&rotatedDoc)

	rawNew, _, _, _ := newSigner.Sign("user-2", "session-2", false, now, now)

	before := hits.Load()
	claims, err := v.Verify(context.Background(), rawNew)
	if err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if claims.UserID != "user-2" {
		t.Fatalf("UserID = %q, want user-2", claims.UserID)
	}
	if hits.Load() != before+1 {
		t.Fatalf("expected exactly one refresh on an unknown kid, got %d", hits.Load()-before)
	}

	// Tokens signed before the rotation must still verify.
	if _, err := v.Verify(context.Background(), rawOld); err != nil {
		t.Fatalf("token from before the rotation stopped verifying: %v", err)
	}
}

// A flood of tokens with bogus kids must not become a flood of requests to
// goauth.
func TestUnknownKidRefreshIsThrottled(t *testing.T) {
	s := signerWithSeed(t, 1)
	foreign := signerWithSeed(t, 50)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, hits := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	now := time.Now()
	rogue, _, _, _ := foreign.Sign("attacker", "session-x", true, now, now)

	for i := 0; i < 20; i++ {
		if _, err := v.Verify(context.Background(), rogue); err == nil {
			t.Fatal("a token signed by an unknown key verified")
		}
	}

	if got := hits.Load(); got > 2 {
		t.Fatalf("the issuer was hit %d times by 20 forged tokens; the refresh throttle is not working", got)
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	s := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, _ := jwksServer(t, &doc)

	v, err := New(Config{JWKSURL: srv.URL, Issuer: "goauth", Audience: "a-different-app"})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	now := time.Now()
	raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)

	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("a token minted for another audience verified")
	}
}

func TestRejectsExpiredAndMissing(t *testing.T) {
	s := signerWithSeed(t, 1)

	var doc atomic.Pointer[[]byte]
	jwks := s.JWKS()
	doc.Store(&jwks)
	srv, _ := jwksServer(t, &doc)

	v := verifier(t, srv.URL)

	past := time.Now().Add(-time.Hour)
	raw, _, _, _ := s.Sign("user-1", "session-1", false, past, past)

	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if _, err := v.Verify(context.Background(), ""); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("err = %v, want ErrMissingToken", err)
	}
}

func TestNewRequiresJWKSURL(t *testing.T) {
	if _, err := New(Config{Issuer: "goauth"}); err == nil {
		t.Fatal("expected an error when JWKSURL is empty")
	}
}

func seedOf(t *testing.T, fill byte) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = fill + byte(i)
	}
	return seed
}
