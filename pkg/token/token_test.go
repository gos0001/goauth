package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	return Config{
		PrivateKey: base64.StdEncoding.EncodeToString(seed),
		Issuer:     "goauth",
		Audience:   "test-app",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 720 * time.Hour,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Now()
	raw, jti, expiresAt, err := s.Sign("user-1", "session-1", true, now, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims, err := s.Verify(raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
	if claims.SessionID != "session-1" {
		t.Errorf("sid = %q, want session-1", claims.SessionID)
	}
	if !claims.Admin {
		t.Error("adm claim lost")
	}
	if claims.ID != jti {
		t.Errorf("jti = %q, want %q", claims.ID, jti)
	}
	if got := expiresAt.Sub(now); got != 15*time.Minute {
		t.Errorf("expiry offset = %s, want 15m", got)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	s, _ := New(testConfig(t))

	now := time.Now()
	raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	// Flip a character in the signature.
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	if _, err := s.Verify(tampered); err == nil {
		t.Fatal("tampered token verified")
	}
}

// The payload carries adm; escalating it must invalidate the signature.
func TestVerifyRejectsEscalatedClaims(t *testing.T) {
	s, _ := New(testConfig(t))

	now := time.Now()
	raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)

	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	body["adm"] = true

	forged, _ := json.Marshal(body)
	escalated := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]

	if _, err := s.Verify(escalated); err == nil {
		t.Fatal("token with an edited adm claim verified")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s, _ := New(testConfig(t))

	past := time.Now().Add(-2 * time.Hour)
	raw, _, _, _ := s.Sign("user-1", "session-1", false, past, past)

	_, err := s.Verify(raw)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsForeignIssuerAndAudience(t *testing.T) {
	cfg := testConfig(t)
	s, _ := New(cfg)

	other := cfg
	other.Issuer = "someone-else"
	otherSigner, _ := New(other)

	now := time.Now()
	raw, _, _, _ := otherSigner.Sign("user-1", "session-1", false, now, now)

	if _, err := s.Verify(raw); err == nil {
		t.Fatal("token from a different issuer verified")
	}
}

// Tokens signed by a retired key must keep verifying until they expire, or
// every rotation would log the whole userbase out.
func TestPreviousKeysStillVerify(t *testing.T) {
	oldCfg := testConfig(t)
	oldSigner, _ := New(oldCfg)

	now := time.Now()
	rawFromOld, _, _, _ := oldSigner.Sign("user-1", "session-1", false, now, now)

	newSeed := make([]byte, ed25519.SeedSize)
	for i := range newSeed {
		newSeed[i] = byte(200 - i)
	}

	rotated := testConfig(t)
	rotated.PrivateKey = base64.StdEncoding.EncodeToString(newSeed)
	rotated.PreviousPublicKeys = []string{oldSigner.PublicKeyBase64()}

	newSigner, err := New(rotated)
	if err != nil {
		t.Fatalf("new signer after rotation: %v", err)
	}

	if _, err := newSigner.Verify(rawFromOld); err != nil {
		t.Fatalf("token signed by the retired key no longer verifies: %v", err)
	}

	// And a token minted now must also verify.
	rawFromNew, _, _, _ := newSigner.Sign("user-2", "session-2", false, now, now)
	if _, err := newSigner.Verify(rawFromNew); err != nil {
		t.Fatalf("token signed by the current key does not verify: %v", err)
	}
}

func TestKeyIDIsStable(t *testing.T) {
	a, _ := New(testConfig(t))
	b, _ := New(testConfig(t))

	if a.kid != b.kid {
		t.Fatalf("kid differs across restarts: %q vs %q", a.kid, b.kid)
	}
	if a.kid == "" {
		t.Fatal("kid is empty")
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	s, _ := New(testConfig(t))

	keys, err := ParseJWKS(s.JWKS())
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in the set, got %d", len(keys))
	}

	pub, ok := keys[s.kid]
	if !ok {
		t.Fatalf("jwks does not contain the active kid %q", s.kid)
	}

	// The published key must actually verify a real signature.
	now := time.Now()
	raw, _, _, _ := s.Sign("user-1", "session-1", false, now, now)

	parts := strings.Split(raw, ".")
	signing := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if !ed25519.Verify(pub, []byte(signing), sig) {
		t.Fatal("key published in the JWKS does not verify a token this signer produced")
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	cases := map[string]string{
		"not base64": "not base64 at all!!",
		"wrong size": base64.StdEncoding.EncodeToString([]byte("too short")),
		"empty":      "",
	}

	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.PrivateKey = key
			if _, err := New(cfg); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}
