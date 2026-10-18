package middleware

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gos0001/goauth/pkg/authcookie"
	"github.com/gos0001/goauth/pkg/token"
)

func init() { gin.SetMode(gin.TestMode) }

func signer(t *testing.T, fill byte) *token.Signer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = fill + byte(i)
	}

	s, err := token.New(token.Config{
		PrivateKey: base64.StdEncoding.EncodeToString(seed),
		Issuer:     "goauth",
		Audience:   "goauth",
		AccessTTL:  15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

// guarded builds the admin chain as controller/http_v1 wires it, minus the
// database-backed AdminJWT step, which has its own concerns.
func guarded(t *testing.T, s *token.Signer) *gin.Engine {
	t.Helper()

	m := &Middleware{signer: s, logger: zap.NewNop().Sugar()}

	r := gin.New()
	r.GET("/admin/users", m.AuthSilent(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/auth/me", m.Auth(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func call(r *gin.Engine, path, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func mint(t *testing.T, s *token.Signer, issuedAt time.Time) string {
	t.Helper()
	raw, _, _, err := s.Sign("user-1", "session-1", true, issuedAt, issuedAt)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// The defect this exists for: an expired token used to be a bodiless 404, so a
// panel had no way to know it should refresh and simply stopped working.
func TestExpiredTokenOnAdminIsUnauthorized(t *testing.T) {
	s := signer(t, 1)
	r := guarded(t, s)

	expired := mint(t, s, time.Now().Add(-2*time.Hour))

	w := call(r, "/admin/users", expired)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a client keys its refresh on it", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Fatal("no body, so a client still cannot tell why it was refused")
	}
	if !contains(w.Body.String(), "expired") {
		t.Errorf("body = %s, want it to name expiry", w.Body.String())
	}
}

// The reason the 404 scheme exists. Widening it to 401 here would tell an
// ordinary user that the admin surface is real and they are simply not on it.
func TestValidNonExpiredTokenStillGetsNotFound(t *testing.T) {
	s := signer(t, 1)
	m := &Middleware{signer: s, logger: zap.NewNop().Sugar()}

	// AuthSilent admits a valid token; AdminJWT is what refuses a non-admin, so
	// the pairing is what must keep answering 404.
	r := gin.New()
	r.GET("/admin/users", m.AuthSilent(), func(c *gin.Context) {
		c.AbortWithStatus(http.StatusNotFound) // stands in for AdminJWT's refusal
	})

	w := call(r, "/admin/users", mint(t, s, time.Now()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a caller without rights", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want nothing to distinguish it from a missing route", w.Body.String())
	}
}

func TestEverythingElseStaysSilent(t *testing.T) {
	s := signer(t, 1)
	other := signer(t, 100)
	r := guarded(t, s)

	cases := map[string]string{
		"no token":    "",
		"garbage":     "not-a-jwt",
		"another key": mint(t, other, time.Now()),
		"truncated":   mint(t, s, time.Now())[:20],
	}

	for name, bearer := range cases {
		t.Run(name, func(t *testing.T) {
			w := call(r, "/admin/users", bearer)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", w.Code)
			}
			if w.Body.Len() != 0 {
				t.Errorf("body = %q, want none", w.Body.String())
			}
		})
	}
}

// The two surfaces must answer expiry the same way, so a client needs one rule.
func TestExpiryIsConsistentAcrossSurfaces(t *testing.T) {
	s := signer(t, 1)
	r := guarded(t, s)
	expired := mint(t, s, time.Now().Add(-2*time.Hour))

	admin := call(r, "/admin/users", expired)
	auth := call(r, "/auth/me", expired)

	if admin.Code != auth.Code {
		t.Fatalf("/admin/users = %d but /auth/me = %d", admin.Code, auth.Code)
	}
	if admin.Body.String() != auth.Body.String() {
		t.Errorf("bodies differ:\n  admin: %s\n  auth:  %s", admin.Body.String(), auth.Body.String())
	}
}

func TestValidTokenPasses(t *testing.T) {
	s := signer(t, 1)
	r := guarded(t, s)

	if w := call(r, "/admin/users", mint(t, s, time.Now())); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a valid token", w.Code)
	}
}

// --- cookie channel ---

func cookieChannel(t *testing.T, s *token.Signer, enabled bool) *gin.Engine {
	t.Helper()

	m := &Middleware{
		signer:  s,
		cookies: authcookie.New(authcookie.Config{Enabled: enabled, Secure: true, SameSite: "strict"}),
		logger:  zap.NewNop().Sugar(),
	}

	r := gin.New()
	r.GET("/admin/users", m.AuthSilent(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/auth/me", m.Auth(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func callWithCookie(r *gin.Engine, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Cookie", cookie)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAccessCookieAuthenticates(t *testing.T) {
	s := signer(t, 1)
	r := cookieChannel(t, s, true)

	w := callWithCookie(r, "/auth/me", authcookie.AccessName+"="+mint(t, s, time.Now()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the access cookie is a credential when the channel is on", w.Code)
	}

	// The silent surface must behave the same way: a panel that logged in via
	// cookies has no header to send either.
	if w := callWithCookie(r, "/admin/users", authcookie.AccessName+"="+mint(t, s, time.Now())); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 on the silent surface", w.Code)
	}
}

// A caller naming its credential in the header must not be refused because of
// what the browser attached — and must not be authenticated by it either.
func TestHeaderWinsOverCookie(t *testing.T) {
	s := signer(t, 1)
	other := signer(t, 100)
	r := cookieChannel(t, s, true)

	// A valid header alongside a wrong-key cookie: the header decides.
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+mint(t, s, time.Now()))
	req.Header.Set("Cookie", authcookie.AccessName+"="+mint(t, other, time.Now()))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the explicit credential has priority", w.Code)
	}
}

func TestCookieIgnoredWhenChannelDisabled(t *testing.T) {
	s := signer(t, 1)
	r := cookieChannel(t, s, false)

	w := callWithCookie(r, "/auth/me", authcookie.AccessName+"="+mint(t, s, time.Now()))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a disabled channel must not honour cookies", w.Code)
	}

	if w := callWithCookie(r, "/admin/users", authcookie.AccessName+"="+mint(t, s, time.Now())); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the silent 404", w.Code)
	}
}

// The expiry contract must hold whichever way the token was presented, or a
// cookie client cannot key its refresh on 401.
func TestExpiredCookieIsUnauthorizedOnBothSurfaces(t *testing.T) {
	s := signer(t, 1)
	r := cookieChannel(t, s, true)
	expired := authcookie.AccessName + "=" + mint(t, s, time.Now().Add(-2*time.Hour))

	admin := callWithCookie(r, "/admin/users", expired)
	auth := callWithCookie(r, "/auth/me", expired)

	if admin.Code != http.StatusUnauthorized || auth.Code != http.StatusUnauthorized {
		t.Fatalf("/admin/users = %d, /auth/me = %d, want both 401", admin.Code, auth.Code)
	}
	if admin.Body.String() != auth.Body.String() {
		t.Errorf("bodies differ:\n  admin: %s\n  auth:  %s", admin.Body.String(), auth.Body.String())
	}
}

func TestGarbageCookieIsNotACredential(t *testing.T) {
	s := signer(t, 1)
	r := cookieChannel(t, s, true)

	for _, value := range []string{"not-a-jwt", ""} {
		if w := callWithCookie(r, "/auth/me", authcookie.AccessName+"="+value); w.Code != http.StatusUnauthorized {
			t.Fatalf("cookie %q: status = %d, want 401", value, w.Code)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && stringIndex(haystack, needle) >= 0
}

func stringIndex(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
