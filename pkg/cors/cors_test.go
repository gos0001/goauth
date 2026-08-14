package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func router(t *testing.T, domains ...string) *gin.Engine {
	t.Helper()

	mw, err := New(Config{AllowDomains: domains, MaxAge: 12 * time.Hour})
	if err != nil {
		t.Fatalf("New(%v): %v", domains, err)
	}

	r := gin.New()
	r.Use(mw.Handler())
	r.POST("/auth/token", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func do(r *gin.Engine, method, path, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// The failure that makes an allowlist decoration: sending headers for an origin
// that is not on it.
func TestUnlistedOriginGetsNoHeaders(t *testing.T) {
	r := router(t, "https://app.example.com")

	w := do(r, http.MethodPost, "/auth/token", "https://evil.com")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q for an unlisted origin", got)
	}
	// The request itself still reaches the handler — CORS governs the browser,
	// not the server.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want the request to be served normally", w.Code)
	}
}

func TestAllowedOriginIsEchoedExactly(t *testing.T) {
	r := router(t, "https://app.example.com")

	w := do(r, http.MethodPost, "/auth/token", "https://app.example.com")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q — a shared cache could serve this to another origin", got)
	}
}

// Origins that merely contain an allowed one must not match. These are the
// shapes a naive strings.Contains implementation lets through.
func TestLookalikeOriginsAreRejected(t *testing.T) {
	r := router(t, "https://app.example.com")

	for _, origin := range []string{
		"https://app.example.com.evil.com",
		"https://evil.com/?x=https://app.example.com",
		"http://app.example.com", // different scheme, different origin
		"https://app.example.com:8443",
		"https://notapp.example.com",
	} {
		t.Run(origin, func(t *testing.T) {
			w := do(r, http.MethodPost, "/auth/token", origin)
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("Allow-Origin = %q for %s", got, origin)
			}
		})
	}
}

func TestWildcardSubdomain(t *testing.T) {
	r := router(t, "https://*.example.com")

	allowed := []string{"https://app.example.com", "https://a.b.example.com"}
	for _, origin := range allowed {
		if got := do(r, http.MethodPost, "/auth/token", origin).Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("%s was not allowed", origin)
		}
	}

	// The bare domain and a lookalike must not match — the second is the reason
	// the suffix keeps its leading dot.
	for _, origin := range []string{"https://example.com", "https://notexample.com", "http://a.example.com"} {
		if got := do(r, http.MethodPost, "/auth/token", origin).Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s was allowed by a *.example.com rule", origin)
		}
	}
}

func TestPreflight(t *testing.T) {
	r := router(t, "https://app.example.com")

	w := do(r, http.MethodOptions, "/auth/token", "https://app.example.com")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("no Allow-Methods on the preflight")
	}
	if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("no Allow-Headers — Authorization would be refused")
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got != "43200" {
		t.Errorf("Max-Age = %q, want 43200", got)
	}
	// The handler must not run: a preflight is not the request.
	if w.Body.Len() != 0 {
		t.Errorf("preflight reached the handler, body = %q", w.Body.String())
	}
}

func TestPreflightForUnlistedOriginRevealsNothing(t *testing.T) {
	r := router(t, "https://app.example.com")

	w := do(r, http.MethodOptions, "/auth/token", "https://evil.com")
	if w.Header().Get("Access-Control-Allow-Origin") != "" ||
		w.Header().Get("Access-Control-Allow-Methods") != "" {
		t.Fatal("the preflight answered an unlisted origin")
	}
}

func TestWildcardAllowsEverything(t *testing.T) {
	r := router(t, "*")

	w := do(r, http.MethodPost, "/auth/token", "https://anything.example.org")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Allow-Origin = %q, want *", got)
	}
	// With "*" the answer does not depend on the origin, so Vary is noise.
	if got := w.Header().Get("Vary"); got != "" {
		t.Errorf("Vary = %q, want none for a wildcard", got)
	}
}

func TestDisabledByDefault(t *testing.T) {
	r := router(t)

	w := do(r, http.MethodPost, "/auth/token", "https://app.example.com")
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q with no ALLOW_DOMAINS set", got)
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d — disabling CORS must not break the API itself", w.Code)
	}
}

func TestRequestWithoutOriginIsUntouched(t *testing.T) {
	r := router(t, "https://app.example.com")

	w := do(r, http.MethodPost, "/auth/token", "")
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("a non-browser request was given CORS headers")
	}
}

func TestConfigRejectsAmbiguousEntries(t *testing.T) {
	for _, entry := range []string{
		"example.com",                  // no scheme: http and https are different origins
		"ftp://example.com",            // not a browser origin
		"https://app.*.example.com",    // wildcard not in the leading label
		"https://example.com/callback", // an origin has no path
		"https://*.",                   // names no domain
	} {
		t.Run(entry, func(t *testing.T) {
			if _, _, err := parse([]string{entry}); err == nil {
				t.Fatalf("parse(%q) succeeded, want a startup error", entry)
			}
		})
	}
}

func TestConfigAcceptsValidEntries(t *testing.T) {
	for _, entry := range []string{
		"https://app.example.com",
		"http://localhost:3000",
		"https://*.example.com",
		"*",
		"https://app.example.com/", // a trailing slash is forgiven
	} {
		t.Run(entry, func(t *testing.T) {
			if _, _, err := parse([]string{entry}); err != nil {
				t.Fatalf("parse(%q): %v", entry, err)
			}
		})
	}
}

func TestOriginMatchingIsCaseInsensitive(t *testing.T) {
	r := router(t, "https://App.Example.com")

	if got := do(r, http.MethodPost, "/auth/token", "https://app.example.com").
		Header().Get("Access-Control-Allow-Origin"); got == "" {
		t.Fatal("host casing prevented a match; hosts are case-insensitive")
	}
}
