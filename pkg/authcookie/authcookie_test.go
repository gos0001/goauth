package authcookie

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func enabled() *Cookies {
	return New(Config{Enabled: true, Secure: true, SameSite: "strict"})
}

func setHeaders(ck *Cookies) []string {
	w := httptest.NewRecorder()
	ck.Set(w, "access-value", "refresh-value", 15*time.Minute, 720*time.Hour)
	return w.Header().Values("Set-Cookie")
}

func TestSetWritesBothCookiesWithAttributes(t *testing.T) {
	headers := setHeaders(enabled())
	if len(headers) != 2 {
		t.Fatalf("got %d Set-Cookie headers, want 2: %v", len(headers), headers)
	}

	access, refresh := headers[0], headers[1]
	if !strings.HasPrefix(access, AccessName+"=access-value;") {
		t.Errorf("access cookie = %q", access)
	}
	if !strings.HasPrefix(refresh, RefreshName+"=refresh-value;") {
		t.Errorf("refresh cookie = %q", refresh)
	}

	for name, header := range map[string]string{"access": access, "refresh": refresh} {
		for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
			if !strings.Contains(header, want) {
				t.Errorf("%s cookie %q missing %s", name, header, want)
			}
		}
		if strings.Contains(header, "Domain=") {
			t.Errorf("%s cookie %q sets a Domain — it must stay host-only", name, header)
		}
	}

	if !strings.Contains(access, "Max-Age=900") {
		t.Errorf("access cookie %q: Max-Age should be the 15-minute access TTL", access)
	}
	if !strings.Contains(refresh, "Max-Age=2592000") {
		t.Errorf("refresh cookie %q: Max-Age should be the 30-day refresh TTL", refresh)
	}
}

func TestLaxConfigIsHonoured(t *testing.T) {
	ck := New(Config{Enabled: true, Secure: true, SameSite: "lax"})

	for _, header := range setHeaders(ck) {
		if !strings.Contains(header, "SameSite=Lax") {
			t.Errorf("cookie %q: want SameSite=Lax", header)
		}
	}
}

// Disabled must mean nothing is written at all, not empty cookies — a stray
// Set-Cookie on every response would be a behaviour change nobody opted into.
func TestDisabledWritesNothing(t *testing.T) {
	ck := New(Config{Enabled: false})

	if headers := setHeaders(ck); len(headers) != 0 {
		t.Fatalf("disabled channel wrote %v", headers)
	}

	w := httptest.NewRecorder()
	ck.Clear(w)
	if headers := w.Header().Values("Set-Cookie"); len(headers) != 0 {
		t.Fatalf("disabled channel cleared %v", headers)
	}
}

func TestClearDeletesBothCookies(t *testing.T) {
	w := httptest.NewRecorder()
	enabled().Clear(w)

	headers := w.Header().Values("Set-Cookie")
	if len(headers) != 2 {
		t.Fatalf("got %d Set-Cookie headers, want 2: %v", len(headers), headers)
	}
	for _, header := range headers {
		if !strings.Contains(header, "Max-Age=0") {
			t.Errorf("clear header %q: want Max-Age=0", header)
		}
		for _, want := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
			if !strings.Contains(header, want) {
				t.Errorf("clear header %q missing %s — attributes must match Set", header, want)
			}
		}
	}
}

func TestFromRequestRoundTrip(t *testing.T) {
	ck := enabled()

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: AccessName, Value: "the-access"})
	req.AddCookie(&http.Cookie{Name: RefreshName, Value: "the-refresh"})

	if v, ok := ck.AccessFromRequest(req); !ok || v != "the-access" {
		t.Errorf("AccessFromRequest = %q, %v", v, ok)
	}
	if v, ok := ck.RefreshFromRequest(req); !ok || v != "the-refresh" {
		t.Errorf("RefreshFromRequest = %q, %v", v, ok)
	}
}

// The reason reads are gated on Enabled: a deployment that never turned the
// channel on must not have its cookies quietly become credentials.
func TestDisabledReadsNothing(t *testing.T) {
	ck := New(Config{Enabled: false})

	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: AccessName, Value: "the-access"})
	req.AddCookie(&http.Cookie{Name: RefreshName, Value: "the-refresh"})

	if _, ok := ck.AccessFromRequest(req); ok {
		t.Error("AccessFromRequest answered while disabled")
	}
	if _, ok := ck.RefreshFromRequest(req); ok {
		t.Error("RefreshFromRequest answered while disabled")
	}
}

func TestEmptyCookieValueIsNotACredential(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/token", nil)
	req.AddCookie(&http.Cookie{Name: AccessName, Value: ""})

	if _, ok := enabled().AccessFromRequest(req); ok {
		t.Error("an empty cookie value must not count as presented")
	}
}
