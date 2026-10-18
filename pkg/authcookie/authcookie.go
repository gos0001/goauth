// Package authcookie carries the browser credential channel: when enabled,
// token responses are accompanied by HttpOnly cookies holding the same tokens
// the JSON body returns, so a browser frontend never needs to keep a refresh
// token in JavaScript-readable storage.
//
// Worth being clear about what this buys: a script injected into the frontend
// can no longer exfiltrate the refresh token, but it can still drive the
// session from inside the browser while it runs. Cookies contain the blast
// radius of an XSS, they do not prevent one — a Content-Security-Policy on the
// frontend does that.
//
// The package is mechanism only. Whether and when cookies are written is the
// calling handlers' policy; every method here is a no-op or an empty answer
// while the channel is disabled, so callers need no branching of their own.
//
// Zero domain imports.
package authcookie

import (
	"net/http"
	"time"
)

// Cookie names, fixed rather than configurable. They are part of the surface a
// browser frontend codes against, and a deployment renaming them gains nothing
// except a frontend that no longer logs in.
const (
	AccessName  = "goauth_access"
	RefreshName = "goauth_refresh"
)

// Cookies writes and reads the credential cookies. Construct it once; it holds
// nothing mutable.
type Cookies struct {
	cfg Config
}

func New(cfg Config) *Cookies {
	return &Cookies{cfg: cfg}
}

// Enabled reports whether the cookie channel is on.
func (ck *Cookies) Enabled() bool { return ck.cfg.Enabled }

// Set writes both credential cookies: HttpOnly, Secure, SameSite, Path=/. No
// Domain is set, so the cookies are host-only and never leak to a parent or a
// sibling — a cookie that names a domain is readable from every subdomain of
// it. Max-Age matches the token lifetimes, so a browser forgets a dead token
// on its own schedule.
func (ck *Cookies) Set(w http.ResponseWriter, access, refresh string, accessTTL, refreshTTL time.Duration) {
	if !ck.cfg.Enabled {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     AccessName,
		Value:    access,
		Path:     "/",
		MaxAge:   int(accessTTL / time.Second),
		HttpOnly: true,
		Secure:   ck.cfg.Secure,
		SameSite: ck.sameSite(),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshName,
		Value:    refresh,
		Path:     "/",
		MaxAge:   int(refreshTTL / time.Second),
		HttpOnly: true,
		Secure:   ck.cfg.Secure,
		SameSite: ck.sameSite(),
	})
}

// Clear deletes both cookies. The attributes match Set because a browser
// replaces a cookie only for the same name, path and domain — a bare
// name alone would leave the real cookie in place.
func (ck *Cookies) Clear(w http.ResponseWriter) {
	if !ck.cfg.Enabled {
		return
	}

	for _, name := range []string{AccessName, RefreshName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   ck.cfg.Secure,
			SameSite: ck.sameSite(),
		})
	}
}

// AccessFromRequest reads the access cookie — the fallback the auth
// middleware uses when no Authorization header was presented. Empty answer
// while the channel is disabled: an opt-in feature must not start accepting
// credentials it promised never to read.
func (ck *Cookies) AccessFromRequest(r *http.Request) (string, bool) {
	if !ck.cfg.Enabled {
		return "", false
	}
	return read(r, AccessName)
}

// RefreshFromRequest reads the refresh cookie, so a browser can rotate its
// session without ever seeing the token it is spending.
func (ck *Cookies) RefreshFromRequest(r *http.Request) (string, bool) {
	if !ck.cfg.Enabled {
		return "", false
	}
	return read(r, RefreshName)
}

func (ck *Cookies) sameSite() http.SameSite {
	if ck.cfg.SameSite == "lax" {
		return http.SameSiteLaxMode
	}
	return http.SameSiteStrictMode
}

func read(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}
