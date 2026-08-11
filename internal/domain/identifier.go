package domain

import (
	"net/mail"
	"regexp"
	"strings"
)

// Identifier normalisation. Kept in the domain because every layer must agree
// on it: the value written at registration and the value looked up at login
// have to be byte-identical, or a user simply cannot log in.

// usernamePattern is deliberately narrow. Beyond keeping identifiers readable,
// forbidding "@" is what makes LooksLikeEmail a sound way to pick which column
// to search — a username could otherwise be registered that shadows an email.
//
// Restricting to ASCII also sidesteps Unicode confusables: without it, "аdmin"
// with a Cyrillic "а" is a different string that renders identically.
var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// reservedUsernames are names that would let their holder impersonate the
// service itself.
var reservedUsernames = map[string]struct{}{
	"admin": {}, "administrator": {}, "root": {}, "system": {}, "support": {},
	"help": {}, "api": {}, "auth": {}, "goauth": {}, "security": {},
	"noreply": {}, "no-reply": {}, "postmaster": {}, "webmaster": {}, "abuse": {},
}

// LooksLikeEmail decides which identifier column a login attempt targets.
func LooksLikeEmail(s string) bool { return strings.Contains(s, "@") }

// NormalizeUsername lowercases, trims, and validates. The returned value is
// what gets stored and compared.
func NormalizeUsername(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", ErrNoIdentifier
	}
	if !usernamePattern.MatchString(v) {
		return "", ErrInvalidIdentifier
	}
	if _, reserved := reservedUsernames[v]; reserved {
		return "", ErrInvalidIdentifier
	}
	return v, nil
}

// NormalizeEmail lowercases, trims, and checks the address parses. Local-part
// case is technically significant per RFC 5321 but no real provider treats it
// so, and preserving it would let one address register twice.
func NormalizeEmail(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", ErrNoIdentifier
	}

	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Address != v || !strings.Contains(v, ".") {
		return "", ErrInvalidIdentifier
	}
	return v, nil
}

// NormalizeIdentifier normalises a login input whose kind is not known upfront.
func NormalizeIdentifier(raw string) (string, error) {
	if LooksLikeEmail(raw) {
		return NormalizeEmail(raw)
	}
	return NormalizeUsername(raw)
}

// ValidatePassword enforces the only password rule goauth has: a length floor.
// Composition rules (a digit, a symbol, mixed case) push users toward
// predictable substitutions and measurably weaken real-world passwords, so
// length is what is checked.
func ValidatePassword(password string, minLength int) error {
	if len([]rune(password)) < minLength {
		return ErrPasswordTooWeak
	}
	return nil
}
