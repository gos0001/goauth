package domain

import (
	"errors"
	"testing"
)

func TestNormalizeUsername(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		error bool
	}{
		{"lowercases and trims", "  Alice_99  ", "alice_99", false},
		{"minimum length", "abc", "abc", false},
		{"too short", "ab", "", true},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", true},
		{"empty", "   ", "", true},
		{"rejects spaces", "two words", "", true},
		{"rejects dashes", "a-b-c", "", true},
		// An "@" in a username would shadow an email address, since the login
		// path picks the column by looking for one.
		{"rejects at sign", "a@b", "", true},
		// Cyrillic "а" renders identically to ASCII "a"; allowing it would make
		// visually identical accounts possible.
		{"rejects cyrillic lookalike", "аdmin1", "", true},
		{"rejects reserved name", "admin", "", true},
		{"rejects reserved name in mixed case", "ROOT", "", true},
		{"rejects reserved support", "support", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeUsername(tc.in)
			if tc.error {
				if err == nil {
					t.Fatalf("NormalizeUsername(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeUsername(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeUsername(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  string
		error bool
	}{
		// Local-part case is technically significant per RFC 5321, but no real
		// provider honours it; preserving it would let one address register twice.
		{"lowercases", " User@Example.COM ", "user@example.com", false},
		{"plus addressing kept", "user+tag@example.com", "user+tag@example.com", false},
		{"no at sign", "not-an-email", "", true},
		{"no domain dot", "user@localhost", "", true},
		{"empty", "  ", "", true},
		{"display name form rejected", "Alice <alice@example.com>", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEmail(tc.in)
			if tc.error {
				if err == nil {
					t.Fatalf("NormalizeEmail(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEmail(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeEmail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeIdentifierPicksByAtSign(t *testing.T) {
	got, err := NormalizeIdentifier("Alice@Example.com")
	if err != nil {
		t.Fatalf("NormalizeIdentifier: %v", err)
	}
	if got != "alice@example.com" {
		t.Fatalf("got %q, want alice@example.com", got)
	}

	got, err = NormalizeIdentifier("Alice")
	if err != nil {
		t.Fatalf("NormalizeIdentifier: %v", err)
	}
	if got != "alice" {
		t.Fatalf("got %q, want alice", got)
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("exactly12chr", 12); err != nil {
		t.Fatalf("a password of exactly the minimum length was rejected: %v", err)
	}
	if err := ValidatePassword("short", 12); !errors.Is(err, ErrPasswordTooWeak) {
		t.Fatalf("err = %v, want ErrPasswordTooWeak", err)
	}
	// Length is counted in runes, so a passphrase of non-ASCII characters is
	// not penalised for its byte length.
	if err := ValidatePassword("парольпарольпа", 12); err != nil {
		t.Fatalf("a 14-rune password was rejected: %v", err)
	}
}
