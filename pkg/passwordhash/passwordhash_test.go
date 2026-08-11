package passwordhash

import (
	"strings"
	"testing"
)

func newHasher(t *testing.T) *Hasher {
	t.Helper()

	// Cheap parameters: the real cost is the point in production and pure
	// wasted seconds in a test.
	h := &Hasher{params: Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}}

	dummy, err := h.Hash("dummy")
	if err != nil {
		t.Fatalf("build dummy: %v", err)
	}
	h.dummy = dummy

	return h
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := newHasher(t)

	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := h.Verify(encoded, "correct horse battery staple")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}

	ok, err = h.Verify(encoded, "wrong password entirely")
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if ok {
		t.Fatal("wrong password verified")
	}
}

func TestHashIsSalted(t *testing.T) {
	h := newHasher(t)

	a, _ := h.Hash("same password")
	b, _ := h.Hash("same password")

	if a == b {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	h := newHasher(t)

	cases := map[string]string{
		"empty":         "",
		"not phc":       "plaintext",
		"wrong algo":    "$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo",
		"short segment": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA",
		"bad base64":    "$argon2id$v=19$m=8192,t=1,p=1$!!!!$!!!!",
	}

	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := h.Verify(encoded, "anything"); err == nil {
				t.Fatal("expected an error for a malformed hash, got none")
			}
		})
	}
}

// A stored hash produced with different parameters must still verify —
// otherwise raising the cost would lock every existing user out.
func TestVerifyHonoursEmbeddedParams(t *testing.T) {
	weak := &Hasher{params: Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}}
	strong := &Hasher{params: Params{Memory: 16 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}}

	encoded, err := weak.Hash("legacy password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := strong.Verify(encoded, "legacy password")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("hash made with weaker parameters no longer verifies")
	}

	if !strong.NeedsRehash(encoded) {
		t.Fatal("NeedsRehash should flag a hash made with weaker parameters")
	}
	if strong.NeedsRehash(mustHash(t, strong, "fresh")) {
		t.Fatal("NeedsRehash flagged a hash made with current parameters")
	}
}

func TestPHCFormat(t *testing.T) {
	h := newHasher(t)

	encoded := mustHash(t, h, "whatever")
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash prefix: %q", encoded)
	}
	if got := strings.Count(encoded, "$"); got != 5 {
		t.Fatalf("expected 5 separators in a PHC string, got %d: %q", got, encoded)
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	h := newHasher(t)
	h.DummyVerify("anything at all")
}

func mustHash(t *testing.T, h *Hasher, password string) string {
	t.Helper()
	encoded, err := h.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return encoded
}
