// Package passwordhash hashes and verifies passwords with argon2id.
//
// Hashes are stored in PHC string format, which carries its own parameters:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
//
// Verification reads the parameters out of the stored hash rather than from the
// current configuration, so raising the cost later leaves existing hashes
// verifiable and lets them be re-hashed lazily on the next successful login.
//
// Zero domain imports — this package knows nothing about users.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash        = errors.New("passwordhash: malformed hash")
	ErrIncompatibleParams = errors.New("passwordhash: incompatible hash version")
)

// Params are the argon2id cost parameters. The defaults follow the OWASP
// recommendation of 64 MiB with three iterations.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

type Hasher struct {
	params Params

	// dummy is hashed on the user-not-found path so that a failed login costs
	// the same whether or not the account exists. Without it, response time
	// alone enumerates accounts.
	dummy string
}

func New() (*Hasher, error) {
	h := &Hasher{params: DefaultParams()}

	dummy, err := h.Hash("dummy-password-for-constant-time-failures")
	if err != nil {
		return nil, fmt.Errorf("passwordhash: build dummy hash: %w", err)
	}
	h.dummy = dummy

	return h, nil
}

func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: read salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password), salt,
		h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether password matches encoded. A malformed stored hash is
// an error, not a mismatch, so it can be logged rather than silently rejecting
// a legitimate user forever.
func (h *Hasher) Verify(encoded, password string) (bool, error) {
	params, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey(
		[]byte(password), salt,
		params.Iterations, params.Memory, params.Parallelism, uint32(len(want)),
	)

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// DummyVerify burns the same work as a real verification. Call it on the
// user-not-found branch so that branch is indistinguishable by timing.
func (h *Hasher) DummyVerify(password string) {
	_, _ = h.Verify(h.dummy, password)
}

// NeedsRehash reports whether a stored hash was produced with weaker parameters
// than the current configuration, so callers can transparently upgrade it while
// they still hold the plaintext.
func (h *Hasher) NeedsRehash(encoded string) bool {
	params, _, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return params.Memory < h.params.Memory ||
		params.Iterations < h.params.Iterations ||
		params.Parallelism < h.params.Parallelism
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return Params{}, nil, nil, ErrIncompatibleParams
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}

	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))

	return p, salt, key, nil
}
