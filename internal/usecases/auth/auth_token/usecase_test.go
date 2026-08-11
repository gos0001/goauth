package auth_token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gos0001/goauth/internal/domain"
	"github.com/gos0001/goauth/internal/service/tokens"
)

// Fakes are plain structs in the same package, per the project's testing
// convention — no mocking library.

type fakePostgres struct {
	usersByUsername map[string]domain.User
	usersByEmail    map[string]domain.User
	usersByID       map[string]domain.User
	sessions        map[string]domain.Session // keyed by hex of refresh hash

	deletedFamilies []string
	touched         []string
}

func newFakePostgres() *fakePostgres {
	return &fakePostgres{
		usersByUsername: map[string]domain.User{},
		usersByEmail:    map[string]domain.User{},
		usersByID:       map[string]domain.User{},
		sessions:        map[string]domain.Session{},
	}
}

func (f *fakePostgres) add(u domain.User) {
	f.usersByID[u.ID] = u
	if u.Username != "" {
		f.usersByUsername[u.Username] = u
	}
	if u.Email != "" {
		f.usersByEmail[u.Email] = u
	}
}

func (f *fakePostgres) GetUserByUsername(_ context.Context, username string) (domain.User, error) {
	u, ok := f.usersByUsername[username]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakePostgres) GetUserByEmail(_ context.Context, email string) (domain.User, error) {
	u, ok := f.usersByEmail[email]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakePostgres) GetUserByID(_ context.Context, id string) (domain.User, error) {
	u, ok := f.usersByID[id]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakePostgres) TouchUserLogin(_ context.Context, id string) error {
	f.touched = append(f.touched, id)
	return nil
}

func (f *fakePostgres) GetSessionByRefreshHash(_ context.Context, hash []byte) (domain.Session, error) {
	s, ok := f.sessions[string(hash)]
	if !ok {
		return domain.Session{}, domain.ErrSessionNotFound
	}
	return s, nil
}

func (f *fakePostgres) DeleteSessionFamily(_ context.Context, familyID string) (int, error) {
	f.deletedFamilies = append(f.deletedFamilies, familyID)
	n := 0
	for k, s := range f.sessions {
		if s.FamilyID == familyID {
			delete(f.sessions, k)
			n++
		}
	}
	return n, nil
}

type fakeHasher struct {
	// password -> stored hash
	valid       map[string]string
	dummyCalls  int
	verifyError error
}

func (f *fakeHasher) Verify(encoded, password string) (bool, error) {
	if f.verifyError != nil {
		return false, f.verifyError
	}
	return f.valid[password] == encoded, nil
}

func (f *fakeHasher) DummyVerify(string) { f.dummyCalls++ }

type fakeLimiter struct {
	backoff  time.Duration
	failures []string
	resets   []string
	err      error
}

func (f *fakeLimiter) Backoff(context.Context, string) (time.Duration, error) {
	return f.backoff, f.err
}

func (f *fakeLimiter) RegisterFailure(_ context.Context, key string) (time.Duration, error) {
	f.failures = append(f.failures, key)
	return 0, nil
}

func (f *fakeLimiter) Reset(_ context.Context, key string) error {
	f.resets = append(f.resets, key)
	return nil
}

type fakeAuditor struct{ actions []string }

func (f *fakeAuditor) Record(_ context.Context, e domain.AuditEntry) {
	f.actions = append(f.actions, e.Action)
}

type fakeIssuer struct {
	issued  int
	rotated int
	err     error
}

func (f *fakeIssuer) Issue(context.Context, domain.User, tokens.Context) (tokens.Pair, error) {
	if f.err != nil {
		return tokens.Pair{}, f.err
	}
	f.issued++
	return tokens.Pair{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 900}, nil
}

func (f *fakeIssuer) Rotate(context.Context, []byte, domain.User, string, tokens.Context) (tokens.Pair, error) {
	if f.err != nil {
		return tokens.Pair{}, f.err
	}
	f.rotated++
	return tokens.Pair{AccessToken: "access2", RefreshToken: "refresh2", TokenType: "Bearer", ExpiresIn: 900}, nil
}

type harness struct {
	uc      *Usecase
	pg      *fakePostgres
	hasher  *fakeHasher
	limiter *fakeLimiter
	auditor *fakeAuditor
	issuer  *fakeIssuer
}

func newHarness() *harness {
	h := &harness{
		pg:      newFakePostgres(),
		hasher:  &fakeHasher{valid: map[string]string{}},
		limiter: &fakeLimiter{},
		auditor: &fakeAuditor{},
		issuer:  &fakeIssuer{},
	}
	h.uc = &Usecase{
		postgres: h.pg,
		issuer:   h.issuer,
		hasher:   h.hasher,
		limiter:  h.limiter,
		auditor:  h.auditor,
		cfg:      Config{FailClosed: true},
	}
	return h
}

func activeUser() domain.User {
	return domain.User{
		ID:           "user-1",
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: "stored-hash",
		Status:       domain.StatusActive,
	}
}

func TestPasswordGrantSuccess(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())
	h.hasher.valid["s3cret-password"] = "stored-hash"

	out, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "alice", Password: "s3cret-password",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if out.AccessToken == "" || out.RefreshToken == "" {
		t.Fatal("expected a token pair")
	}
	if h.issuer.issued != 1 {
		t.Fatalf("issued = %d, want 1", h.issuer.issued)
	}
	if len(h.pg.touched) != 1 {
		t.Fatal("last_login_at was not updated")
	}
	if len(h.limiter.resets) != 1 {
		t.Fatal("failure counter was not reset after a successful login")
	}
}

// Login by email must work identically — the identifier column is chosen by the
// presence of "@", and usernames cannot contain one.
func TestPasswordGrantByEmail(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())
	h.hasher.valid["s3cret-password"] = "stored-hash"

	out, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "Alice@Example.com ", Password: "s3cret-password",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.User.ID != "user-1" {
		t.Fatalf("user = %q, want user-1", out.User.ID)
	}
}

// The central anti-enumeration property: an unknown account and a wrong
// password must be indistinguishable, both in the error returned and in the
// argon2 work performed.
func TestUnknownIdentifierAndWrongPasswordAreIndistinguishable(t *testing.T) {
	unknown := newHarness()
	_, errUnknown := unknown.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "nobody", Password: "whatever-password",
	})

	wrong := newHarness()
	wrong.pg.add(activeUser())
	wrong.hasher.valid["s3cret-password"] = "stored-hash"
	_, errWrong := wrong.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "alice", Password: "not-the-password",
	})

	if !errors.Is(errUnknown, domain.ErrInvalidCredentials) {
		t.Fatalf("unknown identifier err = %v, want ErrInvalidCredentials", errUnknown)
	}
	if !errors.Is(errWrong, domain.ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v, want ErrInvalidCredentials", errWrong)
	}

	if unknown.hasher.dummyCalls != 1 {
		t.Fatal("no dummy hash was computed for an unknown identifier: the timing difference leaks account existence")
	}

	if len(unknown.limiter.failures) != 1 || len(wrong.limiter.failures) != 1 {
		t.Fatal("both failure paths must feed the backoff counter")
	}
}

// A malformed identifier must not skip the dummy hash either.
func TestInvalidIdentifierStillBurnsWork(t *testing.T) {
	h := newHarness()

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "no", Password: "whatever-password",
	})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if h.hasher.dummyCalls != 1 {
		t.Fatal("expected a dummy hash for a malformed identifier")
	}
}

func TestBlockedUserCannotLogIn(t *testing.T) {
	h := newHarness()
	u := activeUser()
	u.Status = domain.StatusBlocked
	h.pg.add(u)
	h.hasher.valid["s3cret-password"] = "stored-hash"

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "alice", Password: "s3cret-password",
	})
	if !errors.Is(err, domain.ErrUserBlocked) {
		t.Fatalf("err = %v, want ErrUserBlocked", err)
	}
	if h.issuer.issued != 0 {
		t.Fatal("tokens were issued to a blocked user")
	}
}

func TestBackoffBlocksAttempt(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())
	h.hasher.valid["s3cret-password"] = "stored-hash"
	h.limiter.backoff = 30 * time.Second

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "alice", Password: "s3cret-password",
	})
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("err = %v, want ErrTooManyAttempts", err)
	}
}

// With FailClosed set, an unreachable limiter must stop password checks rather
// than let every attempt through.
func TestLimiterOutageFailsClosed(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())
	h.hasher.valid["s3cret-password"] = "stored-hash"
	h.limiter.err = errors.New("redis down")

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantPassword, Identifier: "alice", Password: "s3cret-password",
	})
	if err == nil {
		t.Fatal("expected the login to be refused while the limiter is unavailable")
	}
	if h.issuer.issued != 0 {
		t.Fatal("tokens were issued despite the limiter being unavailable")
	}
}

func TestRefreshGrantRotates(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())

	hash := tokens.HashRefresh("refresh-token-value")
	h.pg.sessions[string(hash)] = domain.Session{
		ID: "session-1", UserID: "user-1", FamilyID: "family-1",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}

	out, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantRefresh, RefreshToken: "refresh-token-value",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.AccessToken != "access2" {
		t.Fatalf("access token = %q, want the rotated one", out.AccessToken)
	}
	if h.issuer.rotated != 1 {
		t.Fatalf("rotated = %d, want 1", h.issuer.rotated)
	}
}

// The reuse rule: presenting a spent token means two parties hold it, so the
// entire family dies rather than just the presented link.
func TestReusedRefreshTokenDestroysFamily(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())

	used := time.Now().Add(-time.Minute)
	hash := tokens.HashRefresh("already-used")
	h.pg.sessions[string(hash)] = domain.Session{
		ID: "session-1", UserID: "user-1", FamilyID: "family-1",
		UsedAt: &used, ExpiresAt: time.Now().Add(time.Hour),
	}

	// A sibling session in the same family must die too.
	siblingHash := tokens.HashRefresh("sibling")
	h.pg.sessions[string(siblingHash)] = domain.Session{
		ID: "session-2", UserID: "user-1", FamilyID: "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantRefresh, RefreshToken: "already-used",
	})
	if !errors.Is(err, domain.ErrRefreshReused) {
		t.Fatalf("err = %v, want ErrRefreshReused", err)
	}

	if len(h.pg.deletedFamilies) != 1 || h.pg.deletedFamilies[0] != "family-1" {
		t.Fatalf("deleted families = %v, want [family-1]", h.pg.deletedFamilies)
	}
	if _, alive := h.pg.sessions[string(siblingHash)]; alive {
		t.Fatal("a sibling session in the compromised family survived")
	}
	if h.issuer.rotated != 0 {
		t.Fatal("a rotated pair was issued for a reused token")
	}
}

func TestExpiredRefreshTokenRejected(t *testing.T) {
	h := newHarness()
	h.pg.add(activeUser())

	hash := tokens.HashRefresh("stale")
	h.pg.sessions[string(hash)] = domain.Session{
		ID: "session-1", UserID: "user-1", FamilyID: "family-1",
		ExpiresAt: time.Now().Add(-time.Minute),
	}

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantRefresh, RefreshToken: "stale",
	})
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
	// An expired token is not evidence of a leak, so the family stays.
	if len(h.pg.deletedFamilies) != 0 {
		t.Fatal("an expired token should not destroy the family")
	}
}

func TestRefreshRejectedForBlockedUser(t *testing.T) {
	h := newHarness()
	u := activeUser()
	u.Status = domain.StatusBlocked
	h.pg.add(u)

	hash := tokens.HashRefresh("valid-token")
	h.pg.sessions[string(hash)] = domain.Session{
		ID: "session-1", UserID: "user-1", FamilyID: "family-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	_, err := h.uc.Execute(context.Background(), Input{
		GrantType: GrantRefresh, RefreshToken: "valid-token",
	})
	if !errors.Is(err, domain.ErrUserBlocked) {
		t.Fatalf("err = %v, want ErrUserBlocked", err)
	}
}

func TestUnknownGrantTypeRejected(t *testing.T) {
	h := newHarness()

	_, err := h.uc.Execute(context.Background(), Input{GrantType: "client_credentials"})
	if !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      Input
		wantErr bool
	}{
		{"password ok", Input{GrantType: GrantPassword, Identifier: "alice", Password: "x"}, false},
		{"password missing identifier", Input{GrantType: GrantPassword, Password: "x"}, true},
		{"password missing password", Input{GrantType: GrantPassword, Identifier: "alice"}, true},
		{"refresh ok", Input{GrantType: GrantRefresh, RefreshToken: "t"}, false},
		{"refresh missing token", Input{GrantType: GrantRefresh}, true},
		{"unknown grant", Input{GrantType: "magic"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			err := in.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
