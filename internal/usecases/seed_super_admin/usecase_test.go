package seed_super_admin

import (
	"context"
	"testing"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type fakePostgres struct {
	activeAdmins int
	created      []postgresadapter.CreateUserParams

	// createErr simulates another replica winning the race to insert.
	createErr error
}

func (f *fakePostgres) CountActiveAdmins(context.Context) (int, error) { return f.activeAdmins, nil }

func (f *fakePostgres) CreateUser(_ context.Context, p postgresadapter.CreateUserParams) (domain.User, error) {
	if f.createErr != nil {
		return domain.User{}, f.createErr
	}
	f.created = append(f.created, p)
	f.activeAdmins++
	return domain.User{
		ID:                 "seeded-1",
		Username:           p.Username,
		Email:              p.Email,
		IsAdmin:            p.IsAdmin,
		Status:             p.Status,
		MustChangePassword: p.MustChangePassword,
	}, nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(string) (string, error) { return "hashed", nil }

type fakeAuditor struct{ actions []string }

func (f *fakeAuditor) Record(_ context.Context, e domain.AuditEntry) {
	f.actions = append(f.actions, e.Action)
}

func harness(cfg Config) (*Usecase, *fakePostgres) {
	pg := &fakePostgres{}
	return &Usecase{postgres: pg, hasher: fakeHasher{}, auditor: &fakeAuditor{}, cfg: cfg}, pg
}

func validConfig() Config {
	return Config{Username: "superadmin", Password: "a-long-enough-password", MinPasswordLength: 12}
}

func TestSeedsOnEmptyInstallation(t *testing.T) {
	uc, pg := harness(validConfig())

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !out.Created {
		t.Fatal("no admin was created on an empty installation")
	}
	if len(pg.created) != 1 {
		t.Fatalf("created %d users, want 1", len(pg.created))
	}

	got := pg.created[0]
	if !got.IsAdmin {
		t.Error("the seeded user is not an admin")
	}
	// The bootstrap password is visible in the environment, in `docker inspect`
	// and in CI logs, so it must not survive first login.
	if !got.MustChangePassword {
		t.Error("must_change_password was not forced on the bootstrap account")
	}
	if got.Username != "superadmin" {
		t.Errorf("username = %q, want superadmin", got.Username)
	}
}

func TestSecondRunIsANoOp(t *testing.T) {
	uc, pg := harness(validConfig())

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("first run: %v", err)
	}
	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if out.Created {
		t.Fatal("the second run created another admin")
	}
	if len(pg.created) != 1 {
		t.Fatalf("created %d users across two runs, want 1", len(pg.created))
	}
}

// The guard is "no active admin exists", not "no user with this username" —
// otherwise renaming the admin and restarting would quietly mint a second one.
func TestSkipsWhenADifferentlyNamedAdminExists(t *testing.T) {
	uc, pg := harness(validConfig())
	pg.activeAdmins = 1

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Created || len(pg.created) != 0 {
		t.Fatal("an admin was seeded even though the installation already had one")
	}
}

func TestSkipsWhenNotConfigured(t *testing.T) {
	uc, pg := harness(Config{MinPasswordLength: 12})

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Created || len(pg.created) != 0 {
		t.Fatal("an admin was seeded with no credentials configured")
	}
	if !out.Skipped {
		t.Fatal("expected the run to report itself skipped")
	}
}

// An empty SUPER_ADMIN_PASSWORD is the zero-configuration path: the service
// invents one so `docker run` against an empty database yields a usable
// installation.
func TestGeneratesPasswordWhenNotSupplied(t *testing.T) {
	cfg := validConfig()
	cfg.Password = ""
	uc, pg := harness(cfg)

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !out.Created {
		t.Fatal("no admin was created")
	}
	if out.GeneratedPassword == "" {
		t.Fatal("no password was generated, so the account is unreachable")
	}
	if len(out.GeneratedPassword) < cfg.MinPasswordLength {
		t.Fatalf("generated password is %d characters, below the configured floor of %d",
			len(out.GeneratedPassword), cfg.MinPasswordLength)
	}
	if len(pg.created) != 1 {
		t.Fatalf("created %d users, want 1", len(pg.created))
	}
	// The stored value must be the hash, never the password itself.
	if pg.created[0].PasswordHash == out.GeneratedPassword {
		t.Fatal("the generated password was stored unhashed")
	}
}

func TestGeneratedPasswordsDiffer(t *testing.T) {
	cfg := validConfig()
	cfg.Password = ""

	seen := make(map[string]struct{}, 8)
	for i := 0; i < 8; i++ {
		uc, _ := harness(cfg)
		out, err := uc.Execute(context.Background(), Input{})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if _, dup := seen[out.GeneratedPassword]; dup {
			t.Fatal("the same password was generated twice")
		}
		seen[out.GeneratedPassword] = struct{}{}
	}
}

// An explicit password is used verbatim and must not be reported as generated,
// or the caller would print a secret the operator already knows into the logs.
func TestSuppliedPasswordIsNotReportedAsGenerated(t *testing.T) {
	uc, _ := harness(validConfig())

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.GeneratedPassword != "" {
		t.Fatal("an explicitly configured password was reported as generated")
	}
}

// Refusing to boot beats booting with a guessable administrator.
func TestWeakPasswordFailsLoudly(t *testing.T) {
	cfg := validConfig()
	cfg.Password = "short"
	uc, pg := harness(cfg)

	if _, err := uc.Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected an error for a password below the minimum length")
	}
	if len(pg.created) != 0 {
		t.Fatal("an admin was created with a too-short password")
	}
}

// Two replicas starting against the same empty database both pass the
// admin-count check, then one loses the insert. Losing that race must not stop
// the replica from booting — the admin it wanted now exists.
func TestConcurrentSeedLoserStillBoots(t *testing.T) {
	uc, pg := harness(validConfig())
	pg.createErr = domain.ErrUserAlreadyExists

	out, err := uc.Execute(context.Background(), Input{})
	if err != nil {
		t.Fatalf("losing the seed race aborted the boot: %v", err)
	}
	if out.Created {
		t.Fatal("reported a creation that did not happen")
	}
	if !out.Skipped {
		t.Fatal("expected the run to report itself skipped")
	}
}

func TestInvalidUsernameFailsLoudly(t *testing.T) {
	cfg := validConfig()
	cfg.Username = "admin" // reserved
	uc, _ := harness(cfg)

	if _, err := uc.Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected an error for a reserved username")
	}
}
