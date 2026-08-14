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
		ID:       "seeded-1",
		Username: p.Username,
		Email:    p.Email,
		IsAdmin:  p.IsAdmin,
		Status:   p.Status,
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

// The credentials are static: what is in the environment is what works. An
// empty password would create an account nobody can sign into, so it fails the
// boot instead.
func TestEmptyPasswordFailsRatherThanCreatingAnUnreachableAccount(t *testing.T) {
	cfg := validConfig()
	cfg.Password = ""
	uc, pg := harness(cfg)

	if _, err := uc.Execute(context.Background(), Input{}); err == nil {
		t.Fatal("expected an error for an empty SUPER_ADMIN_PASSWORD")
	}
	if len(pg.created) != 0 {
		t.Fatal("an admin was created with no password")
	}
}

// The environment password is used exactly as given — hashed, never stored raw.
func TestConfiguredPasswordIsUsedVerbatim(t *testing.T) {
	uc, pg := harness(validConfig())

	if _, err := uc.Execute(context.Background(), Input{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.created) != 1 {
		t.Fatalf("created %d users, want 1", len(pg.created))
	}
	if pg.created[0].PasswordHash == validConfig().Password {
		t.Fatal("the password was stored unhashed")
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
