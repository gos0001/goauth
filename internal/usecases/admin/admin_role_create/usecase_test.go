package admin_role_create

import (
	"context"
	"errors"
	"testing"

	"github.com/gos0001/goauth/internal/domain"
)

type fakePostgres struct {
	created []domain.Role
}

func (f *fakePostgres) CreateRole(_ context.Context, r domain.Role) (domain.Role, error) {
	f.created = append(f.created, r)
	return r, nil
}

type fakeGuard struct{ role domain.Role }

func (f fakeGuard) Actor(_ context.Context, _ string) (domain.Role, error) {
	return f.role, nil
}

type fakeAuditor struct{ actions []string }

func (f *fakeAuditor) Record(_ context.Context, e domain.AuditEntry) {
	f.actions = append(f.actions, e.Action)
}

func adminActor(perms ...domain.Permission) fakeGuard {
	if perms == nil {
		perms = domain.AllPermissions()
	}
	return fakeGuard{role: domain.Role{
		Name: domain.RoleAdmin, Rank: domain.RankAdmin, Permissions: perms,
	}}
}

func harness(g fakeGuard) (*Usecase, *fakePostgres, *fakeAuditor) {
	pg := &fakePostgres{}
	aud := &fakeAuditor{}
	return &Usecase{postgres: pg, guard: g, auditor: aud}, pg, aud
}

func TestCreateRoleBelowActorRank(t *testing.T) {
	uc, pg, aud := harness(adminActor())

	out, err := uc.Execute(context.Background(), Input{
		Name:        "support",
		Rank:        20,
		Permissions: []domain.Permission{domain.PermUsersRead},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.created) != 1 || pg.created[0].Name != "support" {
		t.Fatalf("created = %+v, want one support role", pg.created)
	}
	if out.Role.IsSystem {
		t.Fatal("the API must not mint system roles")
	}
	if !contains(aud.actions, domain.ActionRoleCreated) {
		t.Fatalf("audit actions = %v, want role.created", aud.actions)
	}
}

// An admin building a role at their own rank is manufacturing a peer.
func TestCreateRoleAtActorRankRefused(t *testing.T) {
	uc, _, _ := harness(adminActor())

	_, err := uc.Execute(context.Background(), Input{Name: "shadow", Rank: domain.RankAdmin})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
	}
}

// Without this rule, roles:manage alone is full escalation: build a role with
// everything and step into it.
func TestCreateRoleWithUnheldPermissionRefused(t *testing.T) {
	uc, _, _ := harness(adminActor(domain.PermRolesRead, domain.PermRolesManage))

	_, err := uc.Execute(context.Background(), Input{
		Name:        "killer",
		Rank:        10,
		Permissions: []domain.Permission{domain.PermUsersDelete},
	})
	if !errors.Is(err, domain.ErrPermissionNotHeld) {
		t.Fatalf("err = %v, want ErrPermissionNotHeld", err)
	}
}

func TestCreateReservedNameRefused(t *testing.T) {

	for _, name := range []string{"superadmin", "admin", "manager", "user"} {
		if err := (&Input{Name: name, Rank: 10}).Validate(); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("name %q should be rejected", name)
		}
	}
}

func TestRankBoundsEnforced(t *testing.T) {
	uc, _, _ := harness(adminActor())

	for _, rank := range []int{0, 100, -5, 1000} {
		_, err := uc.Execute(context.Background(), Input{Name: "edge", Rank: rank})
		if !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("rank %d should be rejected, got err = %v", rank, err)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
