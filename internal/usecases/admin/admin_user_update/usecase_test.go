package admin_user_update

import (
	"context"
	"errors"
	"testing"

	postgresadapter "github.com/gos0001/goauth/internal/adapter/postgres"
	"github.com/gos0001/goauth/internal/domain"
)

type fakePostgres struct {
	users        map[string]domain.User
	activeAdmins int

	updated         []postgresadapter.UpdateUserParams
	revokedOnUpdate bool
}

func (f *fakePostgres) GetUserByID(_ context.Context, id string) (domain.User, error) {
	u, ok := f.users[id]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}

func (f *fakePostgres) CountActiveSuperAdmins(context.Context) (int, error) {
	return f.activeAdmins, nil
}

func (f *fakePostgres) GetRole(_ context.Context, name string) (domain.Role, error) {
	if name == "" {
		name = domain.RoleUser
	}
	rank := domain.RankUser
	switch name {
	case domain.RoleManager:
		rank = domain.RankManager
	case domain.RoleAdmin:
		rank = domain.RankAdmin
	case domain.RoleSuperAdmin:
		rank = domain.RankSuperAdmin
	}
	return domain.Role{Name: name, Rank: rank}, nil
}

func (f *fakePostgres) UpdateUser(_ context.Context, p postgresadapter.UpdateUserParams) (domain.User, error) {
	f.updated = append(f.updated, p)
	return f.apply(p), nil
}

func (f *fakePostgres) UpdateUserAndRevokeSessions(_ context.Context, p postgresadapter.UpdateUserParams) (domain.User, error) {
	f.updated = append(f.updated, p)
	f.revokedOnUpdate = true
	return f.apply(p), nil
}

func (f *fakePostgres) apply(p postgresadapter.UpdateUserParams) domain.User {
	u := f.users[p.ID]
	if p.Username != nil {
		u.Username = *p.Username
	}
	if p.Email != nil {
		u.Email = *p.Email
	}
	if p.Status != nil {
		u.Status = *p.Status
	}
	if p.Role != nil {
		u.Role = *p.Role
	}
	f.users[p.ID] = u
	return u
}

type fakeAuditor struct{ actions []string }

func (f *fakeAuditor) Record(_ context.Context, e domain.AuditEntry) {
	f.actions = append(f.actions, e.Action)
}

// fakeGuard answers as one fixed role for every actor, machine included: the
// rank rules themselves are exercised through the roles the fake postgres
// hands out, not through the actor's identity.
type fakeGuard struct{ role domain.Role }

func (f fakeGuard) Actor(_ context.Context, _ string) (domain.Role, error) {
	return f.role, nil
}

func superGuard() fakeGuard {
	return fakeGuard{role: domain.Role{Name: domain.RoleSuperAdmin, Rank: domain.RankSuperAdmin}}
}

func adminGuard() fakeGuard {
	return fakeGuard{role: domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin}}
}

func harness(users ...domain.User) (*Usecase, *fakePostgres, *fakeAuditor) {
	return harnessWith(superGuard(), users...)
}

func harnessWith(g fakeGuard, users ...domain.User) (*Usecase, *fakePostgres, *fakeAuditor) {
	pg := &fakePostgres{users: map[string]domain.User{}}
	for _, u := range users {
		pg.users[u.ID] = u
		if u.IsSuperAdmin() && u.Active() {
			pg.activeAdmins++
		}
	}
	auditor := &fakeAuditor{}
	return &Usecase{postgres: pg, guard: g, auditor: auditor}, pg, auditor
}

func admin(id string) domain.User {
	return domain.User{ID: id, Username: id, Role: domain.RoleSuperAdmin, Status: domain.StatusActive}
}

func member(id string) domain.User {
	return domain.User{ID: id, Username: id, Role: domain.RoleUser, Status: domain.StatusActive}
}

func ptr[T any](v T) *T { return &v }

// Changing your own role leaves nobody able to give the old one back — or
// hands you a better one nobody authorised.
func TestSelfRoleChangeRefused(t *testing.T) {
	uc, _, _ := harness(admin("admin-1"), admin("admin-2"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "admin-1", ActorUserID: "admin-1", Role: ptr(domain.RoleUser),
	})
	if !errors.Is(err, domain.ErrSelfDemote) {
		t.Fatalf("err = %v, want ErrSelfDemote", err)
	}
}

// Demoting the only remaining admin bricks the installation: the repair would
// have to be manual SQL.
func TestLastAdminCannotBeDemoted(t *testing.T) {
	uc, _, _ := harness(admin("admin-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "admin-1", ActorUserID: "", Role: ptr(domain.RoleUser),
	})
	if !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
}

func TestLastAdminCannotBeBlocked(t *testing.T) {
	uc, _, _ := harness(admin("admin-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "admin-1", ActorUserID: "", Status: ptr(string(domain.StatusBlocked)),
	})
	if !errors.Is(err, domain.ErrLastAdmin) {
		t.Fatalf("err = %v, want ErrLastAdmin", err)
	}
}

func TestAdminCanBeDemotedWhenAnotherExists(t *testing.T) {
	uc, _, auditor := harness(admin("admin-1"), admin("admin-2"))

	out, err := uc.Execute(context.Background(), Input{
		ID: "admin-2", ActorUserID: "admin-1", Role: ptr(domain.RoleUser),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Role != domain.RoleUser {
		t.Fatal("role was not cleared")
	}
	if !contains(auditor.actions, domain.ActionRoleAssigned) {
		t.Fatalf("audit actions = %v, want a role_assigned entry", auditor.actions)
	}
}

// A block that leaves live sessions working is not a block.
func TestBlockingRevokesSessions(t *testing.T) {
	uc, pg, auditor := harness(member("user-1"), admin("admin-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", ActorUserID: "admin-1", Status: ptr(string(domain.StatusBlocked)),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !pg.revokedOnUpdate {
		t.Fatal("blocking a user did not revoke their sessions")
	}
	if !contains(auditor.actions, domain.ActionUserBlocked) {
		t.Fatalf("audit actions = %v, want a blocked entry", auditor.actions)
	}
}

// Unblocking is not destructive, so it must not take the revoking path.
func TestUnblockingDoesNotRevokeSessions(t *testing.T) {
	blocked := member("user-1")
	blocked.Status = domain.StatusBlocked
	uc, pg, _ := harness(blocked, admin("admin-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", ActorUserID: "admin-1", Status: ptr(string(domain.StatusActive)),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if pg.revokedOnUpdate {
		t.Fatal("unblocking should not revoke sessions")
	}
}

func TestIdentifiersAreNormalised(t *testing.T) {
	uc, pg, _ := harness(member("user-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", Username: ptr("  NewName  "), Email: ptr("USER@Example.COM"),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	last := pg.updated[len(pg.updated)-1]
	if *last.Username != "newname" {
		t.Fatalf("username = %q, want newname", *last.Username)
	}
	if *last.Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", *last.Email)
	}
}

func TestReservedUsernameRejected(t *testing.T) {
	uc, _, _ := harness(member("user-1"))

	_, err := uc.Execute(context.Background(), Input{ID: "user-1", Username: ptr("admin")})
	if !errors.Is(err, domain.ErrInvalidIdentifier) {
		t.Fatalf("err = %v, want ErrInvalidIdentifier", err)
	}
}

func TestValidateRejectsDeletionThroughPatch(t *testing.T) {
	in := Input{ID: "user-1", Status: ptr(string(domain.StatusDeleted))}
	if err := in.Validate(); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
}

func TestValidateRejectsEmptyPatch(t *testing.T) {
	in := Input{ID: "user-1"}
	if err := in.Validate(); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
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
