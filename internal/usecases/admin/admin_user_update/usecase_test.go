package admin_user_update

import (
	"context"
	"errors"
	"testing"

	postgresadapter "github.com/gos0001/goauth/v2/internal/adapter/postgres"
	"github.com/gos0001/goauth/v2/internal/domain"
)

type fakePostgres struct {
	users        map[string]domain.User
	activeAdmins int

	updated         []postgresadapter.UpdateUserParams
	revokedOnUpdate bool
	ownerWrites     []string // (user, owner) pairs, flat
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

func (f *fakePostgres) UpdateUserOwner(_ context.Context, id, owner string, _ *domain.OutboxEvent) (domain.User, error) {
	f.ownerWrites = append(f.ownerWrites, id, owner)
	u := f.users[id]
	u.CreatedBy = owner
	f.users[id] = u
	return u, nil
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

// Off-mode semantics: rank only, no ownership. The delegated rules are
// covered in roleguard's own tests.
func (f fakeGuard) CanActOnUser(actor domain.Role, _ string, _ domain.User, targetRole domain.Role) error {
	if !domain.CanManage(actor.Rank, targetRole.Rank) {
		return domain.ErrInsufficientRank
	}
	return nil
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

func TestValidateOwnerMustBeUUID(t *testing.T) {
	in := Input{ID: "user-1", Owner: ptr("not-a-uuid")}
	if err := in.Validate(); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want ErrInvalidInput", err)
	}
	// The empty string is valid: it means "unassign".
	in = Input{ID: "user-1", Owner: ptr("")}
	if err := in.Validate(); err != nil {
		t.Fatalf("unassign should validate: %v", err)
	}
}

// Re-pointing created_by is the superadmin's lever; a delegated admin who
// could do it could give themselves anybody's user.
func TestOwnerTransferIsSuperAdminOnly(t *testing.T) {
	uc, _, _ := harnessWith(adminGuard(), admin("admin-1"), member("user-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", ActorUserID: "admin-1", Owner: ptr("admin-2"),
	})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
	}
}

// A transfer must land on a real account that outranks the row; an owner
// who cannot manage the user would leave the row stranded.
func TestOwnerTransferRequiresExistingOwner(t *testing.T) {
	uc, _, _ := harness(member("user-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", Owner: ptr("11111111-1111-1111-1111-111111111111"),
	})
	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

func TestOwnerTransferRejectsEqualRankOwner(t *testing.T) {
	uc, _, _ := harness(member("user-1"), member("user-2"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", Owner: ptr("user-2"),
	})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
	}
}

// Ownership alone must not fire the main UPDATE: it would touch nothing but
// updated_at and emit a misleading event name.
func TestOwnerOnlyPatchSkipsMainUpdate(t *testing.T) {
	uc, pg, _ := harness(member("user-1"), admin("admin-1"))

	out, err := uc.Execute(context.Background(), Input{ID: "user-1", Owner: ptr("admin-1")})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(pg.updated) != 0 {
		t.Fatalf("main update ran %d times, want 0", len(pg.updated))
	}
	if len(pg.ownerWrites) != 2 || pg.ownerWrites[1] != "admin-1" {
		t.Fatalf("ownerWrites = %v, want one write to admin-1", pg.ownerWrites)
	}
	if out.CreatedBy != "admin-1" {
		t.Fatalf("out.CreatedBy = %q, want admin-1 (superadmin caller)", out.CreatedBy)
	}
}

// Promoting a user above their owner would detach the row from the only
// admin who is supposed to manage it.
func TestRoleChangeCannotOutrankOwner(t *testing.T) {
	owner := domain.User{ID: "admin-1", Username: "admin-1", Role: domain.RoleAdmin, Status: domain.StatusActive}
	owned := member("user-1")
	owned.CreatedBy = "admin-1"
	uc, _, _ := harness(owned, owner)

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", Role: ptr(domain.RoleSuperAdmin),
	})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
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
