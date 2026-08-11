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

func (f *fakePostgres) CountActiveAdmins(context.Context) (int, error) {
	return f.activeAdmins, nil
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
	if p.IsAdmin != nil {
		u.IsAdmin = *p.IsAdmin
	}
	f.users[p.ID] = u
	return u
}

type fakeAuditor struct{ actions []string }

func (f *fakeAuditor) Record(_ context.Context, e domain.AuditEntry) {
	f.actions = append(f.actions, e.Action)
}

func harness(users ...domain.User) (*Usecase, *fakePostgres, *fakeAuditor) {
	pg := &fakePostgres{users: map[string]domain.User{}}
	for _, u := range users {
		pg.users[u.ID] = u
		if u.IsAdmin && u.Active() {
			pg.activeAdmins++
		}
	}
	auditor := &fakeAuditor{}
	return &Usecase{postgres: pg, auditor: auditor}, pg, auditor
}

func admin(id string) domain.User {
	return domain.User{ID: id, Username: id, IsAdmin: true, Status: domain.StatusActive}
}

func member(id string) domain.User {
	return domain.User{ID: id, Username: id, Status: domain.StatusActive}
}

func ptr[T any](v T) *T { return &v }

// Losing your own admin rights leaves nobody able to give them back to you.
func TestSelfDemotionRefused(t *testing.T) {
	uc, _, _ := harness(admin("admin-1"), admin("admin-2"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "admin-1", ActorUserID: "admin-1", IsAdmin: ptr(false),
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
		ID: "admin-1", ActorUserID: "", IsAdmin: ptr(false),
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
		ID: "admin-2", ActorUserID: "admin-1", IsAdmin: ptr(false),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.IsAdmin {
		t.Fatal("is_admin was not cleared")
	}
	if !contains(auditor.actions, domain.ActionAdminRevoked) {
		t.Fatalf("audit actions = %v, want an admin_revoked entry", auditor.actions)
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
