package roleguard

import (
	"context"
	"errors"
	"testing"

	"github.com/gos0001/goauth/v2/internal/domain"
)

type fakePostgres struct {
	role    domain.Role
	userIDs map[string]bool
}

func (f *fakePostgres) ActorRole(_ context.Context, userID string) (domain.Role, error) {
	if !f.userIDs[userID] {
		return domain.Role{}, domain.ErrUserNotFound
	}
	return f.role, nil
}

func TestActorFromDatabase(t *testing.T) {
	g := New(nil, Config{})
	g.postgres = &fakePostgres{
		role:    domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin},
		userIDs: map[string]bool{"u-1": true},
	}

	role, err := g.Actor(context.Background(), "u-1")
	if err != nil {
		t.Fatalf("Actor: %v", err)
	}
	if role.Rank != domain.RankAdmin {
		t.Fatalf("rank = %d, want %d", role.Rank, domain.RankAdmin)
	}

	if _, err := g.Actor(context.Background(), "nope"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

// The machine caller on the private listener holds everything; modelling it
// as a superadmin keeps one code path instead of two.
func TestMachineActorIsSuperAdmin(t *testing.T) {
	g := New(nil, Config{})

	role, err := g.Actor(context.Background(), "")
	if err != nil {
		t.Fatalf("Actor: %v", err)
	}
	if role.Rank != domain.RankSuperAdmin {
		t.Fatalf("rank = %d, want superadmin", role.Rank)
	}
	for _, p := range domain.AllPermissions() {
		if !role.Has(p) {
			t.Fatalf("machine actor lacks %s", p)
		}
	}
}

func TestCanActOnUser(t *testing.T) {
	off := New(nil, Config{})
	delegated := New(nil, Config{Ownership: ModeDelegated})

	admin := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin}
	super := domain.Role{Name: domain.RoleSuperAdmin, Rank: domain.RankSuperAdmin}
	manager := domain.Role{Name: domain.RoleManager, Rank: domain.RankManager}
	adminReadAll := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin,
		Permissions: []domain.Permission{domain.PermUsersReadAll}}
	adminManageAll := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin,
		Permissions: []domain.Permission{domain.PermUsersManageAll}}

	userRole := domain.Role{Name: domain.RoleUser, Rank: domain.RankUser}
	owned := domain.User{ID: "u-9", Role: domain.RoleUser, CreatedBy: "admin-1"}
	foreign := domain.User{ID: "u-9", Role: domain.RoleUser, CreatedBy: "someone-else"}

	cases := []struct {
		name  string
		g     *Guard
		actor domain.Role
		// target is the user under management; its role supplies the rank.
		target     domain.User
		targetRole domain.Role
		actorID    string
		want       error
	}{
		{"admin over user", off, admin, owned, userRole, "admin-1", nil},
		{"admin over admin", off, admin, owned, admin, "admin-1", domain.ErrInsufficientRank},
		{"admin over superadmin", off, admin, owned, super, "admin-1", domain.ErrInsufficientRank},
		{"manager over user", off, manager, owned, userRole, "admin-1", nil},
		// The one exception: the top of the ladder manages itself, or a
		// redundant superadmin could never be demoted.
		{"superadmin over superadmin", off, super, owned, super, "super-1", nil},

		// Delegated mode adds ownership to the rank rule.
		{"delegated: own creation", delegated, admin, owned, userRole, "admin-1", nil},
		{"delegated: foreign creation", delegated, admin, foreign, userRole, "admin-1", domain.ErrUserNotOwned},
		{"delegated: manage_all exception", delegated, adminManageAll, foreign, userRole, "admin-1", nil},
		{"delegated: read_all is no manage exception", delegated, adminReadAll, foreign, userRole, "admin-1", domain.ErrUserNotOwned},
		{"delegated: superadmin owns everything", delegated, super, foreign, userRole, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.g.CanActOnUser(tc.actor, tc.actorID, tc.target, tc.targetRole)
			if !errors.Is(got, tc.want) {
				t.Fatalf("err = %v, want %v", got, tc.want)
			}
		})
	}
}

// The read side: every way out of scope is a 404, so an equal or a superior
// does not become confirmed by the error code.
func TestCanSeeUser(t *testing.T) {
	delegated := New(nil, Config{Ownership: ModeDelegated})
	admin := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin}
	userRole := domain.Role{Name: domain.RoleUser, Rank: domain.RankUser}
	owned := domain.User{ID: "u-9", Role: domain.RoleUser, CreatedBy: "admin-1"}
	foreign := domain.User{ID: "u-9", Role: domain.RoleUser, CreatedBy: "someone-else"}

	if err := delegated.CanSeeUser(admin, "admin-1", owned, userRole); err != nil {
		t.Fatalf("own creation should be visible: %v", err)
	}
	if err := delegated.CanSeeUser(admin, "admin-1", foreign, userRole); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
	if err := delegated.CanSeeUser(admin, "admin-1", foreign, admin); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound for a peer", err)
	}
}

// The list/count filters: nothing in off mode or for superadmins, rank +
// owner otherwise, with users:read_all dropping the owner half.
func TestUserVisibility(t *testing.T) {
	off := New(nil, Config{})
	delegated := New(nil, Config{Ownership: ModeDelegated})
	admin := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin}
	super := domain.Role{Name: domain.RoleSuperAdmin, Rank: domain.RankSuperAdmin}
	adminReadAll := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin,
		Permissions: []domain.Permission{domain.PermUsersReadAll}}

	if apply, _, _ := off.UserVisibility(admin, "admin-1"); apply {
		t.Fatal("off mode must not filter")
	}
	if apply, _, _ := delegated.UserVisibility(super, ""); apply {
		t.Fatal("superadmin must not be filtered")
	}
	if apply, rank, owner := delegated.UserVisibility(admin, "admin-1"); !apply || rank != domain.RankAdmin || owner != "admin-1" {
		t.Fatalf("apply=%v rank=%d owner=%q, want true/%d/admin-1", apply, rank, owner, domain.RankAdmin)
	}
	if apply, rank, owner := delegated.UserVisibility(adminReadAll, "admin-1"); !apply || rank != domain.RankAdmin || owner != "" {
		t.Fatalf("apply=%v rank=%d owner=%q, want true/%d/\"\" for read_all", apply, rank, owner, domain.RankAdmin)
	}
}

func TestMayPlaceInRole(t *testing.T) {
	actor := domain.Role{
		Name:        domain.RoleAdmin,
		Rank:        domain.RankAdmin,
		Permissions: []domain.Permission{domain.PermUsersRead, domain.PermUsersUpdate},
	}

	if err := MayPlaceInRole(actor, []domain.Permission{domain.PermUsersRead}); err != nil {
		t.Fatalf("held permissions should pass: %v", err)
	}

	// The Kubernetes rule: granting what you lack turns roles:manage into
	// full escalation.
	err := MayPlaceInRole(actor, []domain.Permission{domain.PermUsersDelete})
	if !errors.Is(err, domain.ErrPermissionNotHeld) {
		t.Fatalf("err = %v, want ErrPermissionNotHeld", err)
	}

	// A name outside the vocabulary would never be checked by anything.
	err = MayPlaceInRole(actor, []domain.Permission{"users:nuke"})
	if !errors.Is(err, domain.ErrPermissionUnknown) {
		t.Fatalf("err = %v, want ErrPermissionUnknown", err)
	}

	// Empty is valid: rank only.
	if err := MayPlaceInRole(actor, nil); err != nil {
		t.Fatalf("empty permission set should pass: %v", err)
	}
}
