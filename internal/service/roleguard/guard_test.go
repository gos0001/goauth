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
	g := New(nil)
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
	g := New(nil)

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
	admin := domain.Role{Name: domain.RoleAdmin, Rank: domain.RankAdmin}
	super := domain.Role{Name: domain.RoleSuperAdmin, Rank: domain.RankSuperAdmin}
	manager := domain.Role{Name: domain.RoleManager, Rank: domain.RankManager}

	cases := []struct {
		name       string
		actor      domain.Role
		targetRank int
		want       error
	}{
		{"admin over user", admin, domain.RankUser, nil},
		{"admin over manager", admin, domain.RankManager, nil},
		{"admin over admin", admin, domain.RankAdmin, domain.ErrInsufficientRank},
		{"admin over superadmin", admin, domain.RankSuperAdmin, domain.ErrInsufficientRank},
		{"manager over user", manager, domain.RankUser, nil},
		{"manager over manager", manager, domain.RankManager, domain.ErrInsufficientRank},
		// The one exception: the top of the ladder manages itself, or a
		// redundant superadmin could never be demoted.
		{"superadmin over superadmin", super, domain.RankSuperAdmin, nil},
		{"superadmin over admin", super, domain.RankAdmin, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanActOnUser(tc.actor, tc.targetRank)
			if !errors.Is(got, tc.want) {
				t.Fatalf("err = %v, want %v", got, tc.want)
			}
		})
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
