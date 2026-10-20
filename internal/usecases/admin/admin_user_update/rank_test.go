package admin_user_update

import (
	"context"
	"errors"
	"testing"

	"github.com/gos0001/goauth/internal/domain"
)

// The whole point of the hierarchy: an admin must not be able to block,
// rename or otherwise manage another admin. Rank decides, not permission
// lists — the blocking admin holds users:update like any other.
func TestAdminCannotManageAdmin(t *testing.T) {
	uc, _, _ := harnessWith(adminGuard(), admin("admin-1"), admin("admin-2"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "admin-2", ActorUserID: "admin-1", Status: ptr(string(domain.StatusBlocked)),
	})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
	}
}

// Assigning a role at or above the actor's own rank is manufacturing a peer
// or a superior.
func TestAdminCannotAssignAdminRole(t *testing.T) {
	uc, _, _ := harnessWith(adminGuard(), admin("admin-1"), member("user-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", ActorUserID: "admin-1", Role: ptr(domain.RoleAdmin),
	})
	if !errors.Is(err, domain.ErrInsufficientRank) {
		t.Fatalf("err = %v, want ErrInsufficientRank", err)
	}
}

// The top exception: a superadmin may demote another superadmin — someone
// has to be able to clean up a redundant one.
func TestSuperAdminCanDemoteSuperAdmin(t *testing.T) {
	uc, _, auditor := harness(admin("super-1"), admin("super-2"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "super-2", ActorUserID: "super-1", Role: ptr(domain.RoleAdmin),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !contains(auditor.actions, domain.ActionRoleAssigned) {
		t.Fatalf("audit actions = %v, want role_assigned", auditor.actions)
	}
}

// Admin over plain users still works: the hierarchy gates peers and
// superiors, not the everyday case.
func TestAdminStillManagesUsers(t *testing.T) {
	uc, _, _ := harnessWith(adminGuard(), admin("admin-1"), member("user-1"))

	_, err := uc.Execute(context.Background(), Input{
		ID: "user-1", ActorUserID: "admin-1", Role: ptr(domain.RoleManager),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
}
