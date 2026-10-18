package auth

import (
	"context"
	"slices"

	"github.com/Vadim-27/bookit-api/internal/user"
)

// Permission is the key of an action a role may allow, e.g. "workspaces.create".
type Permission string

// Platform permissions (security.md, group 4). Workspace permissions are added
// together with workspaces. The privacy exceptions workspaces.support_access and
// workspaces.archive.view are deliberately absent: they will come with their
// audit trail and time limit, so nobody can hold them by accident.
const (
	PermWorkspacesView    Permission = "workspaces.view"
	PermWorkspacesCreate  Permission = "workspaces.create"
	PermWorkspacesEdit    Permission = "workspaces.edit"
	PermWorkspacesSuspend Permission = "workspaces.suspend"
	PermWorkspacesArchive Permission = "workspaces.archive"
	PermWorkspacesRestore Permission = "workspaces.restore"

	PermPlansView Permission = "plans.view"
	PermPlansEdit Permission = "plans.edit"

	PermSubscriptionsView Permission = "subscriptions.view"
	PermSubscriptionsEdit Permission = "subscriptions.edit"

	PermWorkspaceFeaturesEdit Permission = "workspace_features.edit"

	PermPlatformAdminsView    Permission = "platform_admins.view"
	PermPlatformAdminsInvite  Permission = "platform_admins.invite"
	PermPlatformAdminsEdit    Permission = "platform_admins.edit"
	PermPlatformAdminsSuspend Permission = "platform_admins.suspend"
	PermPlatformAdminsDelete  Permission = "platform_admins.delete"

	PermPlatformRolesView   Permission = "platform_roles.view"
	PermPlatformRolesCreate Permission = "platform_roles.create"
	PermPlatformRolesEdit   Permission = "platform_roles.edit"
	PermPlatformRolesDelete Permission = "platform_roles.delete"

	PermPlatformAuditView Permission = "platform_audit.view"
	PermPlatformStatsView Permission = "platform_stats.view"
)

// platformPermissions lists every platform permission.
var platformPermissions = []Permission{
	PermWorkspacesView, PermWorkspacesCreate, PermWorkspacesEdit,
	PermWorkspacesSuspend, PermWorkspacesArchive, PermWorkspacesRestore,
	PermPlansView, PermPlansEdit,
	PermSubscriptionsView, PermSubscriptionsEdit,
	PermWorkspaceFeaturesEdit,
	PermPlatformAdminsView, PermPlatformAdminsInvite, PermPlatformAdminsEdit,
	PermPlatformAdminsSuspend, PermPlatformAdminsDelete,
	PermPlatformRolesView, PermPlatformRolesCreate, PermPlatformRolesEdit, PermPlatformRolesDelete,
	PermPlatformAuditView, PermPlatformStatsView,
}

// Principal is the authenticated user of a request, with the permissions
// resolved for this very request.
type Principal struct {
	UserID       string
	Email        string
	FullName     string
	IsSuperAdmin bool
	permissions  []Permission // sorted and unique, for binary search
}

// NewPrincipal returns a Principal holding perms.
func NewPrincipal(userID, email, fullName string, isSuperAdmin bool, perms ...Permission) *Principal {
	sorted := slices.Clone(perms)
	slices.Sort(sorted)
	return &Principal{
		UserID:       userID,
		Email:        email,
		FullName:     fullName,
		IsSuperAdmin: isSuperAdmin,
		permissions:  slices.Compact(sorted),
	}
}

// Has reports whether the principal holds perm.
func (p *Principal) Has(perm Permission) bool {
	_, found := slices.BinarySearch(p.permissions, perm)
	return found
}

// Permissions returns a sorted copy of the principal's permissions; never nil.
func (p *Principal) Permissions() []Permission {
	return append([]Permission{}, p.permissions...)
}

// principalFor resolves the permissions of u. First iteration (security.md):
// a static mapping — a super admin holds every platform permission, anyone else
// none yet. Roles from the database replace it together with workspaces.
func principalFor(u *user.User) *Principal {
	var perms []Permission
	if u.IsSuperAdmin {
		perms = platformPermissions
	}
	return NewPrincipal(u.ID, u.Email, u.FullName, u.IsSuperAdmin, perms...)
}

type principalKey struct{}

// WithPrincipal returns a copy of ctx that carries p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal stored in ctx by WithPrincipal.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
