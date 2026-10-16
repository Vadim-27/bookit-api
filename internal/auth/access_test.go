package auth_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/user"
)

// accessToken issues a user access token for id with the env's clock.
func accessToken(t *testing.T, e *env, id string) string {
	t.Helper()
	token, _, err := e.tokens.Issue(id, auth.SubjectUser, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

func TestAuthenticate_ResolvesTheCaller(t *testing.T) {
	t.Parallel()

	t.Run("super admin holds every platform permission", func(t *testing.T) {
		t.Parallel()

		users := activeBoss(t)
		users["boss@example.com"].IsSuperAdmin = true
		e := newEnv(t, users)

		p, err := e.auth.Authenticate(context.Background(), accessToken(t, e, "user-1"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if p.UserID != "user-1" || p.Email != "boss@example.com" || !p.IsSuperAdmin {
			t.Errorf("principal: got %+v", p)
		}
		for _, perm := range []auth.Permission{auth.PermWorkspacesCreate, auth.PermPlansEdit, auth.PermPlatformAuditView} {
			if !p.Has(perm) {
				t.Errorf("a super admin lacks %q", perm)
			}
		}
		perms := p.Permissions()
		if !slices.IsSorted(perms) || len(perms) == 0 {
			t.Errorf("permissions must be a sorted non-empty list: %v", perms)
		}
	})

	t.Run("an ordinary user holds no platform permission", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		p, err := e.auth.Authenticate(context.Background(), accessToken(t, e, "user-1"))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if p.Has(auth.PermWorkspacesView) || len(p.Permissions()) != 0 {
			t.Errorf("an ordinary user has permissions: %v", p.Permissions())
		}
		if p.Permissions() == nil {
			t.Error("Permissions must never be nil (it becomes JSON null)")
		}
	})
}

func TestAuthenticate_Rejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status user.Status
		token  func(t *testing.T, e *env) string
	}{
		{"garbage", user.StatusActive, func(*testing.T, *env) string { return "not.a.jwt" }},
		{"empty", user.StatusActive, func(*testing.T, *env) string { return "" }},
		{"client token", user.StatusActive, func(t *testing.T, e *env) string {
			token, _, err := e.tokens.Issue("user-1", auth.SubjectClient, "ws-1")
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			return token
		}},
		{"unknown user", user.StatusActive, func(t *testing.T, e *env) string { return accessToken(t, e, "ghost") }},
		{"suspended user", user.StatusSuspended, func(t *testing.T, e *env) string { return accessToken(t, e, "user-1") }},
		{"invited user", user.StatusPendingInvite, func(t *testing.T, e *env) string { return accessToken(t, e, "user-1") }},
		{"expired token", user.StatusActive, func(t *testing.T, e *env) string {
			token := accessToken(t, e, "user-1")
			e.clock.Advance(16 * time.Minute)
			return token
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			users := activeBoss(t)
			users["boss@example.com"].Status = tt.status
			e := newEnv(t, users)

			p, err := e.auth.Authenticate(context.Background(), tt.token(t, e))
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("got %v, want ErrInvalidToken", err)
			}
			if p != nil {
				t.Errorf("a principal was returned together with an error: %+v", p)
			}
		})
	}
}

func TestAuthenticate_StorageFailureIsNotHiddenAsAnInvalidToken(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	token := accessToken(t, e, "user-1")
	e.users.err = errors.New("database is down")

	_, err := e.auth.Authenticate(context.Background(), token)
	if err == nil || errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("got %v, want a storage error", err)
	}
}

func TestPrincipal(t *testing.T) {
	t.Parallel()

	p := auth.NewPrincipal("u", "u@example.com", "U", false,
		auth.PermPlansView, auth.PermWorkspacesView, auth.PermPlansView)

	if got := p.Permissions(); !slices.Equal(got, []auth.Permission{auth.PermPlansView, auth.PermWorkspacesView}) {
		t.Errorf("permissions must be sorted and unique: %v", got)
	}
	if !p.Has(auth.PermWorkspacesView) || p.Has(auth.PermPlansEdit) {
		t.Error("Has answers wrongly")
	}

	// A copy: changing it must not change the principal.
	p.Permissions()[0] = auth.PermPlatformAdminsDelete
	if p.Has(auth.PermPlatformAdminsDelete) {
		t.Error("Permissions returned the internal slice, not a copy")
	}

	ctx := auth.WithPrincipal(context.Background(), p)
	if got, ok := auth.PrincipalFrom(ctx); !ok || got != p {
		t.Errorf("PrincipalFrom: got %v, %v", got, ok)
	}
	if _, ok := auth.PrincipalFrom(context.Background()); ok {
		t.Error("PrincipalFrom found a principal in an empty context")
	}
}
