package httpapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/auth/httpapi"
	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
)

const (
	superAdminToken = "token-of-the-super-admin"
	ordinaryToken   = "token-of-an-ordinary-user"
	platformPath    = "/api/v1/platform/check"
)

// rbacServer builds the real server with the auth routes and one platform route
// guarded the way platform endpoints will be: authenticated, then permitted.
func rbacServer(fake *fakeAuth, logs *bytes.Buffer) *echo.Echo {
	h := httpapi.New(fake, httpapi.Options{})
	return httpserver.New(slog.New(slog.NewJSONHandler(logs, nil)), httpserver.Options{},
		func(api *echo.Group) { h.Register(api, noLimits()) },
		func(api *echo.Group) {
			platform := api.Group("/platform", h.RequireAuth)
			platform.GET("/check", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) },
				httpapi.RequirePermission(auth.PermWorkspacesCreate))
		},
	)
}

func newRBACFake() *fakeAuth {
	return &fakeAuth{callers: map[string]*auth.Principal{
		superAdminToken: auth.NewPrincipal("admin-1", "boss@example.com", "Boss", true,
			auth.PermWorkspacesCreate, auth.PermWorkspacesView),
		ordinaryToken: auth.NewPrincipal("user-2", "staff@example.com", "Staff", false),
	}}
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// The access matrix of lesson 9, adapted to BookIt: who gets 200, 401 or 403.
func TestAccessMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		path       string
		mutate     func(*http.Request)
		wantStatus int
		wantCode   string
	}{
		{"me without a token", "/api/v1/me", nil, http.StatusUnauthorized, apierror.CodeUnauthenticated},
		{"me with an invalid token", "/api/v1/me", bearer("forged"), http.StatusUnauthorized, apierror.CodeUnauthenticated},
		{"me as an ordinary user", "/api/v1/me", bearer(ordinaryToken), http.StatusOK, ""},
		{"me as the super admin", "/api/v1/me", bearer(superAdminToken), http.StatusOK, ""},

		{"platform without a token", platformPath, nil, http.StatusUnauthorized, apierror.CodeUnauthenticated},
		{"platform with an invalid token", platformPath, bearer("forged"), http.StatusUnauthorized, apierror.CodeUnauthenticated},
		{"platform as an ordinary user", platformPath, bearer(ordinaryToken), http.StatusForbidden, apierror.CodeForbidden},
		{"platform as the super admin", platformPath, bearer(superAdminToken), http.StatusNoContent, ""},

		{"unknown platform path stays 404", "/api/v1/platform/nope", bearer(ordinaryToken), http.StatusNotFound, apierror.CodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			rec := do(rbacServer(newRBACFake(), &logs), http.MethodGet, tt.path, "", tt.mutate)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantCode != "" {
				if got := errorOf(t, rec); got.Code != tt.wantCode {
					t.Errorf("code: got %q, want %q", got.Code, tt.wantCode)
				}
			}
			if rec.Code == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("a 401 must carry the WWW-Authenticate challenge")
			}
		})
	}
}

func TestRequireAuth_ReadsOnlyAWellFormedBearerHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*http.Request)
		ok     bool
	}{
		{"bearer", bearer(ordinaryToken), true},
		{"scheme is case-insensitive", func(r *http.Request) { r.Header.Set("Authorization", "bearer "+ordinaryToken) }, true},
		{"extra spaces around the token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer   "+ordinaryToken+"  ") }, true},
		{"basic scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic "+ordinaryToken) }, false},
		{"no scheme", func(r *http.Request) { r.Header.Set("Authorization", ordinaryToken) }, false},
		{"empty token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer   ") }, false},
		{"oversized header", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 5000)) }, false},
		{"token in the query string is ignored", func(r *http.Request) { r.URL.RawQuery = "access_token=" + ordinaryToken }, false},
		{"token in a cookie is ignored", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "access_token", Value: ordinaryToken})
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake := newRBACFake()
			var logs bytes.Buffer
			rec := do(rbacServer(fake, &logs), http.MethodGet, "/api/v1/me", "", tt.mutate)

			if got := rec.Code == http.StatusOK; got != tt.ok {
				t.Errorf("accepted: got %v (status %d), want %v", got, rec.Code, tt.ok)
			}
			if !tt.ok && fake.gotAccessToken == ordinaryToken {
				t.Error("a token from a rejected place reached the service")
			}
		})
	}
}

func TestRequireAuth_ServiceFailureIsAServerError(t *testing.T) {
	t.Parallel()

	fake := newRBACFake()
	fake.authErr = errors.New("db-internal-host refused")
	var logs bytes.Buffer
	rec := do(rbacServer(fake, &logs), http.MethodGet, "/api/v1/me", "", bearer(ordinaryToken))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "db-internal-host") {
		t.Errorf("the response leaks the cause: %s", rec.Body)
	}
	if strings.Contains(logs.String(), ordinaryToken) {
		t.Errorf("the log contains the access token: %s", logs.String())
	}
}

func TestMe(t *testing.T) {
	t.Parallel()

	type me struct {
		ID           string   `json:"id"`
		Email        string   `json:"email"`
		FullName     string   `json:"full_name"`
		IsSuperAdmin bool     `json:"is_super_admin"`
		Permissions  []string `json:"permissions"`
	}
	tests := []struct {
		name      string
		token     string
		want      me
		wantPerms int
	}{
		{"super admin", superAdminToken, me{ID: "admin-1", Email: "boss@example.com", FullName: "Boss", IsSuperAdmin: true}, 2},
		{"ordinary user", ordinaryToken, me{ID: "user-2", Email: "staff@example.com", FullName: "Staff"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer
			rec := do(rbacServer(newRBACFake(), &logs), http.MethodGet, "/api/v1/me", "", bearer(tt.token))
			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d, want %d", rec.Code, http.StatusOK)
			}

			var got me
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.ID != tt.want.ID || got.Email != tt.want.Email || got.FullName != tt.want.FullName || got.IsSuperAdmin != tt.want.IsSuperAdmin {
				t.Errorf("me: got %+v, want %+v", got, tt.want)
			}
			if len(got.Permissions) != tt.wantPerms {
				t.Errorf("permissions: got %v, want %d of them", got.Permissions, tt.wantPerms)
			}
			// An empty list must be [], not null: the interface iterates it.
			if !strings.Contains(rec.Body.String(), `"permissions":[`) {
				t.Errorf("permissions must be a JSON array: %s", rec.Body)
			}
			for _, field := range []string{"password", "hash", "status"} {
				if strings.Contains(strings.ToLower(rec.Body.String()), field) {
					t.Errorf("me leaks %q: %s", field, rec.Body)
				}
			}
		})
	}
}

func TestRequirePermission_WithoutRequireAuthFailsClosed(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	e := httpserver.New(slog.New(slog.NewJSONHandler(&logs, nil)), httpserver.Options{},
		func(api *echo.Group) {
			// A mistake: the permission check without authentication before it.
			api.GET("/oops", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) },
				httpapi.RequirePermission(auth.PermWorkspacesView))
		})

	rec := do(e, http.MethodGet, "/api/v1/oops", "", bearer(superAdminToken))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want %d: a missing RequireAuth must never open the route", rec.Code, http.StatusUnauthorized)
	}
}
