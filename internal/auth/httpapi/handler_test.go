package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/auth/httpapi"
	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
	"github.com/Vadim-27/bookit-api/internal/platform/ratelimit"
)

const (
	loginPath   = "/api/v1/auth/login"
	refreshPath = "/api/v1/auth/refresh"
	logoutPath  = "/api/v1/auth/logout"
	cookieName  = "bookit_refresh"
)

var (
	accessExpires  = time.Date(2026, 10, 14, 12, 15, 0, 0, time.UTC)
	refreshExpires = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
)

// fakeAuth is a fake Authenticator that records what it was asked.
type fakeAuth struct {
	session *auth.Session
	err     error // returned by Login, Refresh and Logout

	logins, refreshes, logouts int
	gotEmail, gotPassword      string
	gotRefreshToken            string

	// Authenticate answers from tokens: an access token maps to its caller.
	// An unknown token is invalid; authErr, when set, is returned instead.
	callers        map[string]*auth.Principal
	authErr        error
	authenticates  int
	gotAccessToken string
}

func (f *fakeAuth) Authenticate(_ context.Context, token string) (*auth.Principal, error) {
	f.authenticates++
	f.gotAccessToken = token
	if f.authErr != nil {
		return nil, f.authErr
	}
	if p, ok := f.callers[token]; ok {
		return p, nil
	}
	return nil, auth.ErrInvalidToken
}

func newSession() *auth.Session {
	return &auth.Session{
		AccessToken:      "the.access.jwt",
		AccessExpiresAt:  accessExpires,
		RefreshToken:     "the-refresh-token-value-0123456789abcdefghijk",
		RefreshExpiresAt: refreshExpires,
	}
}

func (f *fakeAuth) Login(_ context.Context, email, password string) (*auth.Session, error) {
	f.logins++
	f.gotEmail, f.gotPassword = email, password
	return f.session, f.err
}

func (f *fakeAuth) Refresh(_ context.Context, token string) (*auth.Session, error) {
	f.refreshes++
	f.gotRefreshToken = token
	return f.session, f.err
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.logouts++
	f.gotRefreshToken = token
	return f.err
}

func noLimit(next echo.HandlerFunc) echo.HandlerFunc { return next }

func noLimits() httpapi.Limits {
	return httpapi.Limits{Login: noLimit, Refresh: noLimit, Logout: noLimit}
}

// newServer builds the real server with the auth routes on top of a fake service.
func newServer(fake *fakeAuth, opts httpapi.Options, limits httpapi.Limits, logs *bytes.Buffer) *echo.Echo {
	h := httpapi.New(fake, opts)
	return httpserver.New(slog.New(slog.NewJSONHandler(logs, nil)), httpserver.Options{},
		func(api *echo.Group) { h.Register(api, limits) })
}

func do(e *echo.Echo, method, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:5555"
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func withCookie(value string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: cookieName, Value: value}) }
}

func errorOf(t *testing.T, rec *httptest.ResponseRecorder) apierror.Detail {
	t.Helper()
	var body apierror.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not the error envelope: %v", rec.Body, err)
	}
	return body.Error
}

// refreshCookie returns the refresh cookie set by the response, or nil.
func refreshCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	return nil
}

func assertCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	c := refreshCookie(rec)
	if c == nil || c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("the refresh cookie must be cleared (empty value, MaxAge < 0): %+v", c)
	}
	if c != nil && (!c.HttpOnly || c.Path != "/api/v1/auth") {
		t.Errorf("the clearing cookie must keep the attributes of the original: %+v", c)
	}
}

type tokenBody struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken *string   `json:"refresh_token"`
}

func TestLogin_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		opts       httpapi.Options
		wantSecure bool
	}{
		{"local development", httpapi.Options{}, false},
		{"deployed environment", httpapi.Options{SecureCookies: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeAuth{session: newSession()}
			var logs bytes.Buffer
			e := newServer(fake, tt.opts, noLimits(), &logs)

			rec := do(e, http.MethodPost, loginPath, `{"email":"boss@example.com","password":"correct-horse-battery"}`, nil)

			if rec.Code != http.StatusOK {
				t.Fatalf("status: got %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body)
			}
			var got tokenBody
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if got.AccessToken != "the.access.jwt" || got.TokenType != "Bearer" || !got.ExpiresAt.Equal(accessExpires) {
				t.Errorf("response: got %+v", got)
			}
			if got.RefreshToken != nil || strings.Contains(rec.Body.String(), "refresh") {
				t.Errorf("the refresh token must not be in the body: %s", rec.Body)
			}

			c := refreshCookie(rec)
			if c == nil {
				t.Fatal("no refresh cookie was set")
			}
			if c.Value != newSession().RefreshToken || !c.Expires.Equal(refreshExpires) {
				t.Errorf("cookie value or expiry wrong: %+v", c)
			}
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/api/v1/auth" || c.Secure != tt.wantSecure {
				t.Errorf("cookie attributes: HttpOnly %v, SameSite %v, Path %q, Secure %v; want HttpOnly, Strict, /api/v1/auth, Secure %v",
					c.HttpOnly, c.SameSite, c.Path, c.Secure, tt.wantSecure)
			}

			if fake.gotEmail != "boss@example.com" || fake.gotPassword != "correct-horse-battery" {
				t.Errorf("service got %q / %q", fake.gotEmail, fake.gotPassword)
			}
			for _, secret := range []string{"correct-horse-battery", "the.access.jwt", newSession().RefreshToken} {
				if strings.Contains(logs.String(), secret) {
					t.Errorf("the log contains a secret %q: %s", secret, logs.String())
				}
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("a token response must not be cacheable, Cache-Control: %q", rec.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestLogin_WrongCredentialsAreAnsweredGenerically(t *testing.T) {
	t.Parallel()

	fake := &fakeAuth{err: auth.ErrInvalidCredentials}
	var logs bytes.Buffer
	rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, loginPath,
		`{"email":"x@example.com","password":"whatever-password"}`, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	want := apierror.Detail{Code: apierror.CodeInvalidCredentials, Message: "invalid credentials"}
	if got := errorOf(t, rec); got != want {
		t.Errorf("error: got %+v, want %+v", got, want)
	}
	if c := refreshCookie(rec); c != nil {
		t.Errorf("a failed login must not set a cookie: %+v", c)
	}
}

func TestLogin_ServiceFailureIsAGenericServerError(t *testing.T) {
	t.Parallel()

	fake := &fakeAuth{err: errors.New("connection to db-internal-host refused")}
	var logs bytes.Buffer
	rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, loginPath,
		`{"email":"x@example.com","password":"secret-password-1"}`, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), "db-internal-host") {
		t.Errorf("the response leaks the cause: %s", rec.Body)
	}
	if !strings.Contains(logs.String(), "db-internal-host") {
		t.Errorf("the log lacks the cause: %s", logs.String())
	}
	if strings.Contains(logs.String(), "secret-password-1") {
		t.Errorf("the log contains the password: %s", logs.String())
	}
}

func TestLogin_BadRequestsNeverReachTheService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{"unknown field", "application/json", `{"email":"a@b.com","password":"x","role":"super_admin"}`, http.StatusBadRequest},
		{"broken json", "application/json", `{"email":`, http.StatusBadRequest},
		{"two objects", "application/json", `{"email":"a@b.com"}{"email":"c@d.com"}`, http.StatusBadRequest},
		{"wrong field type", "application/json", `{"email":1}`, http.StatusBadRequest},
		{"empty body", "application/json", ``, http.StatusBadRequest},
		{"not json", "text/plain", `{"email":"a@b.com"}`, http.StatusUnsupportedMediaType},
		{"body too large", "application/json", `{"email":"` + strings.Repeat("a", 5000) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeAuth{}
			var logs bytes.Buffer
			e := newServer(fake, httpapi.Options{}, noLimits(), &logs)

			rec := do(e, http.MethodPost, loginPath, tt.body, func(r *http.Request) { r.Header.Set("Content-Type", tt.contentType) })

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			if fake.logins != 0 {
				t.Errorf("the service was called %d times for a bad request", fake.logins)
			}
		})
	}
}

func TestRefresh_Success(t *testing.T) {
	t.Parallel()

	fake := &fakeAuth{session: newSession()}
	var logs bytes.Buffer
	e := newServer(fake, httpapi.Options{SecureCookies: true}, noLimits(), &logs)

	rec := do(e, http.MethodPost, refreshPath, "", withCookie("old-refresh-token"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body)
	}
	if fake.gotRefreshToken != "old-refresh-token" {
		t.Errorf("the service got token %q, want the one from the cookie", fake.gotRefreshToken)
	}
	var got tokenBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.AccessToken != "the.access.jwt" || got.RefreshToken != nil {
		t.Errorf("response: got %+v (err %v)", got, err)
	}
	c := refreshCookie(rec)
	if c == nil || c.Value != newSession().RefreshToken || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("the rotated token must replace the cookie: %+v", c)
	}
	for _, secret := range []string{"old-refresh-token", newSession().RefreshToken} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log contains a refresh token: %s", logs.String())
		}
	}
}

func TestRefresh_Failures(t *testing.T) {
	t.Parallel()

	t.Run("no cookie", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{session: newSession()}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, refreshPath, "", nil)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if got := errorOf(t, rec); got.Code != apierror.CodeUnauthenticated {
			t.Errorf("code: got %q, want %q", got.Code, apierror.CodeUnauthenticated)
		}
		if fake.refreshes != 0 {
			t.Errorf("the service was called %d times without a token", fake.refreshes)
		}
		assertCleared(t, rec)
	})

	t.Run("invalid or reused token", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{err: auth.ErrInvalidToken}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, refreshPath, "", withCookie("stolen"))

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		assertCleared(t, rec)
	})

	t.Run("service failure", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{err: errors.New("db-internal-host refused")}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, refreshPath, "", withCookie("some-token"))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		if strings.Contains(rec.Body.String(), "db-internal-host") {
			t.Errorf("the response leaks the cause: %s", rec.Body)
		}
		if refreshCookie(rec) != nil {
			t.Error("a server failure must not touch the cookie: the user may retry")
		}
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()

	t.Run("with a cookie", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, logoutPath, "", withCookie("my-refresh-token"))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNoContent)
		}
		if fake.logouts != 1 || fake.gotRefreshToken != "my-refresh-token" {
			t.Errorf("the service got %d calls, token %q", fake.logouts, fake.gotRefreshToken)
		}
		assertCleared(t, rec)
	})

	t.Run("without a cookie it is still fine", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, logoutPath, "", nil)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d", rec.Code, http.StatusNoContent)
		}
		if fake.logouts != 0 {
			t.Errorf("the service was called %d times without a token", fake.logouts)
		}
		assertCleared(t, rec)
	})

	t.Run("service failure", func(t *testing.T) {
		t.Parallel()

		fake := &fakeAuth{err: errors.New("db-internal-host refused")}
		var logs bytes.Buffer
		rec := do(newServer(fake, httpapi.Options{}, noLimits(), &logs), http.MethodPost, logoutPath, "", withCookie("my-refresh-token"))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status: got %d, want %d: the user must know the session may still be alive", rec.Code, http.StatusInternalServerError)
		}
	})
}

func TestOnlyPostIsAllowed(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	e := newServer(&fakeAuth{}, httpapi.Options{}, noLimits(), &logs)

	for _, path := range []string{loginPath, refreshPath, logoutPath} {
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want %d", method, path, rec.Code, http.StatusMethodNotAllowed)
			}
		}
	}
}

func TestEndpointsAreRateLimited(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		path  string
		body  string
		mut   func(*http.Request)
		calls func(*fakeAuth) int
	}{
		{"login", loginPath, `{"email":"x@example.com","password":"guess-number-1"}`, nil, func(f *fakeAuth) int { return f.logins }},
		{"refresh", refreshPath, "", withCookie("some-token"), func(f *fakeAuth) int { return f.refreshes }},
		{"logout", logoutPath, "", withCookie("some-token"), func(f *fakeAuth) int { return f.logouts }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeAuth{err: auth.ErrInvalidCredentials}
			var logs bytes.Buffer
			limits := httpapi.Limits{
				Login:   ratelimit.PerMinute(60, 2),
				Refresh: ratelimit.PerMinute(60, 2),
				Logout:  ratelimit.PerMinute(60, 2),
			}
			e := newServer(fake, httpapi.Options{}, limits, &logs)

			for i := 1; i <= 2; i++ {
				if rec := do(e, http.MethodPost, tt.path, tt.body, tt.mut); rec.Code == http.StatusTooManyRequests {
					t.Fatalf("attempt %d within the burst was limited", i)
				}
			}
			rec := do(e, http.MethodPost, tt.path, tt.body, tt.mut)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt over the limit: got %d, want %d", rec.Code, http.StatusTooManyRequests)
			}
			if got := errorOf(t, rec); got.Code != apierror.CodeTooManyRequests {
				t.Errorf("code: got %q, want %q", got.Code, apierror.CodeTooManyRequests)
			}
			if got := tt.calls(fake); got != 2 {
				t.Errorf("the service was called %d times, want 2: a limited request must not reach it", got)
			}
		})
	}
}
