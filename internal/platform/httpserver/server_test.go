package httpserver_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
)

// discardLogger keeps test output quiet.
func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// serve sends one request to e without a network.
func serve(e *echo.Echo, method, path string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) apierror.Detail {
	t.Helper()
	var body apierror.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not the error envelope: %v", rec.Body.String(), err)
	}
	return body.Error
}

// freeAddr returns a localhost address that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestHealth(t *testing.T) {
	t.Parallel()

	e := httpserver.New(discardLogger(), httpserver.Options{})
	rec := serve(e, http.MethodGet, "/health", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"ok"}`; got != want {
		t.Errorf("body: got %q, want %q", got, want)
	}
}

func TestErrorsUseOneFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCode   string
	}{
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound, apierror.CodeNotFound},
		{"unknown api path", http.MethodGet, "/api/v1/nope", http.StatusNotFound, apierror.CodeNotFound},
		{"method not allowed", http.MethodPost, "/health", http.StatusMethodNotAllowed, apierror.CodeMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := serve(httpserver.New(discardLogger(), httpserver.Options{}), tt.method, tt.path, nil)

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type: got %q, want JSON", ct)
			}
			if got := decodeError(t, rec); got.Code != tt.wantCode || got.Message == "" {
				t.Errorf("error: got %+v, want code %q and a message", got, tt.wantCode)
			}
		})
	}
}

// A group with middleware must not swallow unknown paths under its prefix:
// an unknown URL is 404, not whatever the group's middleware answers.
func TestGroupMiddlewareDoesNotCatchUnknownPaths(t *testing.T) {
	t.Parallel()

	deny := func(echo.HandlerFunc) echo.HandlerFunc {
		return func(*echo.Context) error { return echo.ErrUnauthorized }
	}
	e := httpserver.New(discardLogger(), httpserver.Options{}, func(api *echo.Group) {
		protected := api.Group("", deny)
		protected.GET("/secret", func(c *echo.Context) error { return c.NoContent(http.StatusOK) })
	})

	if rec := serve(e, http.MethodGet, "/api/v1/secret", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the protected route: got %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec := serve(e, http.MethodGet, "/api/v1/no-such-route", nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown path under the group: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPanicBecomesGenericServerError(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	e := httpserver.New(slog.New(slog.NewJSONHandler(&logs, nil)), httpserver.Options{},
		func(api *echo.Group) {
			api.GET("/boom", func(*echo.Context) error { panic("secret-internal-detail") })
		})

	rec := serve(e, http.MethodGet, "/api/v1/boom", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := decodeError(t, rec); got.Code != apierror.CodeInternal {
		t.Errorf("code: got %q, want %q", got.Code, apierror.CodeInternal)
	}
	if strings.Contains(rec.Body.String(), "secret-internal-detail") {
		t.Errorf("the response leaks internals: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "secret-internal-detail") {
		t.Errorf("the server log lacks the real cause: %s", logs.String())
	}
}

func TestHandlerErrorDetailsStayInTheLog(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	e := httpserver.New(slog.New(slog.NewJSONHandler(&logs, nil)), httpserver.Options{},
		func(api *echo.Group) {
			api.GET("/fail", func(*echo.Context) error {
				return &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
			})
		})

	rec := serve(e, http.MethodGet, "/api/v1/fail", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := decodeError(t, rec); got.Message != "internal server error" {
		t.Errorf("message: got %q, want a generic one", got.Message)
	}
	if !strings.Contains(logs.String(), "dial") {
		t.Errorf("the log lacks the error: %s", logs.String())
	}
}

func TestSecurityHeadersOnEveryAnswer(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/health", "/nope"} {
		rec := serve(httpserver.New(discardLogger(), httpserver.Options{}), http.MethodGet, path, nil)

		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options: got %q, want nosniff", path, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control: got %q, want no-store", path, got)
		}
		if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("%s: HSTS must not be sent when HTTPS is not required, got %q", path, got)
		}
	}
}

func TestRequireHTTPS(t *testing.T) {
	t.Parallel()

	forwarded := func(proto string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", proto) }
	}
	tests := []struct {
		name       string
		path       string
		mutate     func(*http.Request)
		wantStatus int
		wantHSTS   bool
	}{
		{"plain http is refused", "/api/v1/anything", nil, http.StatusForbidden, false},
		{"forwarded http is refused", "/api/v1/anything", forwarded("http"), http.StatusForbidden, false},
		{"garbage in the header is refused", "/api/v1/anything", forwarded("httpss"), http.StatusForbidden, false},
		{"forwarded https passes", "/health", forwarded("https"), http.StatusOK, true},
		{"header is case-insensitive", "/health", forwarded("HTTPS"), http.StatusOK, true},
		{"first value of a proxy chain counts", "/health", forwarded("https, http"), http.StatusOK, true},
		{"direct tls passes", "/health", func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, http.StatusOK, true},
		{"health probes may use plain http", "/health", nil, http.StatusOK, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := httpserver.New(discardLogger(), httpserver.Options{RequireHTTPS: true})
			rec := serve(e, http.MethodGet, tt.path, tt.mutate)

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusForbidden {
				if got := decodeError(t, rec); got.Code != apierror.CodeHTTPSRequired {
					t.Errorf("code: got %q, want %q", got.Code, apierror.CodeHTTPSRequired)
				}
			}
			if got := rec.Header().Get("Strict-Transport-Security") != ""; got != tt.wantHSTS {
				t.Errorf("HSTS sent: got %v, want %v", got, tt.wantHSTS)
			}
		})
	}
}

func TestRun_GracefulShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() { done <- httpserver.Run(ctx, addr, httpserver.New(discardLogger(), httpserver.Options{})) }()

	// Wait until the server answers.
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status: got %d, want %d", resp.StatusCode, http.StatusOK)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel: got %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
