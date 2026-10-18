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

	const (
		publicPeer  = "203.0.113.7:4444" // anyone on the internet
		privatePeer = "10.0.0.5:5555"    // our proxy in the private network
		localPeer   = "127.0.0.1:6666"   // our proxy on the same host
	)
	// from sends the request from peer, with X-Forwarded-Proto values if given.
	from := func(peer string, protos ...string) func(*http.Request) {
		return func(r *http.Request) {
			r.RemoteAddr = peer
			for _, p := range protos {
				r.Header.Add("X-Forwarded-Proto", p)
			}
		}
	}
	tests := []struct {
		name       string
		path       string
		mutate     func(*http.Request)
		wantStatus int
		wantHSTS   bool
	}{
		{"plain http is refused", "/api/v1/anything", from(publicPeer), http.StatusForbidden, false},
		// The attack of finding F1: a client claims HTTPS over plain HTTP.
		{"a forged header from the internet is ignored", "/api/v1/anything", from(publicPeer, "https"), http.StatusForbidden, false},
		{"https from our proxy passes", "/health", from(privatePeer, "https"), http.StatusOK, true},
		{"https from a proxy on the same host passes", "/health", from(localPeer, "https"), http.StatusOK, true},
		{"http reported by our proxy is refused", "/api/v1/anything", from(privatePeer, "http"), http.StatusForbidden, false},
		{"header is case-insensitive", "/health", from(privatePeer, "HTTPS"), http.StatusOK, true},
		{"garbage in the header is refused", "/api/v1/anything", from(privatePeer, "httpss"), http.StatusForbidden, false},
		// The proxy appends its value last; a value the client put first is ignored.
		{"a client value before the proxy's is ignored", "/api/v1/anything", from(privatePeer, "https, http"), http.StatusForbidden, false},
		{"the proxy's last value counts", "/health", from(privatePeer, "http, https"), http.StatusOK, true},
		{"direct tls passes", "/health", func(r *http.Request) {
			r.RemoteAddr = publicPeer
			r.TLS = &tls.ConnectionState{}
		}, http.StatusOK, true},
		{"health probes may use plain http", "/health", from(publicPeer), http.StatusOK, false},
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

// The client address decides the rate limits, so it must not be forgeable.
func TestClientIP(t *testing.T) {
	t.Parallel()

	_, cloudflare, err := net.ParseCIDR("173.245.48.0/20")
	if err != nil {
		t.Fatal(err)
	}
	const (
		cfEdge   = "173.245.48.10:443" // a Cloudflare edge, trusted when configured
		stranger = "203.0.113.7:4444"  // anyone on the internet
		client   = "198.51.100.23"     // the real visitor
	)
	tests := []struct {
		name    string
		trusted []*net.IPNet
		peer    string
		xff     string
		want    string
	}{
		{"no proxy configured: the header is ignored", nil, stranger, "1.2.3.4", "203.0.113.7"},
		{"no proxy configured: even from a Cloudflare address", nil, cfEdge, client, "173.245.48.10"},
		{"trusted proxy names the client", []*net.IPNet{cloudflare}, cfEdge, client, client},
		{"untrusted peer cannot name a client", []*net.IPNet{cloudflare}, stranger, "1.2.3.4", "203.0.113.7"},
		{"a value the client made up on the left is skipped", []*net.IPNet{cloudflare}, cfEdge, "6.6.6.6, " + client, client},
		{"no header from a trusted proxy", []*net.IPNet{cloudflare}, cfEdge, "", "173.245.48.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := httpserver.New(discardLogger(), httpserver.Options{TrustedProxies: tt.trusted},
				func(api *echo.Group) {
					api.GET("/ip", func(c *echo.Context) error { return c.String(http.StatusOK, c.RealIP()) })
				})
			rec := serve(e, http.MethodGet, "/api/v1/ip", func(r *http.Request) {
				r.RemoteAddr = tt.peer
				if tt.xff != "" {
					r.Header.Set("X-Forwarded-For", tt.xff)
				}
			})
			if got := rec.Body.String(); got != tt.want {
				t.Errorf("client IP: got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequireHTTPS_TrustsConfiguredProxyForTheScheme(t *testing.T) {
	t.Parallel()

	_, cloudflare, err := net.ParseCIDR("173.245.48.0/20")
	if err != nil {
		t.Fatal(err)
	}
	e := httpserver.New(discardLogger(), httpserver.Options{RequireHTTPS: true, TrustedProxies: []*net.IPNet{cloudflare}})

	fromCF := serve(e, http.MethodGet, "/health", func(r *http.Request) {
		r.RemoteAddr = "173.245.48.10:443"
		r.Header.Set("X-Forwarded-Proto", "https")
	})
	if fromCF.Header().Get("Strict-Transport-Security") == "" {
		t.Error("https reported by a configured proxy was not believed")
	}

	forged := serve(e, http.MethodGet, "/api/v1/anything", func(r *http.Request) {
		r.RemoteAddr = "203.0.113.7:4444"
		r.Header.Set("X-Forwarded-Proto", "https")
	})
	if forged.Code != http.StatusForbidden {
		t.Errorf("https claimed by a stranger: got %d, want %d", forged.Code, http.StatusForbidden)
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
