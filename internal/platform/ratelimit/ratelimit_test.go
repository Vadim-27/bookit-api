package ratelimit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/ratelimit"
)

// newEcho returns a server whose /x route allows 3 requests at once and then
// one per second per client IP, set up like the real server.
func newEcho() *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = apierror.Handler
	e.IPExtractor = echo.ExtractIPDirect()
	e.GET("/x", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) }, ratelimit.PerMinute(60, 3))
	return e
}

func get(e *echo.Echo, remoteAddr string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = remoteAddr
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestPerMinute_LimitsEveryRequest(t *testing.T) {
	t.Parallel()

	e := newEcho()
	for i := 1; i <= 3; i++ {
		if rec := get(e, "192.0.2.1:1000", nil); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d within the burst: got %d, want %d", i, rec.Code, http.StatusNoContent)
		}
	}

	rec := get(e, "192.0.2.1:1000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request over the limit: got %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	var body apierror.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not the error envelope: %v", rec.Body, err)
	}
	if body.Error.Code != apierror.CodeTooManyRequests {
		t.Errorf("code: got %q, want %q", body.Error.Code, apierror.CodeTooManyRequests)
	}
	if got, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || got < 1 {
		t.Errorf("Retry-After: got %q, want a positive number of seconds", rec.Header().Get("Retry-After"))
	}
}

func TestPerMinute_ForgedForwardedForDoesNotHelp(t *testing.T) {
	t.Parallel()

	e := newEcho()
	// The same connection address, a different X-Forwarded-For every time.
	var denied bool
	for i := 0; i < 10; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1)
		rec := get(e, "192.0.2.7:1000", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", ip)
			r.Header.Set("X-Real-IP", ip)
		})
		if rec.Code == http.StatusTooManyRequests {
			denied = true
		}
	}
	if !denied {
		t.Error("10 requests from one connection with forged headers were never limited")
	}
}

func TestPerMinute_ClientsAreCountedSeparately(t *testing.T) {
	t.Parallel()

	e := newEcho()
	for range 3 {
		get(e, "192.0.2.1:1000", nil)
	}
	if rec := get(e, "192.0.2.1:1000", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("first client over the limit: got %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	// Another address has its own allowance; the port does not matter.
	if rec := get(e, "192.0.2.2:1000", nil); rec.Code != http.StatusNoContent {
		t.Errorf("second client: got %d, want %d", rec.Code, http.StatusNoContent)
	}
	if rec := get(e, "192.0.2.1:2222", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("same client on another port: got %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}
