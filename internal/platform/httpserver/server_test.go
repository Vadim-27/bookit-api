package httpserver_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
)

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

func TestRun_GracefulShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := freeAddr(t)
	done := make(chan error, 1)
	go func() { done <- httpserver.Run(ctx, addr, httpserver.New()) }()

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

func TestHealth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		{"get health", http.MethodGet, "/health", http.StatusOK, `{"status":"ok"}`},
		{"post not allowed", http.MethodPost, "/health", http.StatusMethodNotAllowed, ""},
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := httpserver.New()
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody == "" {
				return
			}
			if got := strings.TrimSpace(rec.Body.String()); got != tt.wantBody {
				t.Errorf("body: got %q, want %q", got, tt.wantBody)
			}
		})
	}
}
