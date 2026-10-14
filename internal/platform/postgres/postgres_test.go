package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/platform/postgres"
)

const testPassword = "s3cretpw"

func TestNewPool_ErrorsDoNotLeakPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"unparsable url", "postgres://u:" + testPassword + "@h:99x/db"},
		{"unreachable server", "postgres://u:" + testPassword + "@127.0.0.1:1/db?sslmode=disable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			pool, err := postgres.NewPool(ctx, tt.url, 2)
			if err == nil {
				pool.Close()
				t.Fatal("NewPool: got nil error, want error")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Errorf("error leaks the password: %v", err)
			}
		})
	}
}

// TestNewPool_Integration needs a running database with migrations applied:
//
//	BOOKIT_TEST_DATABASE_URL=postgres://... go test ./internal/platform/postgres
func TestNewPool_Integration(t *testing.T) {
	t.Parallel()

	url := os.Getenv("BOOKIT_TEST_DATABASE_URL")
	if url == "" || testing.Short() {
		t.Skip("BOOKIT_TEST_DATABASE_URL is not set or -short is used")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, url, 3)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(pool.Close)

	if got := pool.Config().MaxConns; got != 3 {
		t.Errorf("MaxConns: got %d, want 3", got)
	}

	var extensions int
	err = pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_extension WHERE extname = ANY($1)`,
		[]string{"citext", "btree_gist"},
	).Scan(&extensions)
	if err != nil {
		t.Fatalf("query extensions: %v", err)
	}
	if extensions != 2 {
		t.Errorf("installed extensions: got %d, want 2 (migrations applied?)", extensions)
	}
}
