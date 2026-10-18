package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformpg "github.com/Vadim-27/bookit-api/internal/platform/postgres"
	"github.com/Vadim-27/bookit-api/internal/user"
	"github.com/Vadim-27/bookit-api/internal/user/postgres"
)

// Integration tests need a database with migrations applied:
//
//	BOOKIT_TEST_DATABASE_URL=postgres://... go test ./internal/user/postgres
func newTestRepo(t *testing.T) *postgres.Repository {
	t.Helper()

	url := os.Getenv("BOOKIT_TEST_DATABASE_URL")
	if url == "" || testing.Short() {
		t.Skip("BOOKIT_TEST_DATABASE_URL is not set or -short is used")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := platformpg.NewPool(ctx, url, 4)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return postgres.NewRepository(pool)
}

// uniqueEmail keeps parallel tests and reruns from colliding on the unique email.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d-%s@example.com", time.Now().UnixNano(), strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")))
}

func TestRepository_CreateAndFind(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()

	email := uniqueEmail(t)
	u := &user.User{Email: email, PasswordHash: "hash", FullName: "Anna", Status: user.StatusActive}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Errorf("Create did not fill ID/timestamps: %+v", u)
	}

	t.Run("by email is case-insensitive", func(t *testing.T) {
		got, err := repo.FindByEmail(ctx, strings.ToUpper(email))
		if err != nil {
			t.Fatalf("FindByEmail: %v", err)
		}
		if got.ID != u.ID || got.PasswordHash != "hash" || got.FullName != "Anna" || got.Status != user.StatusActive {
			t.Errorf("FindByEmail: got %+v, want the created user %+v", got, u)
		}
	})

	t.Run("by id", func(t *testing.T) {
		got, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if got.Email != email {
			t.Errorf("FindByID: got email %q, want %q", got.Email, email)
		}
	})
}

func TestRepository_Create_DuplicateEmail(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()

	email := uniqueEmail(t)
	first := &user.User{Email: email, PasswordHash: "h", FullName: "A", Status: user.StatusActive}
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}

	// Same email in another case must still collide (citext).
	second := &user.User{Email: strings.ToUpper(email), PasswordHash: "h", FullName: "B", Status: user.StatusActive}
	if err := repo.Create(ctx, second); !errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("Create duplicate: got %v, want ErrEmailTaken", err)
	}
}

func TestRepository_Create_PendingInviteWithoutPassword(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()

	u := &user.User{Email: uniqueEmail(t), FullName: "Invited", Status: user.StatusPendingInvite}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create pending user: %v", err)
	}
	got, err := repo.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.PasswordHash != "" {
		t.Errorf("PasswordHash: got %q, want empty", got.PasswordHash)
	}
}

func TestRepository_Create_ActiveUserNeedsPassword(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)

	u := &user.User{Email: uniqueEmail(t), FullName: "No password", Status: user.StatusActive}
	err := repo.Create(context.Background(), u)
	if err == nil {
		t.Fatal("Create active user without a password: got nil, want a constraint error")
	}
	if errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("a missing password must not be reported as ErrEmailTaken: %v", err)
	}
}

func TestRepository_NotFound(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()

	tests := []struct {
		name string
		find func() error
	}{
		{"unknown email", func() error { _, err := repo.FindByEmail(ctx, "nobody@example.com"); return err }},
		{"unknown id", func() error {
			_, err := repo.FindByID(ctx, "00000000-0000-0000-0000-000000000000")
			return err
		}},
		{"malformed id is not a server error", func() error { _, err := repo.FindByID(ctx, "not-a-uuid"); return err }},
		{"sql injection in email is just a value", func() error {
			_, err := repo.FindByEmail(ctx, "' OR '1'='1")
			return err
		}},
		{"sql injection in id is just a value", func() error {
			_, err := repo.FindByID(ctx, "' OR '1'='1")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.find(); !errors.Is(err, user.ErrNotFound) {
				t.Errorf("got %v, want ErrNotFound", err)
			}
		})
	}
}
