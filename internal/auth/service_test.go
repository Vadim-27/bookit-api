package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/user"
)

// fakeStore is an in-memory UserStore.
type fakeStore struct {
	created []*user.User
	err     error
}

func (f *fakeStore) Create(_ context.Context, u *user.User) error {
	if f.err != nil {
		return f.err
	}
	u.ID = "generated-id"
	f.created = append(f.created, u)
	return nil
}

func TestService_CreateSuperAdmin(t *testing.T) {
	t.Parallel()

	const goodPassword = "correct-horse-battery"

	tests := []struct {
		name     string
		email    string
		fullName string
		password string
		storeErr error
		wantErr  error // matched with errors.Is; nil means success
	}{
		{name: "ok", email: "  Admin@Example.com ", fullName: " Vadym ", password: goodPassword},
		{name: "email with display name", email: "Admin <a@example.com>", fullName: "V", password: goodPassword, wantErr: auth.ErrInvalidInput},
		{name: "email is not an address", email: "nope", fullName: "V", password: goodPassword, wantErr: auth.ErrInvalidInput},
		{name: "empty name", email: "a@example.com", fullName: "  ", password: goodPassword, wantErr: auth.ErrInvalidInput},
		{name: "weak password", email: "a@example.com", fullName: "V", password: "short", wantErr: auth.ErrInvalidPassword},
		{name: "email already taken", email: "a@example.com", fullName: "V", password: goodPassword, storeErr: user.ErrEmailTaken, wantErr: user.ErrEmailTaken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &fakeStore{err: tt.storeErr}
			svc := auth.NewService(store)

			got, err := svc.CreateSuperAdmin(context.Background(), tt.email, tt.fullName, tt.password)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("got error %v, want %v", err, tt.wantErr)
				}
				if len(store.created) != 0 {
					t.Error("a user was stored despite the error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Email != "Admin@Example.com" || got.FullName != "Vadym" {
				t.Errorf("input was not trimmed: email %q, name %q", got.Email, got.FullName)
			}
			if !got.IsSuperAdmin || got.Status != user.StatusActive {
				t.Errorf("got super admin %v, status %q; want true, %q", got.IsSuperAdmin, got.Status, user.StatusActive)
			}
			if got.PasswordHash == "" || got.PasswordHash == tt.password || !auth.CheckPassword(got.PasswordHash, tt.password) {
				t.Error("password is not stored as a valid hash of the given password")
			}
		})
	}
}
