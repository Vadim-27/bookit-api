package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

func TestValidatePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"ok", "correct-horse-battery", false},
		{"exactly minimum length", "abcdefghij", false},
		{"too short", "abcdefghi", true},
		{"empty", "", true},
		{"minimum counted in characters, not bytes", "ааааааааа", true}, // 9 Cyrillic letters, 18 bytes
		{"72 bytes is allowed", strings.Repeat("a", 72), false},
		{"73 bytes is rejected, not truncated", strings.Repeat("a", 73), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := auth.ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePassword(%q): got error %v, want error %v", tt.password, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, auth.ErrInvalidPassword) {
				t.Errorf("error %v does not wrap ErrInvalidPassword", err)
			}
		})
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == password || strings.Contains(hash, password) {
		t.Fatal("hash contains the plain password")
	}

	if !auth.CheckPassword(hash, password) {
		t.Error("CheckPassword: correct password rejected")
	}
	if auth.CheckPassword(hash, "wrong-password-12") {
		t.Error("CheckPassword: wrong password accepted")
	}
	if auth.CheckPassword("not-a-bcrypt-hash", password) {
		t.Error("CheckPassword: malformed hash must never match")
	}

	other, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword (second): %v", err)
	}
	if other == hash {
		t.Error("two hashes of the same password are equal: salt is missing")
	}
}

func TestHashPassword_RejectsWeakPassword(t *testing.T) {
	t.Parallel()

	if _, err := auth.HashPassword("short"); !errors.Is(err, auth.ErrInvalidPassword) {
		t.Errorf("HashPassword(short): got %v, want ErrInvalidPassword", err)
	}
}
