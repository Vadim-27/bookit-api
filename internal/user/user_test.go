package user_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/user"
)

func TestUser_PasswordHashIsNeverSerialized(t *testing.T) {
	t.Parallel()

	const hash = "$2a$10$abcdefghijklmnopqrstuuvwxyz0123456789ABCDEFGHIJKLMNOPQ"
	u := user.User{
		ID:           "id-1",
		Email:        "owner@example.com",
		PasswordHash: hash,
		FullName:     "Owner",
		Status:       user.StatusActive,
	}

	out, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), hash) || strings.Contains(strings.ToLower(string(out)), "passwordhash") {
		t.Errorf("serialized user leaks the password hash: %s", out)
	}
}
