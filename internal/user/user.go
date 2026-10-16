// Package user is the domain of platform and staff accounts: types and errors
// only. It knows nothing about SQL or HTTP; storage lives in the subpackage
// postgres.
package user

import (
	"errors"
	"time"
)

// Status is the lifecycle state of a user account.
type Status string

// Possible user statuses; they match the CHECK constraint in the migration.
const (
	StatusActive        Status = "active"
	StatusPendingInvite Status = "pending_invite"
	StatusSuspended     Status = "suspended"
)

// Errors the callers must be able to tell apart.
var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email already registered")
)

// User is a platform or staff account.
type User struct {
	ID    string
	Email string
	// PasswordHash is empty until an invited user sets a password. The tag is
	// a last line of defence: the hash must never reach a response.
	PasswordHash string `json:"-"`
	FullName     string
	Status       Status
	IsSuperAdmin bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
