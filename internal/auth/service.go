package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Vadim-27/bookit-api/internal/user"
)

const maxFullNameLen = 200

// ErrInvalidInput is returned when the given data does not pass validation.
var ErrInvalidInput = errors.New("invalid input")

// UserStore is the part of the user storage the service needs.
type UserStore interface {
	Create(ctx context.Context, u *user.User) error
}

// Service creates and authenticates accounts.
type Service struct {
	users UserStore
}

// NewService returns a Service backed by users.
func NewService(users UserStore) *Service {
	return &Service{users: users}
}

// CreateSuperAdmin creates an active super admin account. It returns
// user.ErrEmailTaken when the email is already registered.
func (s *Service) CreateSuperAdmin(ctx context.Context, email, fullName, password string) (*user.User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	fullName = strings.TrimSpace(fullName)
	if n := utf8.RuneCountInString(fullName); n == 0 || n > maxFullNameLen {
		return nil, fmt.Errorf("%w: name must be 1-%d characters", ErrInvalidInput, maxFullNameLen)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	u := &user.User{
		Email:        email,
		PasswordHash: hash,
		FullName:     fullName,
		Status:       user.StatusActive,
		IsSuperAdmin: true,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("create super admin: %w", err)
	}
	return u, nil
}
