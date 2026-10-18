// Package auth implements authentication: password hashing and account creation.
package auth

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	minPasswordRunes = 10
	// maxPasswordBytes is the bcrypt limit: longer input is not hashed in full,
	// so it is rejected instead of being silently truncated.
	maxPasswordBytes = 72
)

// ErrInvalidPassword is returned for a password that breaks the policy.
var ErrInvalidPassword = errors.New("invalid password")

// ValidatePassword checks the password policy: at least minPasswordRunes
// characters and at most maxPasswordBytes bytes.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return fmt.Errorf("%w: must be at least %d characters", ErrInvalidPassword, minPasswordRunes)
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("%w: must be at most %d bytes", ErrInvalidPassword, maxPasswordBytes)
	}
	return nil
}

// HashPassword validates the password and returns its bcrypt hash.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword reports whether password matches hash. A malformed hash never matches.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
