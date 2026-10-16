package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// refreshTokenBytes is the entropy of a refresh token: 256 bits, unguessable.
const refreshTokenBytes = 32

// refreshTokenLen is the length of a token as text: base64url of 32 bytes.
const refreshTokenLen = 43

// reuseGrace is how long after use an already exchanged token is treated as a
// harmless double submit (two browser tabs refreshing at once) rather than theft.
const reuseGrace = 10 * time.Second

// Errors of the refresh token storage.
var (
	// ErrRefreshNotUsable means the token is unknown, already used, revoked or expired.
	ErrRefreshNotUsable = errors.New("refresh token is not usable")
	// ErrRefreshNotFound means no such token is stored.
	ErrRefreshNotFound = errors.New("refresh token not found")
)

// RefreshToken is the stored record of a refresh token.
type RefreshToken struct {
	ID       string
	UserID   string
	FamilyID string // shared by every token of one login session
	// TokenHash is the SHA-256 of the token; the token itself is never stored.
	TokenHash []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt is set when the token was exchanged for a new one.
	UsedAt *time.Time
	// RevokedAt is set when the whole family was revoked.
	RevokedAt *time.Time
}

// RefreshStore is the storage the session logic needs.
type RefreshStore interface {
	// Insert stores t. An empty FamilyID starts a new family; the store fills
	// ID and FamilyID.
	Insert(ctx context.Context, t *RefreshToken) error

	// Rotate atomically marks the token with oldHash as used and stores next in
	// the same family. Of two concurrent calls with the same hash exactly one
	// succeeds. It returns the old token, or ErrRefreshNotUsable.
	Rotate(ctx context.Context, oldHash []byte, next *RefreshToken, now time.Time) (*RefreshToken, error)

	// Find returns the token with the given hash or ErrRefreshNotFound.
	Find(ctx context.Context, hash []byte) (*RefreshToken, error)

	// RevokeFamily revokes every token of the family. It is idempotent.
	RevokeFamily(ctx context.Context, familyID string, now time.Time) error
}

// newRefreshToken returns a fresh random token and its hash.
func newRefreshToken() (token string, hash []byte, err error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashRefreshToken(token), nil
}

// hashRefreshToken returns the SHA-256 of the token. A fast hash is enough
// here: the token is 256 random bits, so there is nothing to brute-force.
func hashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
