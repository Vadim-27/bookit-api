package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Vadim-27/bookit-api/internal/user"
)

// ErrInvalidCredentials is the only answer to a failed login: it never says
// whether the email, the password or the account state was the problem.
var ErrInvalidCredentials = errors.New("invalid credentials")

// dummyPassword is hashed once per process. Logins for unknown or unusable
// accounts are compared against its hash, so they cost as much time as real ones.
const dummyPassword = "not-a-real-password"

// dummyHash computes the hash on first use and then returns the same value.
var dummyHash = sync.OnceValues(func() (string, error) { return HashPassword(dummyPassword) })

// UserFinder is the part of the user storage the sessions need.
type UserFinder interface {
	FindByEmail(ctx context.Context, email string) (*user.User, error)
	FindByID(ctx context.Context, id string) (*user.User, error)
}

// Session is what a successful login or refresh returns: a short-lived access
// token for the API and a long-lived refresh token to get the next one.
type Session struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// Options configures an Authenticator.
type Options struct {
	// RefreshTTL is the lifetime of a refresh token; it must be positive.
	RefreshTTL time.Duration
	// Now is the clock; nil means time.Now. Tests inject a fixed one.
	Now func() time.Time
}

// Authenticator checks credentials and manages sessions.
type Authenticator struct {
	users      UserFinder
	sessions   RefreshStore
	tokens     *TokenManager
	dummyHash  string
	refreshTTL time.Duration
	now        func() time.Time
}

// NewAuthenticator returns an Authenticator. The first call in a process hashes
// the dummy password, which costs one bcrypt operation.
func NewAuthenticator(users UserFinder, sessions RefreshStore, tokens *TokenManager, opts Options) (*Authenticator, error) {
	if opts.RefreshTTL <= 0 {
		return nil, errors.New("refresh token ttl must be positive")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	hash, err := dummyHash()
	if err != nil {
		return nil, fmt.Errorf("prepare login: %w", err)
	}
	return &Authenticator{
		users:      users,
		sessions:   sessions,
		tokens:     tokens,
		dummyHash:  hash,
		refreshTTL: opts.RefreshTTL,
		now:        opts.Now,
	}, nil
}

// Login checks the credentials of a user account (platform or staff) and
// starts a session. Every authentication failure returns ErrInvalidCredentials;
// any other error is an infrastructure problem.
//
// A bcrypt comparison is always performed, even for a malformed email or an
// unknown account, so the response time does not reveal which emails exist.
func (a *Authenticator) Login(ctx context.Context, email, password string) (*Session, error) {
	u, err := a.findUser(ctx, email)
	switch {
	case errors.Is(err, user.ErrNotFound):
		u = nil // no usable account: still do the bcrypt work below
	case err != nil:
		return nil, err
	}

	hash := a.dummyHash
	if u != nil && u.PasswordHash != "" {
		hash = u.PasswordHash
	}
	matches := CheckPassword(hash, password)

	// bcrypt looks only at the first 72 bytes: registration never allows more,
	// so a longer password can only be a different one. Reject it explicitly.
	valid := u != nil &&
		u.PasswordHash != "" &&
		matches &&
		len(password) <= maxPasswordBytes &&
		u.Status == user.StatusActive
	if !valid {
		return nil, ErrInvalidCredentials
	}

	refreshToken, refreshHash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	now := a.now()
	rt := &RefreshToken{UserID: u.ID, TokenHash: refreshHash, CreatedAt: now, ExpiresAt: now.Add(a.refreshTTL)}
	if err := a.sessions.Insert(ctx, rt); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}
	return a.session(u.ID, refreshToken, rt.ExpiresAt)
}

// Refresh exchanges a refresh token for a new session. The old token is
// consumed: each refresh token works exactly once. Any problem with the token
// returns ErrInvalidToken.
//
// If a token that was already exchanged is presented again, someone holds a
// copy of it, so the whole session (the family of tokens) is revoked.
func (a *Authenticator) Refresh(ctx context.Context, refreshToken string) (*Session, error) {
	// A well-formed token has a fixed length: refuse anything else without
	// touching the database.
	if len(refreshToken) != refreshTokenLen {
		return nil, ErrInvalidToken
	}
	oldHash := hashRefreshToken(refreshToken)

	nextToken, nextHash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	now := a.now()
	next := &RefreshToken{TokenHash: nextHash, CreatedAt: now, ExpiresAt: now.Add(a.refreshTTL)}

	prev, err := a.sessions.Rotate(ctx, oldHash, next, now)
	switch {
	case errors.Is(err, ErrRefreshNotUsable):
		if err := a.punishReuse(ctx, oldHash, now); err != nil {
			return nil, err
		}
		return nil, ErrInvalidToken
	case err != nil:
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	// The account must still be allowed to log in: a suspended or deleted user
	// loses the session at once, even though the token itself was fine.
	u, err := a.users.FindByID(ctx, prev.UserID)
	switch {
	case err == nil && u.Status == user.StatusActive:
		return a.session(u.ID, nextToken, next.ExpiresAt)
	case err == nil || errors.Is(err, user.ErrNotFound):
		if err := a.sessions.RevokeFamily(ctx, prev.FamilyID, now); err != nil {
			return nil, fmt.Errorf("revoke session: %w", err)
		}
		return nil, ErrInvalidToken
	default:
		return nil, fmt.Errorf("find user: %w", err)
	}
}

// Logout ends the session the refresh token belongs to. It is idempotent: an
// unknown or already used token is not an error. Access tokens already issued
// stay valid until they expire (at most 15 minutes).
func (a *Authenticator) Logout(ctx context.Context, refreshToken string) error {
	if len(refreshToken) != refreshTokenLen {
		return nil
	}
	t, err := a.sessions.Find(ctx, hashRefreshToken(refreshToken))
	switch {
	case errors.Is(err, ErrRefreshNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("find refresh token: %w", err)
	}
	if err := a.sessions.RevokeFamily(ctx, t.FamilyID, a.now()); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// punishReuse revokes the whole session when an already exchanged token comes
// back after the grace period. Unknown, expired or revoked tokens change nothing.
func (a *Authenticator) punishReuse(ctx context.Context, hash []byte, now time.Time) error {
	old, err := a.sessions.Find(ctx, hash)
	switch {
	case errors.Is(err, ErrRefreshNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("find refresh token: %w", err)
	}
	if old.UsedAt == nil || now.Sub(*old.UsedAt) <= reuseGrace {
		return nil
	}
	if err := a.sessions.RevokeFamily(ctx, old.FamilyID, now); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// session issues an access token and bundles it with the refresh token.
func (a *Authenticator) session(userID, refreshToken string, refreshExpiresAt time.Time) (*Session, error) {
	access, accessExpiresAt, err := a.tokens.Issue(userID, SubjectUser, "")
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}
	return &Session{
		AccessToken:      access,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

// findUser returns user.ErrNotFound both for an unknown and for a malformed
// email (the storage is not even asked about the latter). Any other error is a
// real storage failure.
func (a *Authenticator) findUser(ctx context.Context, rawEmail string) (*user.User, error) {
	email, err := NormalizeEmail(rawEmail)
	if err != nil {
		return nil, user.ErrNotFound
	}
	u, err := a.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}
	return u, nil
}
