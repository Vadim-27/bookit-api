package auth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/user"
)

const (
	loginPassword = "correct-horse-battery"
	refreshTTL    = 30 * 24 * time.Hour
	maxSessionAge = 90 * 24 * time.Hour
)

// testClock is a clock the tests move by hand; it is safe for concurrent use.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeFinder is an in-memory UserFinder that counts its calls.
type fakeFinder struct {
	mu         sync.Mutex
	users      map[string]*user.User // keyed by the exact normalized email
	err        error                 // returned by every call when set
	emailCalls int
}

func (f *fakeFinder) FindByEmail(_ context.Context, email string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.emailCalls++
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}

func (f *fakeFinder) FindByID(_ context.Context, id string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}

// setStatus changes the status of the user with the given email.
func (f *fakeFinder) setStatus(email string, status user.Status) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[email].Status = status
}

// fakeSessions is an in-memory RefreshStore with the same guarantees as the
// real one: Rotate is atomic.
type fakeSessions struct {
	mu          sync.Mutex
	byHash      map[string]*auth.RefreshToken
	seq         int
	insertErr   error
	rotateCalls int
	purgeCalls  int
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{byHash: make(map[string]*auth.RefreshToken)}
}

func (f *fakeSessions) Insert(_ context.Context, t *auth.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.insertLocked(t)
}

func (f *fakeSessions) insertLocked(t *auth.RefreshToken) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.seq++
	t.ID = fmt.Sprintf("rt-%d", f.seq)
	if t.FamilyID == "" {
		t.FamilyID = fmt.Sprintf("family-%d", f.seq)
	}
	stored := *t
	f.byHash[string(t.TokenHash)] = &stored
	return nil
}

func (f *fakeSessions) Rotate(_ context.Context, oldHash []byte, next *auth.RefreshToken, now time.Time) (*auth.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotateCalls++

	old, ok := f.byHash[string(oldHash)]
	if !ok || old.UsedAt != nil || old.RevokedAt != nil || !old.ExpiresAt.After(now) {
		return nil, auth.ErrRefreshNotUsable
	}
	used := now
	old.UsedAt = &used
	next.UserID, next.FamilyID = old.UserID, old.FamilyID
	next.SessionExpiresAt = old.SessionExpiresAt
	if next.ExpiresAt.After(next.SessionExpiresAt) {
		next.ExpiresAt = next.SessionExpiresAt
	}
	if err := f.insertLocked(next); err != nil {
		return nil, err
	}
	prev := *old
	return &prev, nil
}

func (f *fakeSessions) Find(_ context.Context, hash []byte) (*auth.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.byHash[string(hash)]
	if !ok {
		return nil, auth.ErrRefreshNotFound
	}
	cp := *t
	return &cp, nil
}

func (f *fakeSessions) PurgeExpired(_ context.Context, before time.Time, limit int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purgeCalls++
	var n int64
	for hash, t := range f.byHash {
		if int(n) == limit {
			break
		}
		if t.ExpiresAt.Before(before) {
			delete(f.byHash, hash)
			n++
		}
	}
	return n, nil
}

// put stores a token directly, for tests that need many records.
func (f *fakeSessions) put(t auth.RefreshToken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byHash[string(t.TokenHash)] = &t
}

func (f *fakeSessions) RevokeFamily(_ context.Context, familyID string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.byHash {
		if t.FamilyID == familyID && t.RevokedAt == nil {
			revoked := now
			t.RevokedAt = &revoked
		}
	}
	return nil
}

// all returns copies of every stored token.
func (f *fakeSessions) all() []auth.RefreshToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]auth.RefreshToken, 0, len(f.byHash))
	for _, t := range f.byHash {
		out = append(out, *t)
	}
	return out
}

// env bundles an Authenticator with its fakes.
type env struct {
	auth     *auth.Authenticator
	users    *fakeFinder
	sessions *fakeSessions
	tokens   *auth.TokenManager
	clock    *testClock
}

func newEnv(t *testing.T, users map[string]*user.User) *env {
	t.Helper()
	clock := &testClock{t: epoch}
	finder := &fakeFinder{users: users}
	sessions := newFakeSessions()
	tokens, err := auth.NewTokenManager(secretA, "", 15*time.Minute, clock.Now)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	a, err := auth.NewAuthenticator(finder, sessions, tokens,
		auth.Options{RefreshTTL: refreshTTL, MaxSessionAge: maxSessionAge, Now: clock.Now})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &env{auth: a, users: finder, sessions: sessions, tokens: tokens, clock: clock}
}

// hashes caches bcrypt hashes of test passwords: hashing is deliberately slow
// and dozens of tests need the same few.
var (
	hashesMu sync.Mutex
	hashes   = make(map[string]string)
)

func cachedHash(t *testing.T, password string) string {
	t.Helper()
	hashesMu.Lock()
	defer hashesMu.Unlock()
	if h, ok := hashes[password]; ok {
		return h
	}
	h, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	hashes[password] = h
	return h
}

func accountWithPassword(t *testing.T, password string, status user.Status) *user.User {
	t.Helper()
	return &user.User{ID: "user-1", Email: "boss@example.com", PasswordHash: cachedHash(t, password), FullName: "Boss", Status: status}
}

func activeBoss(t *testing.T) map[string]*user.User {
	t.Helper()
	return map[string]*user.User{"boss@example.com": accountWithPassword(t, loginPassword, user.StatusActive)}
}

func TestLogin_Success(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))

	s, err := e.auth.Login(context.Background(), "  boss@example.com ", loginPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	claims, err := e.tokens.Parse(s.AccessToken)
	if err != nil {
		t.Fatalf("issued access token does not verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Type != auth.SubjectUser {
		t.Errorf("claims: got %+v", claims)
	}
	if want := epoch.Add(15 * time.Minute); !s.AccessExpiresAt.Equal(want) {
		t.Errorf("AccessExpiresAt: got %v, want %v", s.AccessExpiresAt, want)
	}
	if want := epoch.Add(refreshTTL); !s.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt: got %v, want %v", s.RefreshExpiresAt, want)
	}
	if len(s.RefreshToken) != 43 {
		t.Errorf("refresh token length: got %d, want 43 (256 random bits)", len(s.RefreshToken))
	}

	// Only the hash of the refresh token is stored, never the token.
	stored := e.sessions.all()
	if len(stored) != 1 {
		t.Fatalf("stored refresh tokens: got %d, want 1", len(stored))
	}
	wantHash := sha256.Sum256([]byte(s.RefreshToken))
	if !bytes.Equal(stored[0].TokenHash, wantHash[:]) {
		t.Error("the stored hash is not the SHA-256 of the refresh token")
	}
	if bytes.Contains(stored[0].TokenHash, []byte(s.RefreshToken)) || stored[0].UserID != "user-1" {
		t.Errorf("unexpected stored token: %+v", stored[0])
	}
}

func TestLogin_RefreshTokensAreUnique(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	seen := make(map[string]bool)
	for range 20 {
		s, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if seen[s.RefreshToken] {
			t.Fatal("two logins returned the same refresh token")
		}
		seen[s.RefreshToken] = true
	}
}

func TestLogin_EveryFailureLooksTheSame(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 72)
	tests := []struct {
		name     string
		users    map[string]*user.User
		email    string
		password string
	}{
		{"wrong password", activeBoss(t), "boss@example.com", "wrong-password-1"},
		{"unknown email", nil, "nobody@example.com", loginPassword},
		{"malformed email", nil, "not an email", loginPassword},
		{"empty email", nil, "", loginPassword},
		{"empty password", activeBoss(t), "boss@example.com", ""},
		{"suspended account with the right password", map[string]*user.User{"boss@example.com": accountWithPassword(t, loginPassword, user.StatusSuspended)}, "boss@example.com", loginPassword},
		{"invited account has no password yet", map[string]*user.User{"boss@example.com": {ID: "u", Email: "boss@example.com", Status: user.StatusPendingInvite}}, "boss@example.com", loginPassword},
		{"password longer than bcrypt reads", map[string]*user.User{"boss@example.com": accountWithPassword(t, long, user.StatusActive)}, "boss@example.com", long + "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := newEnv(t, tt.users)
			s, err := e.auth.Login(context.Background(), tt.email, tt.password)
			if !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatalf("Login: got %v, want ErrInvalidCredentials", err)
			}
			if s != nil {
				t.Errorf("Login returned a session %+v together with an error", s)
			}
			if got := len(e.sessions.all()); got != 0 {
				t.Errorf("a failed login stored %d refresh tokens", got)
			}
		})
	}
}

func TestLogin_MalformedEmailNeverReachesTheStore(t *testing.T) {
	t.Parallel()

	e := newEnv(t, nil)
	if _, err := e.auth.Login(context.Background(), "user@example.com\nBcc: evil@example.com", "x"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("Login: got %v, want ErrInvalidCredentials", err)
	}
	if e.users.emailCalls != 0 {
		t.Errorf("store was called %d times for a malformed email", e.users.emailCalls)
	}
}

func TestLogin_StorageFailuresAreNotHiddenAsBadCredentials(t *testing.T) {
	t.Parallel()

	t.Run("user storage", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, nil)
		e.users.err = errors.New("database is down")
		_, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
		if err == nil || errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("Login: got %v, want a storage error that is not ErrInvalidCredentials", err)
		}
	})

	t.Run("refresh token storage", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		e.sessions.insertErr = errors.New("disk is full")
		_, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
		if err == nil || errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("Login: got %v, want a storage error that is not ErrInvalidCredentials", err)
		}
	})
}

// Failed logins must cost a bcrypt comparison even when there is nothing to
// compare with, otherwise the response time reveals which emails exist.
func TestLogin_UnknownAndMalformedEmailsStillRunBcrypt(t *testing.T) {
	// Not parallel: it measures time, so it must not compete with other tests.
	e := newEnv(t, nil)

	const minDuration = 10 * time.Millisecond // bcrypt at cost 10 takes tens of ms
	for _, email := range []string{"nobody@example.com", "garbage"} {
		start := time.Now()
		_, err := e.auth.Login(context.Background(), email, loginPassword)
		elapsed := time.Since(start)

		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("Login(%q): got %v, want ErrInvalidCredentials", email, err)
		}
		if elapsed < minDuration {
			t.Errorf("Login(%q) took %v: no bcrypt comparison was done, timing reveals the email is unusable", email, elapsed)
		}
	}
}

func TestNewAuthenticator_RejectsBadOptions(t *testing.T) {
	t.Parallel()

	tokens := newManager(t, secretA, "", epoch)
	tests := []struct {
		name string
		opts auth.Options
	}{
		{"zero refresh ttl", auth.Options{RefreshTTL: 0, MaxSessionAge: maxSessionAge}},
		{"negative refresh ttl", auth.Options{RefreshTTL: -time.Hour, MaxSessionAge: maxSessionAge}},
		{"session shorter than a token", auth.Options{RefreshTTL: refreshTTL, MaxSessionAge: refreshTTL - time.Hour}},
		{"no session limit", auth.Options{RefreshTTL: refreshTTL}},
	}
	for _, tt := range tests {
		if _, err := auth.NewAuthenticator(&fakeFinder{}, newFakeSessions(), tokens, tt.opts); err == nil {
			t.Errorf("%s: got nil error, want an error", tt.name)
		}
	}
}
