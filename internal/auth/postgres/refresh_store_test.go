package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
	authpg "github.com/Vadim-27/bookit-api/internal/auth/postgres"
	platformpg "github.com/Vadim-27/bookit-api/internal/platform/postgres"
	"github.com/Vadim-27/bookit-api/internal/user"
	userpg "github.com/Vadim-27/bookit-api/internal/user/postgres"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// Integration tests need a database with migrations applied:
//
//	BOOKIT_TEST_DATABASE_URL=postgres://... go test ./internal/auth/postgres
func newStore(t *testing.T) (*authpg.RefreshStore, *userpg.Repository) {
	t.Helper()

	url := os.Getenv("BOOKIT_TEST_DATABASE_URL")
	if url == "" || testing.Short() {
		t.Skip("BOOKIT_TEST_DATABASE_URL is not set or -short is used")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := platformpg.NewPool(ctx, url, 30)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return authpg.NewRefreshStore(pool), userpg.NewRepository(pool)
}

// unique makes values that never repeat, even in parallel tests: the clock of
// some systems is too coarse to tell two calls apart, so a counter is added.
var counter atomic.Int64

func unique() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), counter.Add(1))
}

// newUser creates a user: refresh tokens belong to one (foreign key).
func newUser(t *testing.T, users *userpg.Repository) string {
	t.Helper()
	u := &user.User{
		Email:        unique() + "-refresh@example.com",
		PasswordHash: "hash",
		FullName:     "Refresh Tester",
		Status:       user.StatusActive,
	}
	if err := users.Create(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}

// token builds a token record with a random-looking unique hash.
func token(userID, seed string, expiresIn time.Duration) *auth.RefreshToken {
	sum := sha256.Sum256([]byte(seed + "-" + unique()))
	return &auth.RefreshToken{
		UserID:           userID,
		TokenHash:        sum[:],
		CreatedAt:        now,
		ExpiresAt:        now.Add(expiresIn),
		SessionExpiresAt: now.Add(max(expiresIn, 90*24*time.Hour)),
	}
}

// expiredAgo builds a token that expired ago before now.
func expiredAgo(userID, seed string, ago time.Duration) *auth.RefreshToken {
	t := token(userID, seed, time.Hour)
	t.ExpiresAt = now.Add(-ago)
	t.CreatedAt = t.ExpiresAt.Add(-30 * 24 * time.Hour)
	t.SessionExpiresAt = t.ExpiresAt
	return t
}

func TestRefreshStore_InsertAndFind(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()

	tok := token(newUser(t, users), "insert", time.Hour)
	if err := store.Insert(ctx, tok); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if tok.ID == "" || tok.FamilyID == "" {
		t.Fatalf("Insert did not fill ID and FamilyID: %+v", tok)
	}

	got, err := store.Find(ctx, tok.TokenHash)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != tok.ID || got.UserID != tok.UserID || got.FamilyID != tok.FamilyID {
		t.Errorf("Find: got %+v, want %+v", got, tok)
	}
	if !bytes.Equal(got.TokenHash, tok.TokenHash) || !got.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Errorf("hash or expiry changed on the way: %+v", got)
	}
	if got.UsedAt != nil || got.RevokedAt != nil {
		t.Errorf("a new token must be unused and unrevoked: %+v", got)
	}

	if _, err := store.Find(ctx, bytes.Repeat([]byte{7}, 32)); !errors.Is(err, auth.ErrRefreshNotFound) {
		t.Errorf("Find of an unknown hash: got %v, want ErrRefreshNotFound", err)
	}
}

func TestRefreshStore_InsertRejectsBadData(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()
	userID := newUser(t, users)

	t.Run("hash of the wrong length", func(t *testing.T) {
		bad := token(userID, "short-hash", time.Hour)
		bad.TokenHash = []byte("too short")
		if err := store.Insert(ctx, bad); err == nil {
			t.Error("Insert: got nil error, want a constraint error")
		}
	})
	t.Run("expiry before creation", func(t *testing.T) {
		if err := store.Insert(ctx, token(userID, "expired", -time.Hour)); err == nil {
			t.Error("Insert: got nil error, want a constraint error")
		}
	})
	t.Run("unknown user", func(t *testing.T) {
		if err := store.Insert(ctx, token("00000000-0000-0000-0000-000000000000", "orphan", time.Hour)); err == nil {
			t.Error("Insert: got nil error, want a foreign key error")
		}
	})
	t.Run("token outliving its session", func(t *testing.T) {
		bad := token(userID, "outlives", time.Hour)
		bad.SessionExpiresAt = now.Add(time.Minute)
		if err := store.Insert(ctx, bad); err == nil {
			t.Error("Insert: got nil error, want a constraint error")
		}
	})
	t.Run("duplicate hash", func(t *testing.T) {
		first := token(userID, "dup", time.Hour)
		if err := store.Insert(ctx, first); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		second := token(userID, "dup2", time.Hour)
		second.TokenHash = first.TokenHash
		if err := store.Insert(ctx, second); err == nil {
			t.Error("Insert of a duplicate hash: got nil error, want a unique violation")
		}
	})
}

func TestRefreshStore_Rotate(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()

	first := token(newUser(t, users), "first", time.Hour)
	if err := store.Insert(ctx, first); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rotateAt := now.Add(time.Minute)
	next := token("", "next", time.Hour)
	prev, err := store.Rotate(ctx, first.TokenHash, next, rotateAt)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if prev.ID != first.ID || prev.UserID != first.UserID {
		t.Errorf("Rotate returned %+v, want the old token %+v", prev, first)
	}
	if next.ID == "" || next.UserID != first.UserID || next.FamilyID != first.FamilyID {
		t.Errorf("the new token must join the family of the old one: %+v", next)
	}

	old, err := store.Find(ctx, first.TokenHash)
	if err != nil || old.UsedAt == nil || !old.UsedAt.Equal(rotateAt) {
		t.Errorf("the old token must be marked used at %v: %+v (err %v)", rotateAt, old, err)
	}
	if _, err := store.Find(ctx, next.TokenHash); err != nil {
		t.Errorf("the new token was not stored: %v", err)
	}

	// A token works once.
	again := token("", "again", time.Hour)
	if _, err := store.Rotate(ctx, first.TokenHash, again, rotateAt.Add(time.Second)); !errors.Is(err, auth.ErrRefreshNotUsable) {
		t.Errorf("second Rotate of the same token: got %v, want ErrRefreshNotUsable", err)
	}
	if _, err := store.Find(ctx, again.TokenHash); !errors.Is(err, auth.ErrRefreshNotFound) {
		t.Errorf("a failed rotation must not store the new token: %v", err)
	}
}

func TestRefreshStore_RotateRefusesUnusableTokens(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()
	userID := newUser(t, users)

	t.Run("unknown", func(t *testing.T) {
		if _, err := store.Rotate(ctx, bytes.Repeat([]byte{9}, 32), token("", "n", time.Hour), now); !errors.Is(err, auth.ErrRefreshNotUsable) {
			t.Errorf("got %v, want ErrRefreshNotUsable", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		tok := token(userID, "exp", time.Hour)
		if err := store.Insert(ctx, tok); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if _, err := store.Rotate(ctx, tok.TokenHash, token("", "n", time.Hour), now.Add(time.Hour)); !errors.Is(err, auth.ErrRefreshNotUsable) {
			t.Errorf("at the moment of expiry: got %v, want ErrRefreshNotUsable", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		tok := token(userID, "rev", time.Hour)
		if err := store.Insert(ctx, tok); err != nil {
			t.Fatalf("Insert: %v", err)
		}
		if err := store.RevokeFamily(ctx, tok.FamilyID, now); err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}
		if _, err := store.Rotate(ctx, tok.TokenHash, token("", "n", time.Hour), now); !errors.Is(err, auth.ErrRefreshNotUsable) {
			t.Errorf("got %v, want ErrRefreshNotUsable", err)
		}
	})
}

// The point of the atomic UPDATE: of many simultaneous refreshes of one token
// exactly one wins, and only the winner's new token exists.
func TestRefreshStore_RotateConcurrentlySucceedsOnce(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()

	first := token(newUser(t, users), "race", time.Hour)
	if err := store.Insert(ctx, first); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	const attempts = 25
	nexts := make([]*auth.RefreshToken, attempts)
	errs := make([]error, attempts)
	var wg sync.WaitGroup
	for i := range attempts {
		nexts[i] = token("", fmt.Sprintf("racer-%d", i), time.Hour)
		wg.Go(func() {
			_, errs[i] = store.Rotate(ctx, first.TokenHash, nexts[i], now.Add(time.Second))
		})
	}
	wg.Wait()

	var winners, stored int
	for i := range attempts {
		switch {
		case errs[i] == nil:
			winners++
		case !errors.Is(errs[i], auth.ErrRefreshNotUsable):
			t.Errorf("attempt %d: unexpected error %v", i, errs[i])
		}
		if _, err := store.Find(ctx, nexts[i].TokenHash); err == nil {
			stored++
		}
	}
	if winners != 1 {
		t.Errorf("%d concurrent rotations succeeded, want exactly 1", winners)
	}
	if stored != 1 {
		t.Errorf("%d new tokens were stored, want exactly 1", stored)
	}
}

func TestRefreshStore_RotateNeverExtendsTheSession(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()

	first := token(newUser(t, users), "near-end", time.Hour)
	first.SessionExpiresAt = now.Add(2 * time.Hour) // the session ends soon
	if err := store.Insert(ctx, first); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	next := token("", "would-live-30-days", 30*24*time.Hour)
	next.SessionExpiresAt = time.Time{} // must be inherited, not trusted from the caller
	if _, err := store.Rotate(ctx, first.TokenHash, next, now.Add(time.Minute)); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	sessionEnd := now.Add(2 * time.Hour)
	if !next.SessionExpiresAt.Equal(sessionEnd) || !next.ExpiresAt.Equal(sessionEnd) {
		t.Errorf("the new token must end with the session (%v): expires %v, session %v",
			sessionEnd, next.ExpiresAt, next.SessionExpiresAt)
	}
	stored, err := store.Find(ctx, next.TokenHash)
	if err != nil || !stored.ExpiresAt.Equal(sessionEnd) || !stored.SessionExpiresAt.Equal(sessionEnd) {
		t.Errorf("stored token: %+v (err %v), want both expiries %v", stored, err, sessionEnd)
	}
}

func TestRefreshStore_PurgeExpired(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()
	userID := newUser(t, users)

	old := []*auth.RefreshToken{
		expiredAgo(userID, "old-1", 10*24*time.Hour),
		expiredAgo(userID, "old-2", 9*24*time.Hour),
		expiredAgo(userID, "old-3", 8*24*time.Hour),
	}
	recent := expiredAgo(userID, "recent", 24*time.Hour)
	live := token(userID, "live", time.Hour)
	for _, tok := range append(old, recent, live) {
		if err := store.Insert(ctx, tok); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	before := now.Add(-7 * 24 * time.Hour)

	// The limit bounds one call.
	n, err := store.PurgeExpired(ctx, before, 2)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted with limit 2: got %d", n)
	}

	// The next call takes the rest.
	if _, err := store.PurgeExpired(ctx, before, 1000); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	for _, tok := range old {
		if _, err := store.Find(ctx, tok.TokenHash); !errors.Is(err, auth.ErrRefreshNotFound) {
			t.Errorf("a token expired over a week ago survived: %v", err)
		}
	}
	for name, tok := range map[string]*auth.RefreshToken{"recently expired": recent, "live": live} {
		if _, err := store.Find(ctx, tok.TokenHash); err != nil {
			t.Errorf("the %s token was deleted: %v", name, err)
		}
	}
}

func TestRefreshStore_RevokeFamily(t *testing.T) {
	t.Parallel()
	store, users := newStore(t)
	ctx := context.Background()
	userID := newUser(t, users)

	// Family A has two tokens, family B (another login) one.
	a1 := token(userID, "a1", time.Hour)
	if err := store.Insert(ctx, a1); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	a2 := token("", "a2", time.Hour)
	if _, err := store.Rotate(ctx, a1.TokenHash, a2, now); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	b := token(userID, "b", time.Hour)
	if err := store.Insert(ctx, b); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	revokedAt := now.Add(time.Minute)
	for range 2 { // idempotent
		if err := store.RevokeFamily(ctx, a1.FamilyID, revokedAt); err != nil {
			t.Fatalf("RevokeFamily: %v", err)
		}
	}

	for name, hash := range map[string][]byte{"a1": a1.TokenHash, "a2": a2.TokenHash} {
		got, err := store.Find(ctx, hash)
		if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) {
			t.Errorf("%s must be revoked at %v: %+v (err %v)", name, revokedAt, got, err)
		}
	}
	other, err := store.Find(ctx, b.TokenHash)
	if err != nil || other.RevokedAt != nil {
		t.Errorf("another family must be untouched: %+v (err %v)", other, err)
	}
}
