package auth_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/user"
)

// login starts a session for the boss account and returns it.
func login(t *testing.T, e *env) *auth.Session {
	t.Helper()
	s, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return s
}

func refresh(e *env, token string) (*auth.Session, error) {
	return e.auth.Refresh(context.Background(), token)
}

func TestRefresh_RotatesTheToken(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	first := login(t, e)
	e.clock.Advance(5 * time.Minute)

	second, err := refresh(e, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Error("refresh returned the same tokens: nothing was rotated")
	}
	if claims, err := e.tokens.Parse(second.AccessToken); err != nil || claims.Subject != "user-1" {
		t.Errorf("new access token: claims %+v, error %v", claims, err)
	}
	if want := epoch.Add(5*time.Minute + refreshTTL); !second.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt: got %v, want %v", second.RefreshExpiresAt, want)
	}

	// The whole chain is one family, and the new token works in turn.
	stored := e.sessions.all()
	if len(stored) != 2 || stored[0].FamilyID != stored[1].FamilyID {
		t.Fatalf("stored tokens: got %+v, want two tokens of one family", stored)
	}
	if _, err := refresh(e, second.RefreshToken); err != nil {
		t.Errorf("the rotated token does not work: %v", err)
	}
}

func TestRefresh_ReusedTokenRevokesTheWholeSession(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	first := login(t, e)
	second, err := refresh(e, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Long after the exchange the old token shows up again: it was stolen.
	e.clock.Advance(time.Minute)
	if _, err := refresh(e, first.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("reused token: got %v, want ErrInvalidToken", err)
	}

	// The thief's chain and the honest user's chain die together.
	if _, err := refresh(e, second.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("the newest token after theft was detected: got %v, want ErrInvalidToken", err)
	}
	for _, tok := range e.sessions.all() {
		if tok.RevokedAt == nil {
			t.Errorf("token %s of the family is not revoked", tok.ID)
		}
	}
}

func TestRefresh_ReuseRightAfterUseIsOnlyRefused(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	first := login(t, e)
	second, err := refresh(e, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// A double submit (two browser tabs) a moment later: refused, not punished.
	e.clock.Advance(2 * time.Second)
	if _, err := refresh(e, first.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("double submit: got %v, want ErrInvalidToken", err)
	}
	if _, err := refresh(e, second.RefreshToken); err != nil {
		t.Errorf("the session must survive a double submit: %v", err)
	}
}

func TestRefresh_ConcurrentUseOfOneTokenSucceedsOnce(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	first := login(t, e)

	const attempts = 20
	var wg sync.WaitGroup
	results := make(chan *auth.Session, attempts)
	for range attempts {
		wg.Go(func() {
			if s, err := refresh(e, first.RefreshToken); err == nil {
				results <- s
			}
		})
	}
	wg.Wait()
	close(results)

	var winners []*auth.Session
	for s := range results {
		winners = append(winners, s)
	}
	if len(winners) != 1 {
		t.Fatalf("%d concurrent refreshes of one token succeeded, want exactly 1", len(winners))
	}
	if len(e.sessions.all()) != 2 {
		t.Errorf("stored tokens: got %d, want 2 (the login one and one rotation)", len(e.sessions.all()))
	}
	if _, err := refresh(e, winners[0].RefreshToken); err != nil {
		t.Errorf("the winner's session was damaged by the losers: %v", err)
	}
}

func TestRefresh_Rejects(t *testing.T) {
	t.Parallel()

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		s := login(t, e)
		e.clock.Advance(refreshTTL + time.Second)
		if _, err := refresh(e, s.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		if _, err := refresh(e, strings.Repeat("A", 43)); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("malformed tokens never reach the store", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		for _, bad := range []string{"", "short", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 5000)} {
			if _, err := refresh(e, bad); !errors.Is(err, auth.ErrInvalidToken) {
				t.Errorf("token of length %d: got %v, want ErrInvalidToken", len(bad), err)
			}
		}
		if e.sessions.rotateCalls != 0 {
			t.Errorf("the store was asked %d times about malformed tokens", e.sessions.rotateCalls)
		}
	})

	t.Run("account suspended after login", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		s := login(t, e)
		e.users.setStatus("boss@example.com", user.StatusSuspended)

		if _, err := refresh(e, s.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("got %v, want ErrInvalidToken", err)
		}
		for _, tok := range e.sessions.all() {
			if tok.RevokedAt == nil {
				t.Errorf("token %s survived the suspension", tok.ID)
			}
		}
	})

	t.Run("account no longer exists", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		s := login(t, e)
		delete(e.users.users, "boss@example.com")

		if _, err := refresh(e, s.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("user storage failure is not hidden as an invalid token", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		s := login(t, e)
		e.users.err = errors.New("database is down")

		_, err := refresh(e, s.RefreshToken)
		if err == nil || errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("got %v, want a storage error", err)
		}
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()

	t.Run("ends the session", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		first := login(t, e)
		second, err := refresh(e, first.RefreshToken)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}

		if err := e.auth.Logout(context.Background(), second.RefreshToken); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if _, err := refresh(e, second.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("a logged out token still works: %v", err)
		}
		for _, tok := range e.sessions.all() {
			if tok.RevokedAt == nil {
				t.Errorf("token %s of the family is not revoked", tok.ID)
			}
		}
	})

	t.Run("is idempotent and quiet about unknown tokens", func(t *testing.T) {
		t.Parallel()

		e := newEnv(t, activeBoss(t))
		s := login(t, e)
		for _, token := range []string{s.RefreshToken, s.RefreshToken, strings.Repeat("A", 43), "", "short"} {
			if err := e.auth.Logout(context.Background(), token); err != nil {
				t.Errorf("Logout(%q): %v", token, err)
			}
		}
	})
}

func TestRefreshTokenIsNeverStored(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	first := login(t, e)
	second, err := refresh(e, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	for _, tok := range e.sessions.all() {
		for _, secret := range []string{first.RefreshToken, second.RefreshToken} {
			if bytes.Contains(tok.TokenHash, []byte(secret)) {
				t.Errorf("a stored record contains a refresh token: %+v", tok)
			}
		}
		if len(tok.TokenHash) != 32 {
			t.Errorf("stored hash length: got %d, want 32", len(tok.TokenHash))
		}
	}
}
