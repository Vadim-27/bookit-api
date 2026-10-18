package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

func TestSession_EndsAfterMaxAgeHoweverActive(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	s := login(t, e)

	stored := e.sessions.all()
	if len(stored) != 1 || !stored[0].SessionExpiresAt.Equal(epoch.Add(maxSessionAge)) {
		t.Fatalf("the session end is not set at login: %+v", stored)
	}

	// An active user refreshes every 29 days: each refresh works...
	for day := 29; day <= 87; day += 29 {
		e.clock.Advance(29 * 24 * time.Hour)
		next, err := refresh(e, s.RefreshToken)
		if err != nil {
			t.Fatalf("refresh on day %d: %v", day, err)
		}
		s = next
	}

	// ...but on day 87 the new token may live only until the session ends
	// (day 90), not the usual 30 days (day 117).
	if want := epoch.Add(maxSessionAge); !s.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt on day 87: got %v, want the session end %v", s.RefreshExpiresAt, want)
	}

	// After day 90 the password is required again.
	e.clock.Advance(3*24*time.Hour + time.Second)
	if _, err := refresh(e, s.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("refresh after the session ended: got %v, want ErrInvalidToken", err)
	}
}

// expiredToken builds a stored token that expired ago before epoch.
func expiredToken(seq int, ago time.Duration) auth.RefreshToken {
	return auth.RefreshToken{
		ID:               fmt.Sprintf("rt-x%d", seq),
		UserID:           "user-1",
		FamilyID:         fmt.Sprintf("family-x%d", seq),
		TokenHash:        fmt.Appendf(nil, "hash-%d", seq),
		CreatedAt:        epoch.Add(-ago - refreshTTL),
		ExpiresAt:        epoch.Add(-ago),
		SessionExpiresAt: epoch.Add(-ago),
	}
}

func TestPurgeExpiredSessions_KeepsRecentAndLiveTokens(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	live := login(t, e)                                         // expires in 30 days
	e.sessions.put(expiredToken(1, 10*24*time.Hour))            // expired 10 days ago: deleted
	e.sessions.put(expiredToken(2, 8*24*time.Hour))             // expired 8 days ago: deleted
	e.sessions.put(expiredToken(3, 3*24*time.Hour))             // expired 3 days ago: kept a week
	e.sessions.put(expiredToken(4, 7*24*time.Hour-time.Second)) // just under a week: kept

	n, err := e.auth.PurgeExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted: got %d, want 2", n)
	}
	if got := len(e.sessions.all()); got != 3 {
		t.Errorf("remaining tokens: got %d, want 3", got)
	}
	if _, err := refresh(e, live.RefreshToken); err != nil {
		t.Errorf("the purge damaged a live session: %v", err)
	}
}

func TestPurgeExpiredSessions_WorksInBatches(t *testing.T) {
	t.Parallel()

	e := newEnv(t, nil)
	const total = 2500
	for i := range total {
		e.sessions.put(expiredToken(i, 30*24*time.Hour))
	}

	n, err := e.auth.PurgeExpiredSessions(context.Background())
	if err != nil {
		t.Fatalf("PurgeExpiredSessions: %v", err)
	}
	if n != total || len(e.sessions.all()) != 0 {
		t.Errorf("deleted %d of %d, %d left", n, total, len(e.sessions.all()))
	}
	if e.sessions.purgeCalls != 3 { // 1000 + 1000 + 500
		t.Errorf("batches: got %d calls, want 3", e.sessions.purgeCalls)
	}
}

func TestPurgeExpiredSessions_StopsWhenCancelled(t *testing.T) {
	t.Parallel()

	e := newEnv(t, nil)
	for i := range 2500 {
		e.sessions.put(expiredToken(i, 30*24*time.Hour))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the server is shutting down

	n, err := e.auth.PurgeExpiredSessions(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want context.Canceled", err)
	}
	if n != 1000 {
		t.Errorf("deleted: got %d, want one batch (1000) before stopping", n)
	}
}
