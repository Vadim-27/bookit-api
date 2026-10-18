package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

// failLogins makes n failed logins for email.
func failLogins(t *testing.T, e *env, email string, n int) {
	t.Helper()
	for i := range n {
		if _, err := e.auth.Login(context.Background(), email, "wrong-password-xx"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("failure %d: got %v, want ErrInvalidCredentials", i+1, err)
		}
	}
}

func TestLogin_SlowsDownAfterRepeatedFailures(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	failLogins(t, e, "boss@example.com", 5)
	callsBefore := e.users.emailCalls

	// Even the right password must wait now: a guess sent too early is not
	// checked at all, so it tells nothing.
	_, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
	var tooMany *auth.TooManyAttemptsError
	if !errors.As(err, &tooMany) {
		t.Fatalf("got %v, want *TooManyAttemptsError", err)
	}
	if tooMany.RetryAfter != time.Second {
		t.Errorf("RetryAfter: got %v, want 1s", tooMany.RetryAfter)
	}
	if e.users.emailCalls != callsBefore {
		t.Error("a throttled attempt still reached the user storage")
	}

	// After the wait the right password works and clears the count.
	e.clock.Advance(time.Second)
	if _, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword); err != nil {
		t.Fatalf("login after the wait: %v", err)
	}
	failLogins(t, e, "boss@example.com", 4) // free again after the success
}

func TestLogin_SlowDownDoesNotRevealAccounts(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	failLogins(t, e, "boss@example.com", 5)
	failLogins(t, e, "nobody@example.com", 5)

	var existing, unknown *auth.TooManyAttemptsError
	_, errExisting := e.auth.Login(context.Background(), "boss@example.com", "x")
	_, errUnknown := e.auth.Login(context.Background(), "nobody@example.com", "x")
	if !errors.As(errExisting, &existing) || !errors.As(errUnknown, &unknown) {
		t.Fatalf("both must be throttled: existing %v, unknown %v", errExisting, errUnknown)
	}
	if existing.RetryAfter != unknown.RetryAfter || existing.Error() != unknown.Error() {
		t.Errorf("throttling differs: existing %v (%v), unknown %v (%v)",
			existing, existing.RetryAfter, unknown, unknown.RetryAfter)
	}
}

func TestLogin_SlowDownIgnoresCaseOfTheEmail(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	failLogins(t, e, "boss@example.com", 3)
	failLogins(t, e, "BOSS@Example.com", 2)

	_, err := e.auth.Login(context.Background(), " Boss@EXAMPLE.com ", loginPassword)
	var tooMany *auth.TooManyAttemptsError
	if !errors.As(err, &tooMany) {
		t.Errorf("changing the case must not give fresh attempts: got %v", err)
	}
}

func TestLogin_SlowDownIsNotALockout(t *testing.T) {
	t.Parallel()

	e := newEnv(t, activeBoss(t))
	// An attacker hammers the account: guess, and when told to wait, wait.
	// 20 rounds are enough: the delay reaches its cap after 11 failures.
	for range 20 {
		_, err := e.auth.Login(context.Background(), "boss@example.com", "probe-password-1")
		var tooMany *auth.TooManyAttemptsError
		if errors.As(err, &tooMany) {
			if tooMany.RetryAfter > time.Minute {
				t.Fatalf("during the attack the wait grew to %v, over the one-minute cap", tooMany.RetryAfter)
			}
			e.clock.Advance(tooMany.RetryAfter)
		}
	}

	// ...yet the owner never waits more than a minute.
	_, err := e.auth.Login(context.Background(), "boss@example.com", loginPassword)
	var tooMany *auth.TooManyAttemptsError
	if errors.As(err, &tooMany) {
		if tooMany.RetryAfter > time.Minute {
			t.Fatalf("the owner has to wait %v, more than the one-minute cap", tooMany.RetryAfter)
		}
		e.clock.Advance(tooMany.RetryAfter)
		_, err = e.auth.Login(context.Background(), "boss@example.com", loginPassword)
	}
	if err != nil {
		t.Errorf("the owner cannot log in after waiting: %v", err)
	}
}
