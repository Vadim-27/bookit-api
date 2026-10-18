package auth

import (
	"strings"
	"sync"
	"time"
)

// Login slow-down per account. It complements the rate limit per IP, which a
// password-guessing attack from many addresses would get around.
const (
	// freeLoginFailures failed logins for one email are free; after them every
	// further attempt has to wait.
	freeLoginFailures = 5
	// failureWindow: once no attempt failed for this long, the count is forgotten.
	failureWindow = 15 * time.Minute
	// The wait doubles with every further failure, from firstLoginDelay up to
	// maxLoginDelay. The cap is deliberately short: this slows an attacker down
	// to about one guess a minute, but never locks the real owner out — a lock
	// would let anyone block somebody else's account with wrong passwords.
	firstLoginDelay = time.Second
	maxLoginDelay   = time.Minute
	// sweepEvery bounds how often forgotten records are removed from memory.
	sweepEvery = time.Minute
	// maxThrottleKey bounds the memory of one record (an email is ≤ 254 bytes).
	maxThrottleKey = 254
)

// TooManyAttemptsError is returned by Login while an email has to wait after
// repeated failures. Its message does not say whether the account exists.
type TooManyAttemptsError struct {
	// RetryAfter is how long to wait before the next attempt.
	RetryAfter time.Duration
}

func (e *TooManyAttemptsError) Error() string {
	return "too many failed login attempts"
}

// loginThrottle counts failed logins per email in memory, so it works for one
// server instance (several instances would need a shared store such as Redis).
type loginThrottle struct {
	mu        sync.Mutex // guards records and lastSweep
	records   map[string]*failureRecord
	lastSweep time.Time
}

type failureRecord struct {
	failures int
	last     time.Time // time of the last failure
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{records: make(map[string]*failureRecord)}
}

// throttleKey turns the typed email into the key of its record. Unknown and
// even malformed emails get a record too, exactly like real ones: the slow-down
// must not reveal which accounts exist.
func throttleKey(email string) string {
	key := strings.ToLower(strings.TrimSpace(email))
	if len(key) > maxThrottleKey {
		key = key[:maxThrottleKey]
	}
	return key
}

// wait returns how long the email must wait before the next attempt; zero
// means the attempt may go ahead.
func (t *loginThrottle) wait(key string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.records[key]
	switch {
	case !ok:
		return 0
	case now.Sub(r.last) >= failureWindow:
		delete(t.records, key)
		return 0
	case r.failures < freeLoginFailures:
		return 0
	}
	if ready := r.last.Add(loginDelay(r.failures)); now.Before(ready) {
		return ready.Sub(now)
	}
	return 0
}

// failure records a failed login for the email.
func (t *loginThrottle) failure(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.sweepLocked(now)
	r, ok := t.records[key]
	if !ok || now.Sub(r.last) >= failureWindow {
		r = &failureRecord{}
		t.records[key] = r
	}
	r.failures++
	r.last = now
}

// success forgets the failures of the email after a successful login.
func (t *loginThrottle) success(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.records, key)
}

// sweepLocked removes forgotten records, at most once per sweepEvery, so the
// map cannot grow without bound. t.mu must be held.
func (t *loginThrottle) sweepLocked(now time.Time) {
	if now.Sub(t.lastSweep) < sweepEvery {
		return
	}
	t.lastSweep = now
	for key, r := range t.records {
		if now.Sub(r.last) >= failureWindow {
			delete(t.records, key)
		}
	}
}

// loginDelay is the wait after the given number of failures (at least
// freeLoginFailures): 1s, 2s, 4s, ... up to maxLoginDelay.
func loginDelay(failures int) time.Duration {
	extra := failures - freeLoginFailures
	if extra >= 6 { // 1s << 6 = 64s is over the cap; also avoids shift overflow
		return maxLoginDelay
	}
	return min(firstLoginDelay<<extra, maxLoginDelay)
}
