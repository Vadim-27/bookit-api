package auth

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func TestLoginDelay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		failures int
		want     time.Duration
	}{
		{5, time.Second},
		{6, 2 * time.Second},
		{7, 4 * time.Second},
		{10, 32 * time.Second},
		{11, time.Minute}, // 64s is over the cap
		{1000, time.Minute},
	}
	for _, tt := range tests {
		if got := loginDelay(tt.failures); got != tt.want {
			t.Errorf("loginDelay(%d): got %v, want %v", tt.failures, got, tt.want)
		}
	}
}

func TestLoginThrottle_SlowsDownAfterFreeFailures(t *testing.T) {
	t.Parallel()

	th := newLoginThrottle()
	const key = "boss@example.com"

	for i := 1; i <= freeLoginFailures; i++ {
		if w := th.wait(key, t0); w != 0 {
			t.Fatalf("attempt %d of the free ones had to wait %v", i, w)
		}
		th.failure(key, t0)
	}

	if w := th.wait(key, t0); w != time.Second {
		t.Errorf("after %d failures: wait %v, want 1s", freeLoginFailures, w)
	}
	if w := th.wait(key, t0.Add(400*time.Millisecond)); w != 600*time.Millisecond {
		t.Errorf("0.4s later: wait %v, want the remaining 0.6s", w)
	}
	if w := th.wait(key, t0.Add(time.Second)); w != 0 {
		t.Errorf("after the delay: wait %v, want 0", w)
	}

	// Another failure doubles the delay.
	th.failure(key, t0.Add(time.Second))
	if w := th.wait(key, t0.Add(time.Second)); w != 2*time.Second {
		t.Errorf("after one more failure: wait %v, want 2s", w)
	}
}

func TestLoginThrottle_Forgets(t *testing.T) {
	t.Parallel()

	t.Run("after a success", func(t *testing.T) {
		t.Parallel()
		th := newLoginThrottle()
		for range 10 {
			th.failure("k", t0)
		}
		th.success("k")
		if w := th.wait("k", t0); w != 0 {
			t.Errorf("wait after success: %v, want 0", w)
		}
	})

	t.Run("after a quiet window", func(t *testing.T) {
		t.Parallel()
		th := newLoginThrottle()
		for range 10 {
			th.failure("k", t0)
		}
		later := t0.Add(failureWindow)
		if w := th.wait("k", later); w != 0 {
			t.Errorf("wait after the window: %v, want 0", w)
		}
		// The count starts again from scratch: the next failures are free.
		for i := 1; i <= freeLoginFailures-1; i++ {
			th.failure("k", later)
			if w := th.wait("k", later); w != 0 {
				t.Fatalf("failure %d after the window already waits %v", i, w)
			}
		}
	})
}

func TestLoginThrottle_KeysAreIndependent(t *testing.T) {
	t.Parallel()

	th := newLoginThrottle()
	for range 10 {
		th.failure("victim@example.com", t0)
	}
	if w := th.wait("other@example.com", t0); w != 0 {
		t.Errorf("another email has to wait %v", w)
	}
}

func TestLoginThrottle_SweepsForgottenRecords(t *testing.T) {
	t.Parallel()

	th := newLoginThrottle()
	for i := range 500 {
		th.failure(fmt.Sprintf("guess-%d@example.com", i), t0)
	}
	th.failure("fresh@example.com", t0.Add(failureWindow+sweepEvery))

	th.mu.Lock()
	defer th.mu.Unlock()
	if len(th.records) != 1 {
		t.Errorf("records after the sweep: got %d, want only the fresh one", len(th.records))
	}
}

func TestLoginThrottle_ConcurrentFailuresAreAllCounted(t *testing.T) {
	t.Parallel()

	th := newLoginThrottle()
	const attempts = 50
	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() { th.failure("k", t0) })
	}
	wg.Wait()

	th.mu.Lock()
	defer th.mu.Unlock()
	if got := th.records["k"].failures; got != attempts {
		t.Errorf("failures: got %d, want %d (lost updates)", got, attempts)
	}
}

func TestThrottleKey(t *testing.T) {
	t.Parallel()

	if throttleKey("  Boss@Example.COM \n") != throttleKey("boss@example.com") {
		t.Error("the key must not depend on case or surrounding spaces")
	}
	if got := len(throttleKey(strings.Repeat("a", 5000))); got != maxThrottleKey {
		t.Errorf("key length: got %d, want %d", got, maxThrottleKey)
	}
}
