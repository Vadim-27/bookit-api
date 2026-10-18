package periodic_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vadim-27/bookit-api/internal/platform/periodic"
)

// syncBuffer is a bytes.Buffer safe for the job goroutine and the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRun_RepeatsUntilCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runs := make(chan struct{}, 100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		periodic.Run(ctx, slog.New(slog.DiscardHandler), "test", 5*time.Millisecond, func(context.Context) error {
			runs <- struct{}{}
			return nil
		})
	}()

	// The first run happens at once, the next ones on the ticker.
	for i := range 3 {
		select {
		case <-runs:
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d did not happen", i+1)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestRun_LogsErrorsAndKeepsGoing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logs syncBuffer
	runs := make(chan struct{}, 100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		periodic.Run(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), "purge", 5*time.Millisecond, func(context.Context) error {
			runs <- struct{}{}
			return errors.New("database is down")
		})
	}()

	for range 2 { // a failing run does not stop the next one
		select {
		case <-runs:
		case <-time.After(2 * time.Second):
			t.Fatal("the job stopped after an error")
		}
	}
	cancel()
	<-done

	if out := logs.String(); !strings.Contains(out, "database is down") || !strings.Contains(out, `"job":"purge"`) {
		t.Errorf("the error was not logged with the job name: %s", out)
	}
}

func TestRun_ErrorCausedByShutdownIsNotLogged(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var logs syncBuffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		periodic.Run(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), "test", time.Hour, func(ctx context.Context) error {
			cancel() // the shutdown arrives while the job runs
			return ctx.Err()
		})
	}()
	<-done

	if out := logs.String(); out != "" {
		t.Errorf("an error caused by the shutdown was logged: %s", out)
	}
}
