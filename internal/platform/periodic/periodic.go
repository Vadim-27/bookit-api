// Package periodic runs a background job at a fixed interval.
package periodic

import (
	"context"
	"log/slog"
	"time"
)

// Run calls job at once and then every interval until ctx is cancelled. A job
// error is logged and the next run happens on schedule. Run blocks: start it in
// a goroutine the caller waits for, so the job never outlives the resources it
// uses (such as the database pool).
func Run(ctx context.Context, log *slog.Logger, name string, interval time.Duration, job func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// An error caused by the shutdown itself is not worth a log line.
		if err := job(ctx); err != nil && ctx.Err() == nil {
			log.ErrorContext(ctx, "periodic job failed", "job", name, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
