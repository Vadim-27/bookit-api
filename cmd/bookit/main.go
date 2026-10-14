// Command bookit is the BookIt API server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
)

// defaultAddr is temporary: configuration from the environment comes in the next step.
const defaultAddr = ":8080"

func main() {
	if err := run(); err != nil {
		slog.Error("bookit stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := httpserver.Run(ctx, defaultAddr, httpserver.New()); err != nil {
		return fmt.Errorf("run http server: %w", err)
	}
	return nil
}
