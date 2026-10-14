// Command bookit is the BookIt API server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Vadim-27/bookit-api/internal/platform/config"
	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
	"github.com/Vadim-27/bookit-api/internal/platform/logger"
	"github.com/Vadim-27/bookit-api/internal/platform/postgres"
)

func main() {
	if err := run(); err != nil {
		slog.Error("bookit stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(os.Stderr, cfg.Env == config.EnvProd, cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	// Deferred after the HTTP server stops: in-flight requests finish first.
	defer pool.Close()

	log.InfoContext(ctx, "starting bookit", "config", cfg)
	if err := httpserver.Run(ctx, cfg.HTTPAddr, httpserver.New(log)); err != nil {
		return fmt.Errorf("run http server: %w", err)
	}
	log.InfoContext(ctx, "bookit stopped")
	return nil
}
