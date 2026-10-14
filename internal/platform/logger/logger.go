// Package logger builds the application's structured logger.
package logger

import (
	"io"
	"log/slog"
)

// New returns a logger writing to w. JSON output is meant for production
// (machine-readable), text output for local development.
func New(w io.Writer, json bool, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if json {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
