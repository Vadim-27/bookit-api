package logger_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/platform/logger"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		json     bool
		level    slog.Level
		logDebug bool // whether a debug record is written in addition to an info one
		wantJSON bool
	}{
		{"prod writes JSON", true, slog.LevelInfo, false, true},
		{"dev writes text", false, slog.LevelInfo, false, false},
		{"debug level lets debug through", false, slog.LevelDebug, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := logger.New(&buf, tt.json, tt.level)
			log.Debug("debug record")
			log.Info("info record", "key", "value")

			out := buf.String()
			if !strings.Contains(out, "info record") {
				t.Errorf("info record missing in %q", out)
			}
			if got := strings.Contains(out, "debug record"); got != tt.logDebug {
				t.Errorf("debug record written: got %v, want %v", got, tt.logDebug)
			}

			first, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
			if got := json.Valid([]byte(first)); got != tt.wantJSON {
				t.Errorf("first line is JSON: got %v, want %v (line %q)", got, tt.wantJSON, first)
			}
		})
	}
}
