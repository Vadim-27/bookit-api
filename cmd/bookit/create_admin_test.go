package main

import (
	"strings"
	"testing"
)

func TestPasswordFromReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"line with newline", "correct-horse-battery\n", "correct-horse-battery", false},
		{"windows line ending", "correct-horse-battery\r\n", "correct-horse-battery", false},
		{"no line ending", "correct-horse-battery", "correct-horse-battery", false},
		{"only the first line counts", "first-password\nsecond-password\n", "first-password", false},
		{"spaces are part of the password", "  with spaces  \n", "  with spaces  ", false},
		{"empty input", "", "", true},
		{"empty line", "\n", "", true},
		{"windows empty line", "\r\n", "", true},
		{"oversized input is cut, the policy rejects it later", strings.Repeat("a", 5000), strings.Repeat("a", maxStdinPassword), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := passwordFromReader(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("got error %v, want error %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
