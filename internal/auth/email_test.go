package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	var (
		local64 = strings.Repeat("a", 64)
		label63 = strings.Repeat("b", 63)
		// 64 + "@" + 63 + "." + 63 + "." + 57 + ".com" is exactly 254 characters.
		email254 = local64 + "@" + label63 + "." + label63 + "." + strings.Repeat("c", 57) + ".com"
	)

	valid := []struct {
		name  string
		input string
		want  string // normalized form
	}{
		{"simple", "user@example.com", "user@example.com"},
		{"trimmed", "  user@example.com \t", "user@example.com"},
		{"trailing newline is trimmed, not an error", "user@example.com\n", "user@example.com"},
		{"case is preserved", "User.Name@Example.COM", "User.Name@Example.COM"},
		{"plus tag", "user+tag@example.com", "user+tag@example.com"},
		{"dots in local part", "first.last@example.com", "first.last@example.com"},
		{"apostrophe", "o'brien@example.com", "o'brien@example.com"},
		{"all allowed specials", "a!#$%&'*+/=?^_`{|}~-z@example.com", "a!#$%&'*+/=?^_`{|}~-z@example.com"},
		{"digits only local part", "1234567890@example.com", "1234567890@example.com"},
		{"subdomains", "user@mail.dept.example.co.uk", "user@mail.dept.example.co.uk"},
		{"hyphen inside label", "user@exa-mple.com", "user@exa-mple.com"},
		{"digit-only label before the tld", "user@123.example.com", "user@123.example.com"},
		{"punycode domain", "user@xn--80ak6aa92e.com", "user@xn--80ak6aa92e.com"},
		{"two-letter tld", "a@b.co", "a@b.co"},
		{"local part of exactly 64", local64 + "@example.com", local64 + "@example.com"},
		{"domain label of exactly 63", "a@" + label63 + ".com", "a@" + label63 + ".com"},
		{"total length of exactly 254", email254, email254},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := auth.NormalizeEmail(tt.input)
			if err != nil {
				t.Fatalf("NormalizeEmail(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeEmail(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}

	invalid := []struct {
		name  string
		input string
	}{
		// Empty and structure.
		{"empty", ""},
		{"only spaces", "   "},
		{"no at sign", "user.example.com"},
		{"two at signs", "a@b@example.com"},
		{"at sign only", "@"},
		{"empty local part", "@example.com"},
		{"empty domain", "user@"},
		{"two addresses with a comma", "a@example.com,b@example.com"},
		{"two addresses with a semicolon", "a@example.com;b@example.com"},

		// Forms that net/mail would accept.
		{"display name", "Vadym <user@example.com>"},
		{"angle brackets only", "<user@example.com>"},
		{"quoted local part", `"john doe"@example.com`},
		{"comment", "user(comment)@example.com"},
		{"ip literal", "user@[127.0.0.1]"},
		{"bare ip address", "user@127.0.0.1"},

		// Whitespace and control characters (header injection, truncation).
		{"space inside", "us er@example.com"},
		{"space in domain", "user@exam ple.com"},
		{"tab inside", "us\ter@example.com"},
		{"newline inside", "user@example.com\nBcc: evil@example.com"},
		{"carriage return and newline", "user@example.com\r\nBcc: evil@example.com"},
		{"newline in domain", "user@exam\nple.com"},
		{"nul byte", "user\x00@example.com"},
		{"delete character", "user\x7f@example.com"},

		// Non-ASCII: look-alike letters and invisible characters.
		{"cyrillic local part", "юзер@example.com"},
		{"cyrillic domain", "user@приклад.укр"},
		{"non-breaking space inside", "us er@example.com"},
		{"zero-width space inside", "us​er@example.com"},
		{"cyrillic a that looks latin", "аdmin@example.com"},

		// Local part rules.
		{"leading dot", ".user@example.com"},
		{"trailing dot", "user.@example.com"},
		{"two dots in a row", "us..er@example.com"},
		{"forbidden character in local part", "us:er@example.com"},
		{"backslash", `us\er@example.com`},
		{"local part of 65", strings.Repeat("a", 65) + "@example.com"},

		// Domain rules.
		{"no dot in domain", "user@localhost"},
		{"trailing dot in domain", "user@example.com."},
		{"leading dot in domain", "user@.example.com"},
		{"two dots in domain", "user@example..com"},
		{"label starts with hyphen", "user@-example.com"},
		{"label ends with hyphen", "user@example-.com"},
		{"underscore in domain", "user@exa_mple.com"},
		{"single-letter tld", "user@example.c"},
		{"all-digit tld", "user@example.123"},
		{"domain label of 64", "a@" + strings.Repeat("b", 64) + ".com"},

		// Length.
		{"total length of 255", local64 + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 58) + ".com"},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := auth.NormalizeEmail(tt.input)
			if err == nil {
				t.Fatalf("NormalizeEmail(%q): got %q and no error, want an error", tt.input, got)
			}
			if !errors.Is(err, auth.ErrInvalidInput) {
				t.Errorf("error %v does not wrap ErrInvalidInput", err)
			}
			if got != "" {
				t.Errorf("NormalizeEmail(%q): got %q together with an error, want empty", tt.input, got)
			}
		})
	}
}
