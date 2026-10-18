package auth

import (
	"fmt"
	"strings"
)

// Limits from RFC 5321 / RFC 1035. There is no separate domain limit: with a
// local part and "@" the 254-character total already keeps the domain below 253.
const (
	maxEmailLen     = 254
	maxLocalPartLen = 64
	maxLabelLen     = 63
	minTLDLen       = 2
)

// localPartSpecials are the punctuation characters allowed in the local part
// (RFC 5322 "atext" without the dot, which has its own rules).
const localPartSpecials = "!#$%&'*+/=?^_`{|}~-"

// NormalizeEmail trims the email and accepts only a plain ASCII address of the
// form local@domain, a strict subset of RFC 5321. It deliberately rejects what
// the RFC allows but nobody needs and attackers like: quoted local parts,
// comments, "Name <a@b>" forms, IP literals, non-ASCII characters (look-alike
// letters, zero-width characters) and any control character, which would allow
// header injection when the address is used to send a message.
//
// The check is syntactic only: that the owner really controls the mailbox is
// proven by the confirmation email, not here. The case is preserved; uniqueness
// is case-insensitive in the database.
func NormalizeEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)

	switch {
	case email == "":
		return "", invalidEmail("is empty")
	case len(email) > maxEmailLen:
		return "", invalidEmail("is too long")
	}
	for i := 0; i < len(email); i++ {
		// Only printable ASCII without space: this excludes spaces inside the
		// address, control characters (CR, LF, NUL, tab) and all non-ASCII.
		if c := email[i]; c <= ' ' || c >= 0x7f {
			return "", invalidEmail("contains a character that is not allowed")
		}
	}

	local, domain, ok := strings.Cut(email, "@")
	switch {
	case !ok:
		return "", invalidEmail("must contain @")
	case strings.Contains(domain, "@"):
		return "", invalidEmail("must contain a single @")
	}

	if reason := checkLocalPart(local); reason != "" {
		return "", invalidEmail(reason)
	}
	if reason := checkDomain(domain); reason != "" {
		return "", invalidEmail(reason)
	}
	return email, nil
}

func invalidEmail(reason string) error {
	return fmt.Errorf("%w: email %s", ErrInvalidInput, reason)
}

// checkLocalPart returns an empty string when the part before @ is valid.
func checkLocalPart(local string) string {
	switch {
	case local == "":
		return "has an empty part before @"
	case len(local) > maxLocalPartLen:
		return "has a part before @ that is too long"
	case local[0] == '.' || local[len(local)-1] == '.':
		return "must not start or end the part before @ with a dot"
	case strings.Contains(local, ".."):
		return "must not contain two dots in a row"
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		if !isAlnum(c) && c != '.' && !strings.ContainsRune(localPartSpecials, rune(c)) {
			return "has a character that is not allowed before @"
		}
	}
	return ""
}

// checkDomain returns an empty string when the part after @ is a valid host
// name with at least two labels (so "localhost" and IP addresses are rejected).
func checkDomain(domain string) string {
	if domain == "" {
		return "has an empty part after @"
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "must have a domain with a dot after @"
	}
	for _, label := range labels {
		if reason := checkLabel(label); reason != "" {
			return reason
		}
	}

	tld := labels[len(labels)-1]
	if len(tld) < minTLDLen || isAllDigits(tld) {
		return "has an invalid top-level domain"
	}
	return ""
}

func checkLabel(label string) string {
	switch {
	case label == "":
		return "has an empty part in the domain"
	case len(label) > maxLabelLen:
		return "has a domain part that is too long"
	case label[0] == '-' || label[len(label)-1] == '-':
		return "must not start or end a domain part with a hyphen"
	}
	for i := 0; i < len(label); i++ {
		if c := label[i]; !isAlnum(c) && c != '-' {
			return "has a character that is not allowed in the domain"
		}
	}
	return ""
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
