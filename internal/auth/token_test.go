package auth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

const (
	secretA = "0123456789abcdef0123456789abcdef"
	secretB = "fedcba9876543210fedcba9876543210"
)

var epoch = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func newManager(t *testing.T, secret, previous string, now time.Time) *auth.TokenManager {
	t.Helper()
	m, err := auth.NewTokenManager(secret, previous, 15*time.Minute, fixedClock(now))
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return m
}

// forge signs arbitrary claims with any method, to build hostile tokens.
func forge(t *testing.T, method jwt.SigningMethod, key any, claims jwt.Claims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	return s
}

type forgedClaims struct {
	Type        string `json:"typ"`
	WorkspaceID string `json:"ws,omitempty"`
	jwt.RegisteredClaims
}

func goodClaims() forgedClaims {
	return forgedClaims{
		Type: auth.SubjectUser,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			IssuedAt:  jwt.NewNumericDate(epoch),
			ExpiresAt: jwt.NewNumericDate(epoch.Add(15 * time.Minute)),
		},
	}
}

func TestNewTokenManager_RejectsBadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		secret   string
		previous string
		ttl      time.Duration
	}{
		{"short secret", "tiny-secret-xyz", "", time.Minute},
		{"empty secret", "", "", time.Minute},
		{"short previous secret", secretA, "old-secret-xyz", time.Minute},
		{"zero ttl", secretA, "", 0},
		{"negative ttl", secretA, "", -time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := auth.NewTokenManager(tt.secret, tt.previous, tt.ttl, nil)
			if err == nil {
				t.Fatal("got nil error, want an error")
			}
			for _, s := range []string{tt.secret, tt.previous} {
				if len(s) > 3 && strings.Contains(err.Error(), s) {
					t.Errorf("error leaks a secret: %v", err)
				}
			}
		})
	}
}

func TestToken_IssueAndParse(t *testing.T) {
	t.Parallel()

	m := newManager(t, secretA, "", epoch)

	t.Run("user token", func(t *testing.T) {
		t.Parallel()

		raw, expiresAt, err := m.Issue("user-1", auth.SubjectUser, "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if want := epoch.Add(15 * time.Minute); !expiresAt.Equal(want) {
			t.Errorf("expiresAt: got %v, want %v", expiresAt, want)
		}

		got, err := m.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got.Subject != "user-1" || got.Type != auth.SubjectUser || got.WorkspaceID != "" {
			t.Errorf("claims: got %+v", got)
		}
		if got.TokenID == "" || !got.ExpiresAt.Equal(expiresAt) || !got.IssuedAt.Equal(epoch) {
			t.Errorf("claims metadata: got %+v", got)
		}
	})

	t.Run("client token carries the workspace", func(t *testing.T) {
		t.Parallel()

		raw, _, err := m.Issue("client-9", auth.SubjectClient, "ws-3")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		got, err := m.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if got.Type != auth.SubjectClient || got.WorkspaceID != "ws-3" {
			t.Errorf("claims: got %+v", got)
		}
	})

	t.Run("token ids are unique", func(t *testing.T) {
		t.Parallel()

		a, _, _ := m.Issue("user-1", auth.SubjectUser, "")
		b, _, _ := m.Issue("user-1", auth.SubjectUser, "")
		if a == b {
			t.Error("two tokens are identical: jti is not random")
		}
	})
}

func TestToken_IssueRejectsInconsistentClaims(t *testing.T) {
	t.Parallel()

	m := newManager(t, secretA, "", epoch)
	tests := []struct {
		name, subject, typ, ws string
	}{
		{"empty subject", "", auth.SubjectUser, ""},
		{"unknown type", "u", "admin", ""},
		{"user with a workspace", "u", auth.SubjectUser, "ws-1"},
		{"client without a workspace", "c", auth.SubjectClient, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := m.Issue(tt.subject, tt.typ, tt.ws); err == nil {
				t.Error("Issue: got nil error, want an error")
			}
		})
	}
}

func TestToken_ParseRejects(t *testing.T) {
	t.Parallel()

	m := newManager(t, secretA, "", epoch)
	good, _, err := m.Issue("user-1", auth.SubjectUser, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	expired := goodClaims()
	expired.ExpiresAt = jwt.NewNumericDate(epoch.Add(-time.Second))
	noExp := goodClaims()
	noExp.ExpiresAt = nil
	future := goodClaims()
	future.IssuedAt = jwt.NewNumericDate(epoch.Add(time.Hour))
	noSub := goodClaims()
	noSub.Subject = ""
	badType := goodClaims()
	badType.Type = "admin"
	clientNoWS := goodClaims()
	clientNoWS.Type = auth.SubjectClient
	userWithWS := goodClaims()
	userWithWS.WorkspaceID = "ws-1"

	// Tamper: replace the payload of a valid token, keep the old signature.
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + strings.Split(forge(t, jwt.SigningMethodHS256, []byte(secretA), userWithWS), ".")[1] + "." + parts[2]

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not.a.jwt"},
		{"random text", "hello"},
		{"alg none", forge(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, goodClaims())},
		{"other hmac algorithm", forge(t, jwt.SigningMethodHS384, []byte(secretA), goodClaims())},
		{"wrong secret", forge(t, jwt.SigningMethodHS256, []byte(secretB), goodClaims())},
		{"expired", forge(t, jwt.SigningMethodHS256, []byte(secretA), expired)},
		{"no exp claim", forge(t, jwt.SigningMethodHS256, []byte(secretA), noExp)},
		{"issued in the future", forge(t, jwt.SigningMethodHS256, []byte(secretA), future)},
		{"no subject", forge(t, jwt.SigningMethodHS256, []byte(secretA), noSub)},
		{"unknown type", forge(t, jwt.SigningMethodHS256, []byte(secretA), badType)},
		{"client without workspace", forge(t, jwt.SigningMethodHS256, []byte(secretA), clientNoWS)},
		{"user with workspace", forge(t, jwt.SigningMethodHS256, []byte(secretA), userWithWS)},
		{"tampered payload", tampered},
		{"truncated signature", good[:len(good)-4]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := m.Parse(tt.token)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("Parse: got %v, want ErrInvalidToken", err)
			}
			if got != nil {
				t.Errorf("Parse returned claims %+v together with an error", got)
			}
		})
	}

	t.Run("accepts the control token", func(t *testing.T) {
		t.Parallel()

		if _, err := m.Parse(good); err != nil {
			t.Errorf("Parse of a valid token: %v", err)
		}
	})
}

func TestToken_Expiry(t *testing.T) {
	t.Parallel()

	issuer := newManager(t, secretA, "", epoch)
	raw, _, err := issuer.Issue("user-1", auth.SubjectUser, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tests := []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{"just issued", epoch, false},
		{"one second before expiry", epoch.Add(15*time.Minute - time.Second), false},
		{"at expiry", epoch.Add(15 * time.Minute), true},
		{"a day later", epoch.Add(24 * time.Hour), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verifier := newManager(t, secretA, "", tt.now)
			_, err := verifier.Parse(raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse at %v: got error %v, want error %v", tt.now, err, tt.wantErr)
			}
		})
	}
}

func TestToken_SecretRotation(t *testing.T) {
	t.Parallel()

	// A token signed before the rotation, with the old secret.
	oldIssuer := newManager(t, secretA, "", epoch)
	oldToken, _, err := oldIssuer.Issue("user-1", auth.SubjectUser, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	t.Run("during rotation the previous secret still verifies", func(t *testing.T) {
		t.Parallel()

		rotated := newManager(t, secretB, secretA, epoch)
		if _, err := rotated.Parse(oldToken); err != nil {
			t.Errorf("old token was rejected during rotation: %v", err)
		}
	})

	t.Run("new tokens are signed with the current secret only", func(t *testing.T) {
		t.Parallel()

		rotated := newManager(t, secretB, secretA, epoch)
		fresh, _, err := rotated.Issue("user-1", auth.SubjectUser, "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		onlyNew := newManager(t, secretB, "", epoch)
		if _, err := onlyNew.Parse(fresh); err != nil {
			t.Errorf("new token does not verify with the current secret alone: %v", err)
		}
		onlyOld := newManager(t, secretA, "", epoch)
		if _, err := onlyOld.Parse(fresh); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("new token verifies with the old secret: %v", err)
		}
	})

	t.Run("after rotation without the previous secret the old token is rejected", func(t *testing.T) {
		t.Parallel()

		finished := newManager(t, secretB, "", epoch)
		if _, err := finished.Parse(oldToken); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("old token accepted after rotation finished: %v", err)
		}
	})
}
