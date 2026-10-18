package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Subject types carried in the "typ" claim.
const (
	SubjectUser   = "user"   // platform and staff accounts
	SubjectClient = "client" // clients of one workspace
)

// minSecretBytes is the shortest accepted signing secret.
const minSecretBytes = 32

// ErrInvalidToken is returned for any token that must not be trusted. The
// reason is deliberately not exposed.
var ErrInvalidToken = errors.New("invalid token")

// Claims is what a verified access token tells us. Roles and permissions are
// not in the token: they are always read from the database.
type Claims struct {
	Subject     string // id of the user or the client
	Type        string // SubjectUser or SubjectClient
	WorkspaceID string // set for clients only
	TokenID     string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type tokenClaims struct {
	Type        string `json:"typ"`
	WorkspaceID string `json:"ws,omitempty"`
	jwt.RegisteredClaims
}

// TokenManager issues and verifies short-lived HS256 access tokens. It signs
// with the current secret and accepts the previous one for verification, so a
// secret can be rotated without logging everybody out.
type TokenManager struct {
	secrets [][]byte // current first, then the optional previous one
	ttl     time.Duration
	now     func() time.Time
}

// NewTokenManager returns a TokenManager. previousSecret may be empty. now may
// be nil (time.Now is used); tests inject a fixed clock.
func NewTokenManager(secret, previousSecret string, ttl time.Duration, now func() time.Time) (*TokenManager, error) {
	if ttl <= 0 {
		return nil, errors.New("token ttl must be positive")
	}
	secrets := [][]byte{[]byte(secret)}
	if previousSecret != "" {
		secrets = append(secrets, []byte(previousSecret))
	}
	// The messages never include the secret itself.
	for i, s := range secrets {
		if len(s) < minSecretBytes {
			return nil, fmt.Errorf("jwt secret #%d is shorter than %d bytes", i+1, minSecretBytes)
		}
	}
	if now == nil {
		now = time.Now
	}
	return &TokenManager{secrets: secrets, ttl: ttl, now: now}, nil
}

// Issue returns a signed access token for the subject and its expiry time.
// A client token must carry its workspace id; a user token must not.
func (m *TokenManager) Issue(subject, typ, workspaceID string) (string, time.Time, error) {
	if err := checkSubject(subject, typ, workspaceID); err != nil {
		return "", time.Time{}, err
	}
	id, err := newTokenID()
	if err != nil {
		return "", time.Time{}, err
	}

	now := m.now()
	expiresAt := now.Add(m.ttl)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims{
		Type:        typ,
		WorkspaceID: workspaceID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ID:        id,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})
	signed, err := token.SignedString(m.secrets[0])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, expiresAt, nil
}

// Parse verifies the token and returns its claims. Every failure is reported
// as ErrInvalidToken.
func (m *TokenManager) Parse(raw string) (*Claims, error) {
	for _, secret := range m.secrets {
		claims, err := m.parseWith(raw, secret)
		switch {
		case err == nil:
			return claims, nil
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			continue // maybe it was signed with the previous secret
		default:
			return nil, ErrInvalidToken
		}
	}
	return nil, ErrInvalidToken
}

func (m *TokenManager) parseWith(raw string, secret []byte) (*Claims, error) {
	var tc tokenClaims
	_, err := jwt.ParseWithClaims(raw, &tc,
		func(*jwt.Token) (any, error) { return secret, nil },
		// Only the expected algorithm: this also rejects "alg": "none".
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil {
		return nil, err
	}
	if err := checkSubject(tc.Subject, tc.Type, tc.WorkspaceID); err != nil {
		return nil, err
	}
	return &Claims{
		Subject:     tc.Subject,
		Type:        tc.Type,
		WorkspaceID: tc.WorkspaceID,
		TokenID:     tc.ID,
		IssuedAt:    tc.IssuedAt.Time,
		ExpiresAt:   tc.ExpiresAt.Time,
	}, nil
}

// checkSubject enforces the shape of the claims we issue and accept.
func checkSubject(subject, typ, workspaceID string) error {
	switch {
	case subject == "":
		return errors.New("token subject is empty")
	case typ == SubjectUser && workspaceID == "":
		return nil
	case typ == SubjectClient && workspaceID != "":
		return nil
	}
	return errors.New("token type does not match its workspace")
}

func newTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
