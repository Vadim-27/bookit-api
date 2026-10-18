package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/Vadim-27/bookit-api/internal/user"
)

// Authenticate verifies an access token and returns who is calling. The account
// is read from the database on every request, so a suspended user is cut off at
// once instead of when the token expires. Every problem with the token or the
// account is reported as ErrInvalidToken; any other error is an infrastructure
// problem.
func (a *Authenticator) Authenticate(ctx context.Context, accessToken string) (*Principal, error) {
	claims, err := a.tokens.Parse(accessToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	// A client token opens client endpoints only, never staff or platform ones.
	if claims.Type != SubjectUser {
		return nil, ErrInvalidToken
	}

	u, err := a.users.FindByID(ctx, claims.Subject)
	switch {
	case errors.Is(err, user.ErrNotFound):
		return nil, ErrInvalidToken
	case err != nil:
		return nil, fmt.Errorf("find user: %w", err)
	case u.Status != user.StatusActive:
		return nil, ErrInvalidToken
	}
	return principalFor(u), nil
}
