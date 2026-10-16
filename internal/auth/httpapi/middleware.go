package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
)

// maxAuthorizationHeader bounds the header we are willing to look at: an
// access token is a few hundred bytes.
const maxAuthorizationHeader = 4 << 10

// RequireAuth is a middleware that lets a request through only with a valid
// access token of an active user. It stores the caller in the request context
// (read it with auth.PrincipalFrom) and answers 401 otherwise.
//
// The token is taken only from the Authorization header, never from the URL:
// URLs end up in logs, browser history and Referer headers.
func (h *Handler) RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		token, ok := bearerToken(c.Request())
		if !ok {
			return unauthenticated(c)
		}

		p, err := h.auth.Authenticate(c.Request().Context(), token)
		switch {
		case errors.Is(err, auth.ErrInvalidToken):
			return unauthenticated(c)
		case err != nil:
			return fmt.Errorf("authenticate: %w", err)
		}

		c.SetRequest(c.Request().WithContext(auth.WithPrincipal(c.Request().Context(), p)))
		return next(c)
	}
}

// RequirePermission returns a middleware that lets a request through only when
// the caller holds perm; it answers 403 otherwise. It must run after
// RequireAuth: without a known caller it fails closed with 401.
func RequirePermission(perm auth.Permission) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p, ok := auth.PrincipalFrom(c.Request().Context())
			if !ok {
				return unauthenticated(c)
			}
			if !p.Has(perm) {
				return apierror.Write(c, http.StatusForbidden, apierror.CodeForbidden, "insufficient permissions")
			}
			return next(c)
		}
	}
}

// bearerToken extracts the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" || len(header) > maxAuthorizationHeader {
		return "", false
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// unauthenticated answers 401 with the challenge header RFC 6750 asks for. The
// message is the same for a missing, malformed, expired or revoked token.
func unauthenticated(c *echo.Context) error {
	c.Response().Header().Set("WWW-Authenticate", `Bearer realm="bookit"`)
	return apierror.Write(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, "missing or invalid access token")
}
