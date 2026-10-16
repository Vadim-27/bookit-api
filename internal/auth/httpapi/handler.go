// Package httpapi is the HTTP transport of the auth service: it parses
// requests, calls the service through an interface and maps its errors to
// HTTP answers. It knows nothing about storage.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
	"github.com/Vadim-27/bookit-api/internal/platform/httpjson"
)

const (
	// maxLoginBody bounds the request body: a login is a few dozen bytes.
	maxLoginBody = 4 << 10

	// The refresh token travels only in this cookie. JavaScript cannot read it
	// (HttpOnly) and the browser sends it only to the auth endpoints (Path).
	refreshCookieName = "bookit_refresh"
	refreshCookiePath = "/api/v1/auth"
)

// Authenticator is what the handler needs from the auth service.
type Authenticator interface {
	Login(ctx context.Context, email, password string) (*auth.Session, error)
	Refresh(ctx context.Context, refreshToken string) (*auth.Session, error)
	Logout(ctx context.Context, refreshToken string) error
	Authenticate(ctx context.Context, accessToken string) (*auth.Principal, error)
}

// Options configures the handler.
type Options struct {
	// SecureCookies marks the refresh cookie Secure: browsers then send it only
	// over HTTPS. Turn it on in every deployed environment.
	SecureCookies bool
}

// Limits are the rate limiters of the endpoints.
type Limits struct {
	Login, Refresh, Logout echo.MiddlewareFunc
}

// Handler serves the auth endpoints.
type Handler struct {
	auth Authenticator
	opts Options
}

// New returns a Handler that uses a.
func New(a Authenticator, opts Options) *Handler {
	return &Handler{auth: a, opts: opts}
}

// Register mounts the auth routes on the /api/v1 group.
func (h *Handler) Register(api *echo.Group, limits Limits) {
	// Public: anyone may try to log in.
	api.POST("/auth/login", h.login, limits.Login)
	api.POST("/auth/refresh", h.refresh, limits.Refresh)
	api.POST("/auth/logout", h.logout, limits.Logout)

	// Protected: any authenticated user.
	protected := api.Group("", h.RequireAuth)
	protected.GET("/me", h.me)
}

// meResponse describes the caller. Permissions are there for the interface to
// decide which buttons to show; the server checks them again on every request.
type meResponse struct {
	ID           string            `json:"id"`
	Email        string            `json:"email"`
	FullName     string            `json:"full_name"`
	IsSuperAdmin bool              `json:"is_super_admin"`
	Permissions  []auth.Permission `json:"permissions"`
}

func (h *Handler) me(c *echo.Context) error {
	p, ok := auth.PrincipalFrom(c.Request().Context())
	if !ok {
		// Only possible if the route lost RequireAuth: fail closed.
		return unauthenticated(c)
	}
	return c.JSON(http.StatusOK, meResponse{
		ID:           p.UserID,
		Email:        p.Email,
		FullName:     p.FullName,
		IsSuperAdmin: p.IsSuperAdmin,
		Permissions:  p.Permissions(),
	})
}

// loginRequest is the whole input of a login: nothing else can be sent.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// tokenResponse is the body of a successful login or refresh. The refresh
// token is deliberately absent: it is sent only as a cookie.
type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func newTokenResponse(s *auth.Session) tokenResponse {
	return tokenResponse{AccessToken: s.AccessToken, TokenType: "Bearer", ExpiresAt: s.AccessExpiresAt.UTC()}
}

func (h *Handler) login(c *echo.Context) error {
	var req loginRequest
	if err := httpjson.Decode(c, &req, maxLoginBody); err != nil {
		return err
	}

	s, err := h.auth.Login(c.Request().Context(), req.Email, req.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		// The same answer for every kind of failure: no hints for guessing.
		return apierror.Write(c, http.StatusUnauthorized, apierror.CodeInvalidCredentials, "invalid credentials")
	case err != nil:
		// The central error handler logs it and answers a generic 500.
		return fmt.Errorf("login: %w", err)
	}

	h.setRefreshCookie(c, s)
	return c.JSON(http.StatusOK, newTokenResponse(s))
}

func (h *Handler) refresh(c *echo.Context) error {
	cookie, err := c.Request().Cookie(refreshCookieName)
	if err != nil {
		return h.rejectSession(c)
	}

	s, err := h.auth.Refresh(c.Request().Context(), cookie.Value)
	switch {
	case errors.Is(err, auth.ErrInvalidToken):
		return h.rejectSession(c)
	case err != nil:
		return fmt.Errorf("refresh: %w", err)
	}

	h.setRefreshCookie(c, s)
	return c.JSON(http.StatusOK, newTokenResponse(s))
}

func (h *Handler) logout(c *echo.Context) error {
	if cookie, err := c.Request().Cookie(refreshCookieName); err == nil {
		if err := h.auth.Logout(c.Request().Context(), cookie.Value); err != nil {
			return fmt.Errorf("logout: %w", err)
		}
	}
	h.clearRefreshCookie(c)
	return c.NoContent(http.StatusNoContent)
}

// rejectSession answers 401 and removes the useless cookie from the browser.
func (h *Handler) rejectSession(c *echo.Context) error {
	h.clearRefreshCookie(c)
	return apierror.Write(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, "invalid or expired session")
}

func (h *Handler) setRefreshCookie(c *echo.Context, s *auth.Session) {
	http.SetCookie(c.Response(), h.refreshCookie(s.RefreshToken, s.RefreshExpiresAt.UTC(), 0))
}

func (h *Handler) clearRefreshCookie(c *echo.Context) {
	http.SetCookie(c.Response(), h.refreshCookie("", time.Unix(0, 0), -1))
}

// refreshCookie builds the cookie. The attributes must be identical when it is
// cleared, otherwise the browser keeps the old one.
func (h *Handler) refreshCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     refreshCookiePath,
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.opts.SecureCookies,
		// Strict: the browser never sends the cookie on a cross-site request,
		// which also shuts the door on CSRF against /auth/refresh.
		SameSite: http.SameSiteStrictMode,
	}
}
