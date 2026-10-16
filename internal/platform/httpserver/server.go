// Package httpserver builds the Echo router and runs the HTTP server.
package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
)

// Options configures the server.
type Options struct {
	// RequireHTTPS makes the server refuse requests that did not arrive over
	// HTTPS and send the HSTS header. Turn it on in every deployed environment.
	RequireHTTPS bool
}

// RouteRegistrar mounts the routes of one feature on the /api/v1 group.
// Features do not know the server, the server does not know the features: they
// are put together in cmd/bookit.
type RouteRegistrar func(api *echo.Group)

// New returns an Echo instance with the service routes and the given feature
// routes registered. Echo's own messages (startup, shutdown, handler errors)
// go through log.
func New(log *slog.Logger, opts Options, routes ...RouteRegistrar) *echo.Echo {
	e := echo.NewWithConfig(echo.Config{
		Logger:           log,
		HTTPErrorHandler: apierror.Handler,
		// The client address is the address of the connection. X-Forwarded-For
		// can be forged by anyone, so it is not trusted (rate limits depend on it).
		IPExtractor: echo.ExtractIPDirect(),
		// By default a group with middleware catches every unknown path under its
		// prefix, so an unknown URL would run, say, the auth middleware and answer
		// 401 instead of 404. Middleware is attached to real routes only.
		NoGroupAutoRegister404Routes: true,
	})

	// Pre runs before routing, so even 404 and 405 answers get the headers.
	e.Pre(securityHeaders(opts.RequireHTTPS))
	e.Use(middleware.Recover())

	e.GET("/health", health)

	api := e.Group("/api/v1")
	for _, register := range routes {
		register(api)
	}
	return e
}

func health(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// securityHeaders sets the headers every response gets and, when requireHTTPS
// is on, refuses plain HTTP. /health is exempt: platform health probes talk
// plain HTTP and the endpoint returns nothing sensitive.
func securityHeaders(requireHTTPS bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			h := c.Response().Header()
			h.Set("X-Content-Type-Options", "nosniff")
			// API answers carry tokens and personal data: never cache them.
			h.Set("Cache-Control", "no-store")

			if requireHTTPS {
				switch {
				case isHTTPS(c.Request()):
					h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
				case c.Request().URL.Path != "/health":
					return apierror.Write(c, http.StatusForbidden, apierror.CodeHTTPSRequired, "https is required")
				}
			}
			return next(c)
		}
	}
}

// isHTTPS reports whether the request arrived over TLS, either directly or
// through a TLS-terminating proxy that says so in X-Forwarded-Proto. The
// proxy header is only meaningful when the server is reachable through the
// proxy alone; a client talking to the server directly can only deceive itself.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// Run serves h on addr until ctx is cancelled, then shuts the server down
// gracefully. It returns nil after a clean shutdown.
func Run(ctx context.Context, addr string, h http.Handler) error {
	sc := echo.StartConfig{
		Address:         addr,
		HideBanner:      true,
		GracefulTimeout: 10 * time.Second,
		BeforeServeFunc: func(s *http.Server) error {
			// Slowloris protection: a client must send the headers quickly.
			s.ReadHeaderTimeout = 5 * time.Second
			s.IdleTimeout = 60 * time.Second
			// WriteTimeout is intentionally not set: it would cut long-lived
			// connections (SSE) that the notifications may need later.
			return nil
		},
	}
	return sc.Start(ctx, h)
}
