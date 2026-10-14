// Package httpserver builds the Echo router and runs the HTTP server.
package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// New returns an Echo instance with the service routes registered.
func New() *echo.Echo {
	e := echo.New()
	e.GET("/health", health)
	return e
}

func health(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
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
