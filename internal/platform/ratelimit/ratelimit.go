// Package ratelimit limits how often one client may call an endpoint.
package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Vadim-27/bookit-api/internal/platform/apierror"
)

// PerMinute returns a middleware that lets one client IP make perMinute
// requests per minute on average, with at most burst requests at once. Every
// request counts, successful or not. Over the limit the client gets 429 with a
// Retry-After header.
//
// The client is identified by the IP address of the connection (the Echo
// IPExtractor decides, see httpserver), so a forged X-Forwarded-For header
// cannot create a fresh allowance. Counters live in memory: they are reset by
// a restart and are not shared between instances.
func PerMinute(perMinute float64, burst int) echo.MiddlewareFunc {
	store := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate:      perMinute / 60,
		Burst:     burst,
		ExpiresIn: 10 * time.Minute,
	})
	retryAfter := strconv.Itoa(int(math.Ceil(60 / perMinute)))

	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store:               store,
		IdentifierExtractor: func(c *echo.Context) (string, error) { return c.RealIP(), nil },
		ErrorHandler: func(c *echo.Context, _ error) error {
			return apierror.Write(c, http.StatusForbidden, apierror.CodeForbidden, "client cannot be identified")
		},
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			c.Response().Header().Set("Retry-After", retryAfter)
			return apierror.Write(c, http.StatusTooManyRequests, apierror.CodeTooManyRequests, "too many requests")
		},
	})
}
