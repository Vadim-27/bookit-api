package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Vadim-27/bookit-api/internal/auth"
	authhttp "github.com/Vadim-27/bookit-api/internal/auth/httpapi"
	authpg "github.com/Vadim-27/bookit-api/internal/auth/postgres"
	"github.com/Vadim-27/bookit-api/internal/platform/config"
	"github.com/Vadim-27/bookit-api/internal/platform/httpserver"
	"github.com/Vadim-27/bookit-api/internal/platform/logger"
	"github.com/Vadim-27/bookit-api/internal/platform/periodic"
	"github.com/Vadim-27/bookit-api/internal/platform/postgres"
	"github.com/Vadim-27/bookit-api/internal/platform/ratelimit"
	userpg "github.com/Vadim-27/bookit-api/internal/user/postgres"
)

const (
	// accessTokenTTL is short: a stolen access token is useless after it.
	accessTokenTTL = 15 * time.Minute
	// refreshTokenTTL is how long a session lasts without the user logging in
	// again; every refresh starts the period anew.
	refreshTokenTTL = 30 * 24 * time.Hour
	// maxSessionAge is the absolute limit: after it the password is required
	// again, however active the user is.
	maxSessionAge = 90 * 24 * time.Hour
	// sessionPurgeInterval is how often expired refresh tokens are deleted.
	sessionPurgeInterval = 24 * time.Hour

	// Login attempts per client IP: a burst of 5, then one every 12 seconds.
	loginAttemptsPerMinute = 5
	loginBurst             = 5
	// Refresh and logout are called by the app itself, so the limit is looser.
	sessionRequestsPerMinute = 20
	sessionBurst             = 10
)

func runServer() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logger.New(os.Stderr, cfg.Env == config.EnvProd, cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	// Deferred after the HTTP server stops: in-flight requests finish first.
	defer pool.Close()

	// The only place where the layers meet: repository -> service -> handlers.
	tokens, err := auth.NewTokenManager(cfg.JWTSecret, cfg.JWTPreviousSecret, accessTokenTTL, nil)
	if err != nil {
		return fmt.Errorf("create token manager: %w", err)
	}
	authenticator, err := auth.NewAuthenticator(
		userpg.NewRepository(pool), authpg.NewRefreshStore(pool), tokens,
		auth.Options{RefreshTTL: refreshTokenTTL, MaxSessionAge: maxSessionAge},
	)
	if err != nil {
		return fmt.Errorf("create authenticator: %w", err)
	}

	// Background jobs. Defers run in reverse order: on the way out the jobs are
	// cancelled first, then awaited, and only then is the pool closed above.
	jobsCtx, cancelJobs := context.WithCancel(ctx)
	var jobs sync.WaitGroup
	defer jobs.Wait()
	defer cancelJobs()
	jobs.Go(func() {
		periodic.Run(jobsCtx, log, "purge expired sessions", sessionPurgeInterval, func(ctx context.Context) error {
			n, err := authenticator.PurgeExpiredSessions(ctx)
			if n > 0 {
				log.InfoContext(ctx, "expired sessions purged", "count", n)
			}
			return err
		})
	})
	authHandler := authhttp.New(authenticator, authhttp.Options{SecureCookies: cfg.RequireHTTPS})
	// Each endpoint has its own limiter, so they do not eat each other's allowance.
	limits := authhttp.Limits{
		Login:   ratelimit.PerMinute(loginAttemptsPerMinute, loginBurst),
		Refresh: ratelimit.PerMinute(sessionRequestsPerMinute, sessionBurst),
		Logout:  ratelimit.PerMinute(sessionRequestsPerMinute, sessionBurst),
	}

	srv := httpserver.New(log, httpserver.Options{RequireHTTPS: cfg.RequireHTTPS, TrustedProxies: cfg.TrustedProxies},
		func(api *echo.Group) { authHandler.Register(api, limits) },
	)

	log.InfoContext(ctx, "starting bookit", "config", cfg)
	if err := httpserver.Run(ctx, cfg.HTTPAddr, srv); err != nil {
		return fmt.Errorf("run http server: %w", err)
	}
	log.InfoContext(ctx, "bookit stopped")
	return nil
}
