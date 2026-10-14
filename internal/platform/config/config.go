// Package config loads the application configuration from environment variables.
package config

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
)

const defaultDBMaxConns = 10

// Supported values of BOOKIT_ENV.
const (
	EnvDev  = "dev"
	EnvProd = "prod"
)

// Config is the typed application configuration, parsed once at startup.
type Config struct {
	// Env is the deployment environment: EnvDev or EnvProd.
	Env string
	// HTTPAddr is the address the HTTP server listens on, e.g. ":8080".
	HTTPAddr string
	// LogLevel is the minimum level of the application logs.
	LogLevel slog.Level
	// DatabaseURL is the PostgreSQL connection string. It contains a password:
	// never log it or put its value into an error message.
	DatabaseURL string
	// DBMaxConns is the maximum number of pooled database connections.
	DBMaxConns int32
}

// LogValue implements slog.LogValuer, so logging a Config never leaks secrets.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", c.Env),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("log_level", c.LogLevel.String()),
		slog.Int("db_max_conns", int(c.DBMaxConns)),
	)
}

// Load reads the configuration using getenv (usually os.Getenv). Taking the
// function as a parameter keeps Load testable without touching the process
// environment. All problems are reported at once, not one per run.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Env:         cmp.Or(getenv("BOOKIT_ENV"), EnvDev),
		HTTPAddr:    cmp.Or(getenv("BOOKIT_HTTP_ADDR"), ":8080"),
		DatabaseURL: getenv("BOOKIT_DATABASE_URL"),
	}

	var errs []error
	if cfg.Env != EnvDev && cfg.Env != EnvProd {
		errs = append(errs, fmt.Errorf("BOOKIT_ENV: unknown value %q (want %q or %q)", cfg.Env, EnvDev, EnvProd))
	}
	if _, _, err := net.SplitHostPort(cfg.HTTPAddr); err != nil {
		errs = append(errs, fmt.Errorf("BOOKIT_HTTP_ADDR: %w", err))
	}
	if err := cfg.LogLevel.UnmarshalText([]byte(cmp.Or(getenv("BOOKIT_LOG_LEVEL"), "info"))); err != nil {
		errs = append(errs, fmt.Errorf("BOOKIT_LOG_LEVEL: %w", err))
	}

	if err := validateDatabaseURL(cfg.DatabaseURL); err != nil {
		errs = append(errs, err)
	}

	maxConns, err := parseMaxConns(getenv("BOOKIT_DB_MAX_CONNS"))
	if err != nil {
		errs = append(errs, err)
	}
	cfg.DBMaxConns = maxConns

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validateDatabaseURL checks only the shape of the URL. Its errors deliberately
// do not include the value: url.Parse would echo the password back.
func validateDatabaseURL(raw string) error {
	if raw == "" {
		return errors.New("BOOKIT_DATABASE_URL: required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("BOOKIT_DATABASE_URL: not a valid URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return errors.New("BOOKIT_DATABASE_URL: scheme must be postgres or postgresql")
	}
	return nil
}

func parseMaxConns(raw string) (int32, error) {
	if raw == "" {
		return defaultDBMaxConns, nil
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("BOOKIT_DB_MAX_CONNS: want an integer >= 1, got %q", raw)
	}
	return int32(n), nil
}
