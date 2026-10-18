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
	"strings"
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
	// JWTSecret signs access tokens. JWTPreviousSecret, when set, is still
	// accepted for verification: it makes secret rotation seamless. Never log
	// them or put their values into an error message.
	JWTSecret         string
	JWTPreviousSecret string
	// RequireHTTPS makes the server refuse plain HTTP requests and send HSTS.
	// Turn it on in every deployed environment, dev included.
	RequireHTTPS bool
	// TrustedProxies are the address ranges of the proxies in front of the
	// server (e.g. Cloudflare). Only requests from them may name the real
	// client in X-Forwarded-For and the scheme in X-Forwarded-Proto. Empty
	// means no proxy: the address of the connection is the client.
	TrustedProxies []*net.IPNet
}

// LogValue implements slog.LogValuer, so logging a Config never leaks secrets.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", c.Env),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("log_level", c.LogLevel.String()),
		slog.Int("db_max_conns", int(c.DBMaxConns)),
		slog.Bool("require_https", c.RequireHTTPS),
		slog.Int("trusted_proxy_ranges", len(c.TrustedProxies)),
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

		JWTSecret:         getenv("BOOKIT_JWT_SECRET"),
		JWTPreviousSecret: getenv("BOOKIT_JWT_SECRET_PREVIOUS"),
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

	requireHTTPS, err := strconv.ParseBool(cmp.Or(getenv("BOOKIT_REQUIRE_HTTPS"), "false"))
	if err != nil {
		errs = append(errs, errors.New("BOOKIT_REQUIRE_HTTPS: want true or false"))
	}
	cfg.RequireHTTPS = requireHTTPS

	proxies, err := parseTrustedProxies(getenv("BOOKIT_TRUSTED_PROXIES"))
	if err != nil {
		errs = append(errs, err)
	}
	cfg.TrustedProxies = proxies

	if err := validateSecret("BOOKIT_JWT_SECRET", cfg.JWTSecret, true); err != nil {
		errs = append(errs, err)
	}
	if err := validateSecret("BOOKIT_JWT_SECRET_PREVIOUS", cfg.JWTPreviousSecret, false); err != nil {
		errs = append(errs, err)
	}

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

// minSecretBytes is the shortest accepted signing secret. The messages never
// contain the secret itself.
const minSecretBytes = 32

func validateSecret(name, value string, required bool) error {
	switch {
	case value == "" && required:
		return fmt.Errorf("%s: required", name)
	case value != "" && len(value) < minSecretBytes:
		return fmt.Errorf("%s: must be at least %d bytes", name, minSecretBytes)
	}
	return nil
}

// parseTrustedProxies parses a comma-separated list of CIDR ranges such as
// "173.245.48.0/20, 2400:cb00::/32". An empty string means no proxy.
func parseTrustedProxies(raw string) ([]*net.IPNet, error) {
	var ranges []*net.IPNet
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("BOOKIT_TRUSTED_PROXIES: %q is not a CIDR range like 10.0.0.0/8", part)
		}
		ranges = append(ranges, ipNet)
	}
	return ranges, nil
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
