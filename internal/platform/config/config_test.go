package config_test

import (
	"bytes"
	"log/slog"
	"maps"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/Vadim-27/bookit-api/internal/platform/config"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ipNet
}

const (
	testPassword  = "s3cretpw"
	testDBURL     = "postgres://u:" + testPassword + "@localhost:5433/db?sslmode=disable"
	testJWTSecret = "0123456789abcdef0123456789abcdef" // 32 bytes
	testJWTOld    = "fedcba9876543210fedcba9876543210"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		env          map[string]string // overrides on top of a valid base environment
		want         config.Config
		wantErr      []string // substrings that must all appear in the error
		wantNotInErr []string // substrings that must not appear (secrets)
	}{
		{
			name: "defaults",
			env:  nil,
			want: config.Config{
				Env: config.EnvDev, HTTPAddr: ":8080", LogLevel: slog.LevelInfo,
				DatabaseURL: testDBURL, DBMaxConns: 10, JWTSecret: testJWTSecret,
			},
		},
		{
			name: "custom values",
			env: map[string]string{
				"BOOKIT_ENV":                 "prod",
				"BOOKIT_HTTP_ADDR":           "127.0.0.1:9000",
				"BOOKIT_LOG_LEVEL":           "debug",
				"BOOKIT_DB_MAX_CONNS":        "25",
				"BOOKIT_JWT_SECRET_PREVIOUS": testJWTOld,
				"BOOKIT_REQUIRE_HTTPS":       "true",
				"BOOKIT_TRUSTED_PROXIES":     " 173.245.48.0/20 ,2400:cb00::/32,, ",
			},
			want: config.Config{
				Env: config.EnvProd, HTTPAddr: "127.0.0.1:9000", LogLevel: slog.LevelDebug,
				DatabaseURL: testDBURL, DBMaxConns: 25,
				JWTSecret: testJWTSecret, JWTPreviousSecret: testJWTOld,
				RequireHTTPS:   true,
				TrustedProxies: []*net.IPNet{mustCIDR(t, "173.245.48.0/20"), mustCIDR(t, "2400:cb00::/32")},
			},
		},
		{
			name:    "trusted proxy that is not a range",
			env:     map[string]string{"BOOKIT_TRUSTED_PROXIES": "10.0.0.0/8, cloudflare"},
			wantErr: []string{"BOOKIT_TRUSTED_PROXIES", "cloudflare"},
		},
		{
			name:    "trusted proxy as a bare address",
			env:     map[string]string{"BOOKIT_TRUSTED_PROXIES": "10.0.0.1"},
			wantErr: []string{"BOOKIT_TRUSTED_PROXIES"},
		},
		{
			name:    "require https is not a boolean",
			env:     map[string]string{"BOOKIT_REQUIRE_HTTPS": "sometimes"},
			wantErr: []string{"BOOKIT_REQUIRE_HTTPS"},
		},
		{
			name:    "unknown env",
			env:     map[string]string{"BOOKIT_ENV": "staging"},
			wantErr: []string{"BOOKIT_ENV"},
		},
		{
			name:    "address without port",
			env:     map[string]string{"BOOKIT_HTTP_ADDR": "localhost"},
			wantErr: []string{"BOOKIT_HTTP_ADDR"},
		},
		{
			name:    "unknown log level",
			env:     map[string]string{"BOOKIT_LOG_LEVEL": "loud"},
			wantErr: []string{"BOOKIT_LOG_LEVEL"},
		},
		{
			name:    "missing database url",
			env:     map[string]string{"BOOKIT_DATABASE_URL": ""},
			wantErr: []string{"BOOKIT_DATABASE_URL"},
		},
		{
			name:         "wrong database scheme does not leak the password",
			env:          map[string]string{"BOOKIT_DATABASE_URL": "mysql://u:" + testPassword + "@h/db"},
			wantErr:      []string{"BOOKIT_DATABASE_URL"},
			wantNotInErr: []string{testPassword},
		},
		{
			name:         "unparsable database url does not leak the password",
			env:          map[string]string{"BOOKIT_DATABASE_URL": "postgres://u:" + testPassword + "@h:99x/db"},
			wantErr:      []string{"BOOKIT_DATABASE_URL"},
			wantNotInErr: []string{testPassword},
		},
		{
			name:    "max conns is not a number",
			env:     map[string]string{"BOOKIT_DB_MAX_CONNS": "many"},
			wantErr: []string{"BOOKIT_DB_MAX_CONNS"},
		},
		{
			name:    "max conns is zero",
			env:     map[string]string{"BOOKIT_DB_MAX_CONNS": "0"},
			wantErr: []string{"BOOKIT_DB_MAX_CONNS"},
		},
		{
			name:    "missing jwt secret",
			env:     map[string]string{"BOOKIT_JWT_SECRET": ""},
			wantErr: []string{"BOOKIT_JWT_SECRET"},
		},
		{
			name:         "short jwt secret is rejected without being echoed",
			env:          map[string]string{"BOOKIT_JWT_SECRET": "too-short-secret"},
			wantErr:      []string{"BOOKIT_JWT_SECRET", "32"},
			wantNotInErr: []string{"too-short-secret"},
		},
		{
			name:         "short previous jwt secret is rejected without being echoed",
			env:          map[string]string{"BOOKIT_JWT_SECRET_PREVIOUS": "old-short"},
			wantErr:      []string{"BOOKIT_JWT_SECRET_PREVIOUS"},
			wantNotInErr: []string{"old-short"},
		},
		{
			name: "all errors are reported together",
			env: map[string]string{
				"BOOKIT_ENV":          "x",
				"BOOKIT_HTTP_ADDR":    "nope",
				"BOOKIT_LOG_LEVEL":    "loud",
				"BOOKIT_DATABASE_URL": "",
				"BOOKIT_DB_MAX_CONNS": "-1",
				"BOOKIT_JWT_SECRET":   "",
			},
			wantErr: []string{
				"BOOKIT_ENV", "BOOKIT_HTTP_ADDR", "BOOKIT_LOG_LEVEL",
				"BOOKIT_DATABASE_URL", "BOOKIT_DB_MAX_CONNS", "BOOKIT_JWT_SECRET",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{
				"BOOKIT_DATABASE_URL": testDBURL,
				"BOOKIT_JWT_SECRET":   testJWTSecret,
			}
			maps.Copy(env, tt.env)

			got, err := config.Load(func(key string) string { return env[key] })

			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load: got nil error, want error mentioning %v", tt.wantErr)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q does not mention %q", err, s)
					}
				}
				for _, s := range tt.wantNotInErr {
					if strings.Contains(err.Error(), s) {
						t.Errorf("error %q leaks %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load: got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestConfig_LogValueHidesSecrets(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Env: config.EnvDev, HTTPAddr: ":8080", DatabaseURL: testDBURL, DBMaxConns: 10,
		JWTSecret: testJWTSecret, JWTPreviousSecret: testJWTOld,
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config", "config", cfg)

	out := buf.String()
	for _, secret := range []string{testPassword, "postgres://", testJWTSecret, testJWTOld} {
		if strings.Contains(out, secret) {
			t.Errorf("log output leaks %q: %s", secret, out)
		}
	}
	if !strings.Contains(out, `"db_max_conns":10`) {
		t.Errorf("log output misses db_max_conns: %s", out)
	}
}
