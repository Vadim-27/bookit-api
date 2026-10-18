// Package arch_test enforces the layering rules of .claude/rules/architecture.md:
// domain, service, repository and handlers must not know about each other's
// technology. It only parses imports, so it needs no database.
package arch_test

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/Vadim-27/bookit-api"

// Technology packages that only the outer layers may use.
var (
	sqlDriver = []string{"github.com/jackc/pgx"}
	httpStack = []string{"github.com/labstack/echo", "net/http"}
)

// rule says that production code directly in dir (subpackages are checked by
// their own rules) must not import anything under the forbidden prefixes.
type rule struct {
	dir       string // relative to the repository root
	forbidden []string
	why       string
}

var rules = []rule{
	{
		dir:       "internal/user",
		forbidden: concat(sqlDriver, httpStack, module+"/internal/auth", module+"/internal/user/postgres"),
		why:       "the domain knows nothing about storage, HTTP or services",
	},
	{
		dir:       "internal/auth",
		forbidden: concat(sqlDriver, httpStack, module+"/internal/user/postgres", module+"/internal/auth/postgres", module+"/internal/auth/httpapi"),
		why:       "the service depends on interfaces, not on storage or transport",
	},
	{
		dir:       "internal/auth/postgres",
		forbidden: concat(httpStack, module+"/internal/auth/httpapi"),
		why:       "the auth storage knows nothing about HTTP",
	},
	{
		dir:       "internal/user/postgres",
		forbidden: concat(httpStack, module+"/internal/auth", module+"/internal/auth/httpapi"),
		why:       "the repository knows nothing about services or HTTP",
	},
	{
		dir:       "internal/auth/httpapi",
		forbidden: concat(sqlDriver, module+"/internal/user/postgres", module+"/internal/auth/postgres"),
		why:       "handlers know nothing about storage",
	},
}

func concat(groups ...any) []string {
	var out []string
	for _, g := range groups {
		switch v := g.(type) {
		case string:
			out = append(out, v)
		case []string:
			out = append(out, v...)
		}
	}
	return out
}

func TestLayering(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}

	for _, r := range rules {
		t.Run(r.dir, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join(root, filepath.FromSlash(r.dir))
			entries, err := os.ReadDir(dir)
			if errors.Is(err, fs.ErrNotExist) {
				t.Skipf("%s does not exist yet", r.dir)
			}
			if err != nil {
				t.Fatalf("read %s: %v", r.dir, err)
			}

			for _, e := range entries {
				name := e.Name()
				if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
				if err != nil {
					t.Fatalf("parse %s/%s: %v", r.dir, name, err)
				}
				for _, imp := range file.Imports {
					path, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						t.Fatalf("bad import %s in %s/%s: %v", imp.Path.Value, r.dir, name, err)
					}
					for _, bad := range r.forbidden {
						if path == bad || strings.HasPrefix(path, bad+"/") {
							t.Errorf("%s/%s imports %q: %s", r.dir, name, path, r.why)
						}
					}
				}
			}
		})
	}
}
