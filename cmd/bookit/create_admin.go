package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/platform/config"
	"github.com/Vadim-27/bookit-api/internal/platform/postgres"
	userpg "github.com/Vadim-27/bookit-api/internal/user/postgres"
)

// adminPasswordEnv is the fallback for terminals that cannot hide the input
// (for example Git Bash on Windows). Set it only for the one command.
const adminPasswordEnv = "BOOKIT_ADMIN_PASSWORD"

func runCreateAdmin(args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "email of the new super admin (required)")
	name := fs.String("name", "", "full name of the new super admin (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *name == "" {
		return errors.New("both -email and -name are required")
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	password, err := readPassword()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, 2)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer pool.Close()

	svc := auth.NewService(userpg.NewRepository(pool))
	u, err := svc.CreateSuperAdmin(ctx, *email, *name, password)
	if err != nil {
		return err
	}
	fmt.Printf("super admin created: id=%s email=%s\n", u.ID, u.Email)
	return nil
}

// readPassword asks for the password twice with hidden input. When stdin is
// not a terminal it falls back to the BOOKIT_ADMIN_PASSWORD variable.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		if p := os.Getenv(adminPasswordEnv); p != "" {
			return p, nil
		}
		return "", fmt.Errorf("stdin is not a terminal: set %s for this command", adminPasswordEnv)
	}

	first, err := promptHidden(fd, "Password: ")
	if err != nil {
		return "", err
	}
	second, err := promptHidden(fd, "Repeat password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	return first, nil
}

func promptHidden(fd int, prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(b), nil
}
