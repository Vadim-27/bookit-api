package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Vadim-27/bookit-api/internal/auth"
	"github.com/Vadim-27/bookit-api/internal/platform/config"
	"github.com/Vadim-27/bookit-api/internal/platform/postgres"
	userpg "github.com/Vadim-27/bookit-api/internal/user/postgres"
)

// maxStdinPassword bounds what is read from stdin. A valid password is at most
// 72 bytes, so anything longer is rejected later by the password policy.
const maxStdinPassword = 1 << 10

func runCreateAdmin(args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	email := fs.String("email", "", "email of the new super admin (required)")
	name := fs.String("name", "", "full name of the new super admin (required)")
	passwordStdin := fs.Bool("password-stdin", false,
		"read the password from the first line of stdin (for terminals that cannot hide input)")
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

	password, err := readPassword(*passwordStdin)
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

// readPassword returns the password of the new admin. With fromStdin it reads
// the first line of stdin; otherwise it asks twice with hidden input.
//
// The password is never taken from a command-line argument or an environment
// variable: arguments end up in the shell history and the process list, and the
// environment is inherited by child processes.
func readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		return passwordFromReader(os.Stdin)
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal: pipe the password and add -password-stdin")
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

// passwordFromReader returns the first line of r without its line ending.
// Spaces are part of the password and are kept.
func passwordFromReader(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxStdinPassword)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", errors.New("no password on stdin")
	}
	return password, nil
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
