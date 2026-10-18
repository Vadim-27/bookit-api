// Package postgres is the PostgreSQL storage of users. It depends on the
// domain package user, never the other way around.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Vadim-27/bookit-api/internal/user"
)

// PostgreSQL error codes and the constraint name this repository reacts to.
const (
	pgUniqueViolation     = "23505"
	pgInvalidTextFormat   = "22P02" // e.g. a malformed uuid
	emailUniqueConstraint = "users_email_key"
)

// userColumns lists the columns in the order scanUser reads them. It is a
// constant on purpose: request data must never be concatenated into SQL.
const userColumns = `id, email, COALESCE(password_hash, ''), full_name, status, is_super_admin, created_at, updated_at`

// Repository stores users in PostgreSQL.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository returns a Repository that uses pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Create inserts u and fills ID, CreatedAt and UpdatedAt. It returns
// user.ErrEmailTaken when the email (compared case-insensitively) already exists.
func (r *Repository) Create(ctx context.Context, u *user.User) error {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, full_name, status, is_super_admin)
		 VALUES ($1, NULLIF($2, ''), $3, $4, $5)
		 RETURNING id, created_at, updated_at`,
		u.Email, u.PasswordHash, u.FullName, u.Status, u.IsSuperAdmin,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == emailUniqueConstraint {
			return user.ErrEmailTaken
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// FindByEmail returns the user with the given email (case-insensitive) or user.ErrNotFound.
func (r *Repository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1`, email))
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return u, nil
}

// FindByID returns the user with the given id or user.ErrNotFound. A malformed
// id cannot exist, so it is reported as user.ErrNotFound too and never as a
// server error.
func (r *Repository) FindByID(ctx context.Context, id string) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return u, nil
}

func scanUser(row pgx.Row) (*user.User, error) {
	var u user.User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.Status,
		&u.IsSuperAdmin, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, user.ErrNotFound
		case errors.As(err, &pgErr) && pgErr.Code == pgInvalidTextFormat:
			return nil, user.ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}
