// Package postgres is the PostgreSQL storage of the auth service. It depends
// on the auth package, never the other way around.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Vadim-27/bookit-api/internal/auth"
)

// refreshColumns lists the columns in the order scanToken reads them. It is a
// constant on purpose: request data must never be concatenated into SQL.
const refreshColumns = `id, user_id, family_id, token_hash, created_at, expires_at, used_at, revoked_at`

// RefreshStore keeps refresh tokens in PostgreSQL.
type RefreshStore struct {
	pool *pgxpool.Pool
}

// NewRefreshStore returns a RefreshStore that uses pool.
func NewRefreshStore(pool *pgxpool.Pool) *RefreshStore {
	return &RefreshStore{pool: pool}
}

// Insert stores t. An empty FamilyID starts a new family. It fills ID and FamilyID.
func (s *RefreshStore) Insert(ctx context.Context, t *auth.RefreshToken) error {
	return insert(ctx, s.pool, t)
}

// queryRower is what both the pool and a transaction can do.
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func insert(ctx context.Context, q queryRower, t *auth.RefreshToken) error {
	var family *string // NULL makes the database generate a new family id
	if t.FamilyID != "" {
		family = &t.FamilyID
	}
	err := q.QueryRow(ctx,
		`INSERT INTO refresh_tokens (user_id, family_id, token_hash, created_at, expires_at)
		 VALUES ($1, COALESCE($2::uuid, gen_random_uuid()), $3, $4, $5)
		 RETURNING id, family_id`,
		t.UserID, family, t.TokenHash, t.CreatedAt, t.ExpiresAt,
	).Scan(&t.ID, &t.FamilyID)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

// Rotate marks the token with oldHash as used and stores next in the same
// family, in one transaction. The UPDATE only matches an unused, unrevoked,
// unexpired token, and the database lets just one of several concurrent
// updates of a row through, so a token can be exchanged exactly once.
func (s *RefreshStore) Rotate(ctx context.Context, oldHash []byte, next *auth.RefreshToken, now time.Time) (*auth.RefreshToken, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // a no-op after Commit

	prev, err := scanToken(tx.QueryRow(ctx,
		`UPDATE refresh_tokens SET used_at = $2
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
		 RETURNING `+refreshColumns,
		oldHash, now))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrRefreshNotUsable
	}
	if err != nil {
		return nil, fmt.Errorf("use refresh token: %w", err)
	}

	next.UserID, next.FamilyID = prev.UserID, prev.FamilyID
	if err := insert(ctx, tx, next); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit rotation: %w", err)
	}
	return prev, nil
}

// Find returns the token with the given hash or auth.ErrRefreshNotFound.
func (s *RefreshStore) Find(ctx context.Context, hash []byte) (*auth.RefreshToken, error) {
	t, err := scanToken(s.pool.QueryRow(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrRefreshNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return t, nil
}

// RevokeFamily revokes every token of the family that is not revoked yet.
func (s *RefreshStore) RevokeFamily(ctx context.Context, familyID string, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`,
		familyID, now)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

func scanToken(row pgx.Row) (*auth.RefreshToken, error) {
	var t auth.RefreshToken
	err := row.Scan(&t.ID, &t.UserID, &t.FamilyID, &t.TokenHash,
		&t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
