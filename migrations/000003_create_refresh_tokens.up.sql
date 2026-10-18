-- Refresh tokens of user accounts. The token itself is never stored: only its
-- SHA-256, so a leaked database cannot be used to open sessions.
CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- All tokens of one login session (one chain of rotations) share a family.
    family_id  uuid        NOT NULL,
    token_hash bytea       NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    -- Set when the token was exchanged for a new one; presenting it again means theft.
    used_at    timestamptz,
    -- Set when the whole family was revoked (logout, theft, suspended account).
    revoked_at timestamptz,

    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
