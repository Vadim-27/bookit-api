-- Absolute session lifetime: every token of a login session (family) shares the
-- moment the session ends, however often it is refreshed.
ALTER TABLE refresh_tokens ADD COLUMN session_expires_at timestamptz;

-- Existing sessions end 90 days after their first token (never before a token
-- that already exists, so the constraint below holds).
UPDATE refresh_tokens AS t
SET session_expires_at = GREATEST(f.started_at + interval '90 days', t.expires_at)
FROM (SELECT family_id, min(created_at) AS started_at FROM refresh_tokens GROUP BY family_id) AS f
WHERE t.family_id = f.family_id;

ALTER TABLE refresh_tokens ALTER COLUMN session_expires_at SET NOT NULL;

ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_session_expiry_check CHECK (expires_at <= session_expires_at);

-- The periodic clean-up deletes by expiry.
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
