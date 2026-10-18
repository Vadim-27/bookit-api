DROP INDEX IF EXISTS refresh_tokens_expires_at_idx;
ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_session_expiry_check;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS session_expires_at;
