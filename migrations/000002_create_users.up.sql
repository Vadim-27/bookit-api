-- Platform and staff accounts. Clients of a workspace live in a separate table.
CREATE TABLE users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email          citext      NOT NULL,
    -- NULL while an invited user has not set a password yet.
    password_hash  text,
    full_name      text        NOT NULL,
    status         text        NOT NULL DEFAULT 'active',
    is_super_admin boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_length CHECK (char_length(email) <= 254),
    CONSTRAINT users_full_name_length CHECK (char_length(full_name) BETWEEN 1 AND 200),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'pending_invite', 'suspended')),
    CONSTRAINT users_password_required CHECK (status = 'pending_invite' OR password_hash IS NOT NULL)
);
