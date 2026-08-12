-- goauth's entire schema: identity, refresh-token sessions, audit trail.
--
-- Applied at every startup, so every statement is idempotent. There is no
-- migration tool and no version table — the service creates what it needs and
-- leaves alone what already exists.
--
-- Adding to this file later means adding idempotent statements:
-- `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`.
-- A bare `CREATE TABLE IF NOT EXISTS` will not add a column to a table that
-- already exists, because the whole statement is skipped.
--
-- Table prefix ga_ keeps these distinguishable when the service shares a
-- database with a consuming application. Consuming services store user_id as a
-- plain column and never foreign-key into ga_users.
--
-- Identifiers are plain text, not citext: they are normalised (trimmed and
-- lowercased) in Go before they ever reach the database, so a plain UNIQUE is
-- exact. That keeps normalisation explicit and in one place, and avoids
-- teaching pgx a dynamically-assigned extension type OID.

CREATE TABLE IF NOT EXISTS ga_users (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username             text UNIQUE,
    email                text UNIQUE,
    password_hash        text        NOT NULL,
    is_admin             boolean     NOT NULL DEFAULT false,
    status               text        NOT NULL DEFAULT 'active',
    must_change_password boolean     NOT NULL DEFAULT false,
    last_login_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT ga_users_identifier_present CHECK (username IS NOT NULL OR email IS NOT NULL),
    CONSTRAINT ga_users_status_valid       CHECK (status IN ('active', 'blocked', 'deleted'))
);

-- Refresh tokens live here rather than in Redis: reuse detection needs the
-- family history, "my sessions" needs a queryable list, and a cache flush must
-- not log every user out.
CREATE TABLE IF NOT EXISTS ga_sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES ga_users (id) ON DELETE CASCADE,
    family_id    uuid        NOT NULL,
    refresh_hash bytea       NOT NULL UNIQUE,
    used_at      timestamptz,
    expires_at   timestamptz NOT NULL,
    ip           text,
    user_agent   text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ga_sessions_user_live_idx ON ga_sessions (user_id) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS ga_sessions_family_idx    ON ga_sessions (family_id);
CREATE INDEX IF NOT EXISTS ga_sessions_expires_idx   ON ga_sessions (expires_at);

CREATE TABLE IF NOT EXISTS ga_audit_log (
    id             bigserial PRIMARY KEY,
    actor          text        NOT NULL,
    action         text        NOT NULL,
    target_user_id uuid,
    ip             text,
    meta           jsonb       NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ga_audit_log_target_idx  ON ga_audit_log (target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ga_audit_log_created_idx ON ga_audit_log (created_at DESC);
