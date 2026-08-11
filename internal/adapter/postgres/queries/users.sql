-- Identifiers arrive already normalised (trimmed, lowercased) from the use
-- case, so equality is exact and no lower() wrapper is needed here.

-- name: CreateUser :one
INSERT INTO ga_users (username, email, password_hash, is_admin, status, must_change_password)
VALUES (
    sqlc.narg('username'),
    sqlc.narg('email'),
    sqlc.arg('password_hash'),
    sqlc.arg('is_admin'),
    sqlc.arg('status'),
    sqlc.arg('must_change_password')
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM ga_users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM ga_users WHERE username = $1;

-- name: GetUserByEmail :one
SELECT * FROM ga_users WHERE email = $1;

-- Partial update: a NULL argument leaves the column untouched, so the caller
-- sends only what changed. The last-admin and self-demotion guards live in the
-- use case, not here.
-- name: UpdateUser :one
UPDATE ga_users
SET username   = COALESCE(sqlc.narg('username'), username),
    email      = COALESCE(sqlc.narg('email'), email),
    status     = COALESCE(sqlc.narg('status'), status),
    is_admin   = COALESCE(sqlc.narg('is_admin'), is_admin),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: SetUserPassword :one
UPDATE ga_users
SET password_hash        = sqlc.arg('password_hash'),
    must_change_password = sqlc.arg('must_change_password'),
    updated_at           = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- Soft delete keeps the row so user_id references held by other services never
-- dangle; identifiers are cleared so the address can be reused.
-- name: SoftDeleteUser :one
UPDATE ga_users
SET status     = 'deleted',
    username   = NULL,
    email      = NULL,
    is_admin   = false,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: TouchUserLogin :exec
UPDATE ga_users SET last_login_at = now() WHERE id = $1;

-- name: CountActiveAdmins :one
SELECT count(*) FROM ga_users WHERE is_admin = true AND status = 'active';

-- name: ListUsers :many
SELECT * FROM ga_users
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (
        sqlc.narg('q')::text IS NULL
     OR username ILIKE '%' || sqlc.narg('q')::text || '%'
     OR email    ILIKE '%' || sqlc.narg('q')::text || '%'
  )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('lim') OFFSET sqlc.arg('off');

-- name: CountUsers :one
SELECT count(*) FROM ga_users
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (
        sqlc.narg('q')::text IS NULL
     OR username ILIKE '%' || sqlc.narg('q')::text || '%'
     OR email    ILIKE '%' || sqlc.narg('q')::text || '%'
  );
