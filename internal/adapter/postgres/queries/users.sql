-- Identifiers arrive already normalised (trimmed, lowercased) from the use
-- case, so equality is exact and no lower() wrapper is needed here.

-- name: CreateUser :one
INSERT INTO ga_users (username, email, password_hash, role, status, created_by)
VALUES (
    sqlc.narg('username'),
    sqlc.narg('email'),
    sqlc.arg('password_hash'),
    sqlc.arg('role'),
    sqlc.arg('status'),
    sqlc.narg('created_by')
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM ga_users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM ga_users WHERE username = $1;

-- name: GetUserByEmail :one
SELECT * FROM ga_users WHERE email = $1;

-- Partial update: a NULL argument leaves the column untouched, so the caller
-- sends only what changed. The last-superadmin and self-demotion guards live
-- in the use case, not here.
-- name: UpdateUser :one
UPDATE ga_users
SET username   = COALESCE(sqlc.narg('username'), username),
    email      = COALESCE(sqlc.narg('email'), email),
    status     = COALESCE(sqlc.narg('status'), status),
    role       = COALESCE(sqlc.narg('role'), role),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: SetUserPassword :one
UPDATE ga_users
SET password_hash = sqlc.arg('password_hash'),
    updated_at    = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- Soft delete keeps the row so user_id references held by other services never
-- dangle; identifiers are cleared so the address can be reused. A deleted
-- account drops back to the plain role: an administrator's rank must not
-- survive the deletion of the administrator.
-- name: SoftDeleteUser :one
UPDATE ga_users
SET status     = 'deleted',
    username   = NULL,
    email      = NULL,
    role       = 'user',
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: TouchUserLogin :exec
UPDATE ga_users SET last_login_at = now() WHERE id = $1;

-- The last-superadmin guard: 1 means demoting or deleting this one would lock
-- the installation out of its own admin surface.
-- name: CountActiveSuperAdmins :one
SELECT count(*)
FROM ga_users u
JOIN ga_roles r ON r.name = u.role
WHERE r.name = 'superadmin' AND u.status = 'active';

-- name: ListUsers :many
SELECT u.* FROM ga_users u
WHERE (sqlc.narg('status')::text IS NULL OR u.status = sqlc.narg('status')::text)
  AND (
        sqlc.narg('q')::text IS NULL
     OR u.username ILIKE '%' || sqlc.narg('q')::text || '%'
     OR u.email    ILIKE '%' || sqlc.narg('q')::text || '%'
  )
  -- Delegated visibility. NULL min_rank / NULL owner mean the filter is off
  -- (mode "off", or a superadmin): the result is then identical to the
  -- unfiltered query. min_rank keeps only users strictly below the actor;
  -- owner keeps only users created by them.
  AND (sqlc.narg('min_rank')::int IS NULL OR EXISTS (
        SELECT 1 FROM ga_roles r WHERE r.name = u.role AND r.rank < sqlc.narg('min_rank')::int))
  AND (sqlc.narg('owner')::uuid IS NULL OR u.created_by = sqlc.narg('owner')::uuid)
ORDER BY u.created_at DESC, u.id DESC
LIMIT sqlc.arg('lim') OFFSET sqlc.arg('off');

-- name: CountUsers :one
SELECT count(*) FROM ga_users u
WHERE (sqlc.narg('status')::text IS NULL OR u.status = sqlc.narg('status')::text)
  AND (
        sqlc.narg('q')::text IS NULL
     OR u.username ILIKE '%' || sqlc.narg('q')::text || '%'
     OR u.email    ILIKE '%' || sqlc.narg('q')::text || '%'
  )
  AND (sqlc.narg('min_rank')::int IS NULL OR EXISTS (
        SELECT 1 FROM ga_roles r WHERE r.name = u.role AND r.rank < sqlc.narg('min_rank')::int))
  AND (sqlc.narg('owner')::uuid IS NULL OR u.created_by = sqlc.narg('owner')::uuid);

-- Transfer or clear delegated ownership. Unlike UpdateUser this is a plain
-- arg, not an narg: NULL is a meaningful value here (unassign the owner),
-- never "leave the column alone".
-- name: UpdateUserOwner :one
UPDATE ga_users SET created_by = $2, updated_at = now() WHERE id = $1 RETURNING *;
