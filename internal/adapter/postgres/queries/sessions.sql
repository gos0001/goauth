-- name: CreateSession :one
INSERT INTO ga_sessions (user_id, family_id, refresh_hash, expires_at, ip, user_agent)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSessionByRefreshHash :one
SELECT * FROM ga_sessions WHERE refresh_hash = $1;

-- name: GetSessionByID :one
SELECT * FROM ga_sessions WHERE id = $1;

-- Conditional spend: the WHERE clause is the concurrency guard. Zero rows means
-- another request already consumed this token, which the use case treats as
-- reuse rather than as a lost race.
-- name: SpendSession :one
UPDATE ga_sessions
SET used_at = now()
WHERE refresh_hash = $1 AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteSessionFamily :execrows
DELETE FROM ga_sessions WHERE family_id = $1;

-- name: DeleteSession :execrows
DELETE FROM ga_sessions WHERE id = $1;

-- name: DeleteUserSessions :execrows
DELETE FROM ga_sessions WHERE user_id = $1;

-- name: ListLiveUserSessions :many
SELECT * FROM ga_sessions
WHERE user_id = $1 AND used_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: DeleteExpiredSessions :execrows
DELETE FROM ga_sessions WHERE expires_at < now();
