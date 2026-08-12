-- name: InsertAuditEntry :exec
INSERT INTO ga_audit_log (actor, action, target_user_id, ip, meta)
VALUES (
    sqlc.arg('actor'),
    sqlc.arg('action'),
    sqlc.narg('target_user_id'),
    sqlc.narg('ip'),
    sqlc.arg('meta')
);

-- name: ListAuditEntries :many
SELECT * FROM ga_audit_log
WHERE (sqlc.narg('target_user_id')::uuid IS NULL OR target_user_id = sqlc.narg('target_user_id')::uuid)
  AND (sqlc.narg('action')::text IS NULL OR action = sqlc.narg('action')::text)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('lim') OFFSET sqlc.arg('off');

-- name: DeleteAuditEntriesBefore :execrows
DELETE FROM ga_audit_log WHERE created_at < $1;

-- Keeps only the newest N entries. The subquery is ordered the same way
-- ListAuditEntries is, so "newest" means the same thing in both.
-- name: DeleteAuditEntriesBeyond :execrows
DELETE FROM ga_audit_log
WHERE id NOT IN (
    SELECT id FROM ga_audit_log ORDER BY created_at DESC, id DESC LIMIT $1
);
