-- name: InsertOutboxEvent :exec
INSERT INTO ga_outbox (event, payload) VALUES ($1, $2);

-- Claims due events by leasing them: the row is pushed into the future so no
-- other worker sees it, and the statement commits immediately.
--
-- Holding FOR UPDATE across delivery would instead keep a transaction open for
-- the length of an HTTP call to someone else's server. The lease also self-heals:
-- if a worker dies mid-delivery, the row simply becomes due again.
--
-- SKIP LOCKED covers the instant two workers claim at once; ordering by
-- seq means a receiver sees changes in the order they happened; created_at
-- ties when two changes land in the same clock tick.
-- name: ClaimDueOutboxEvents :many
UPDATE ga_outbox
SET next_attempt_at = now() + make_interval(secs => sqlc.arg('lease_seconds')::int)
WHERE id IN (
    SELECT id FROM ga_outbox
    WHERE delivered_at IS NULL
      AND failed_at IS NULL
      AND next_attempt_at <= now()
    ORDER BY seq
    LIMIT sqlc.arg('lim')
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: MarkOutboxDelivered :exec
UPDATE ga_outbox
SET delivered_at = now(), attempts = attempts + 1, last_error = NULL
WHERE id = $1;

-- Records a failure and schedules the retry. Giving up is the caller's decision,
-- passed in as failed, so the backoff policy stays in Go rather than in SQL.
-- name: MarkOutboxFailed :exec
UPDATE ga_outbox
SET attempts        = attempts + 1,
    last_error      = sqlc.arg('last_error'),
    next_attempt_at = sqlc.arg('next_attempt_at'),
    failed_at       = CASE WHEN sqlc.arg('give_up')::boolean THEN now() ELSE NULL END
WHERE id = sqlc.arg('id');

-- name: DeleteOutboxEventsBefore :execrows
DELETE FROM ga_outbox
WHERE created_at < $1 AND (delivered_at IS NOT NULL OR failed_at IS NOT NULL);

-- name: CountPendingOutboxEvents :one
SELECT count(*) FROM ga_outbox WHERE delivered_at IS NULL AND failed_at IS NULL;
