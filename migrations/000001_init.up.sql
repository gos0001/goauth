-- Initial migration. Add your tables here, then run:
--   make migrate-up   (apply to the database)
--   make sqlc         (regenerate typed query code)

CREATE TABLE IF NOT EXISTS schema_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
