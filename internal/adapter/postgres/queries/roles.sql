-- Role CRUD and the user-count check that blocks deleting a role still in
-- use. ga_users.role foreign-keys into ga_roles with no CASCADE, so the
-- database would refuse the delete anyway — this count is what turns that
-- refusal into ErrRoleInUse instead of a raw constraint error.

-- name: CreateRole :one
INSERT INTO ga_roles (name, rank, is_system)
VALUES (sqlc.arg('name'), sqlc.arg('rank'), sqlc.arg('is_system'))
RETURNING *;

-- name: GetRole :one
SELECT * FROM ga_roles WHERE name = $1;

-- name: ListRoles :many
SELECT * FROM ga_roles ORDER BY rank DESC;

-- name: UpdateRole :one
UPDATE ga_roles
SET rank      = COALESCE(sqlc.narg('rank'), rank),
    is_system = COALESCE(sqlc.narg('is_system'), is_system)
WHERE name = sqlc.arg('name')
RETURNING *;

-- name: DeleteRole :exec
DELETE FROM ga_roles WHERE name = $1;

-- name: CountUsersWithRole :one
SELECT count(*) FROM ga_users WHERE role = $1;

-- Permissions are replaced wholesale: the use case validates the full set
-- and writes it in one transaction, so there is no partial grant state.
-- name: DeleteRolePermissions :exec
DELETE FROM ga_role_permissions WHERE role = $1;

-- name: AddRolePermission :exec
INSERT INTO ga_role_permissions (role, permission)
VALUES (sqlc.arg('role'), sqlc.arg('permission'))
ON CONFLICT DO NOTHING;

-- name: ListRolePermissions :many
SELECT permission FROM ga_role_permissions WHERE role = $1 ORDER BY permission;

-- Roles with their permissions in one round trip, for the middleware's
-- actor lookup: given a user id, everything needed to authorise them.
-- name: GetUserRole :one
SELECT r.name, r.rank, r.is_system
FROM ga_roles r
JOIN ga_users u ON u.role = r.name
WHERE u.id = $1 AND u.status = 'active';

-- name: GetUserRolePermissions :many
SELECT p.permission
FROM ga_role_permissions p
JOIN ga_users u ON u.role = p.role
WHERE u.id = $1;

-- Seeding: insert only what is missing, never overwrite a rank or a
-- permission an operator changed at runtime. The database is the truth;
-- the seed only draws the floor.
-- name: SeedRole :one
INSERT INTO ga_roles (name, rank, is_system)
VALUES (sqlc.arg('name'), sqlc.arg('rank'), sqlc.arg('is_system'))
ON CONFLICT (name) DO NOTHING
RETURNING *;

-- name: SeedRolePermission :exec
INSERT INTO ga_role_permissions (role, permission)
VALUES (sqlc.arg('role'), sqlc.arg('permission'))
ON CONFLICT DO NOTHING;
