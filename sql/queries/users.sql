-- name: CreateUser :one
INSERT INTO users (created_at, updated_at, email, hashed_password)
VALUES (
NOW(),
NOW(),
$1,
$2
)
RETURNING id, created_at, updated_at, email;

-- name: ResetUsers :many
DELETE FROM users
RETURNING *;

-- name: ListUsers :many
SELECT id, email, created_at, updated_at FROM users
ORDER BY created_at ASC;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1;

-- name: UpdateUser :one
UPDATE users
SET email = $2, hashed_password = $3
WHERE id = $1
RETURNING *;