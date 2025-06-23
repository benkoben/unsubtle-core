-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, created_at, updated_at, token, expires_at, revoked_at)
VALUES (
$1,
NOW(),
NOW(),
$2,
$3,
$4
)
RETURNING *;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE user_id = $1
RETURNING *;

-- name: UpdateRefreshToken :one
UPDATE refresh_tokens
SET expires_at = $2, updated_at = NOW()
WHERE user_id = $1
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND revoked_at is NULL;
