-- name: CreateCategory :one
INSERT INTO categories (created_at, updated_at, name)
VALUES (
NOW(),
NOW(),
$1
)
RETURNING *;

-- name: ListCategories :many
SELECT * FROM categories
ORDER BY name ASC;

-- name: GetCategory :one
SELECT * FROM categories
WHERE id = $1;

-- name: DeleteCategory :execresult
DELETE FROM categories
WHERE id = $1;

-- name: ResetCategories :many
DELETE FROM categories
RETURNING *;

-- name: UpdateCategory :one
UPDATE categories
SET name = $2, description = $3, updated_at=NOW()
WHERE id = $1
RETURNING *;
