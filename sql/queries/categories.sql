-- name: CreateCategory :one
INSERT INTO categories (created_at, updated_at, name, description, created_by)
VALUES (
NOW(),
NOW(),
$1,
$2,
$3
)
RETURNING *;

-- name: ListCategories :many
SELECT * FROM categories
ORDER BY name ASC;

-- name: ListCategoriesForUserId :many
SELECT * FROM categories
WHERE created_by = $1
ORDER BY name ASC;

-- name: GetCategory :one
SELECT * FROM categories
WHERE id = $1;

-- name: CheckExistingCategory :one
SELECT * FROM categories
WHERE name = $1 AND created_by = $2;

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
