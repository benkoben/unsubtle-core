-- name: CreateCard :one
INSERT INTO cards (created_at, updated_at, name, owner, expires_at)
VALUES (NOW(),
        NOW(),
        $1,
        $2,
        $3)
RETURNING id, created_at, updated_at, name, owner, expires_at;

-- name: ResetCards :many
DELETE
FROM cards
RETURNING *;

-- name: ListCards :many
SELECT *
FROM cards
ORDER BY created_at ASC;

-- name: ListCardsForOwner :many
SELECT *
FROM cards
WHERE owner = $1;

-- name: GetCard :one
SELECT *
FROM cards
WHERE id = $1;

-- name: GetCardByName :one
SELECT *
FROM cards
WHERE name = $1 AND owner = $2;

-- name: UpdateCard :one
UPDATE cards
SET name       = $2,
    expires_at = $3,
    updated_at = $4
WHERE id = $1
RETURNING *;

-- name: DeleteCard :execresult
DELETE
FROM cards
WHERE id = $1;
