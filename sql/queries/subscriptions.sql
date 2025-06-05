-- name: CreateSubscription :one
INSERT INTO subscriptions (created_at, updated_at, name, monthly_cost, currency, unsubscribe_url, description, category_id, created_by)
VALUES (
NOW(),
NOW(),
$1,
$2,
$3,
$4,
$5,
$6,
$7
)
RETURNING *;

-- name: ListSubscriptions :many
SELECT * FROM subscriptions
ORDER BY name ASC;

-- name: ListSubscriptionsForUserId :many
SELECT * FROM subscriptions
WHERE created_by = $1
ORDER BY name ASC;

-- name: GetSubscription :one
SELECT * FROM subscriptions
WHERE id = $1;

-- name: GetSubscriptionByNameAndCreator :one
SELECT * FROM subscriptions
WHERE created_by = $1 AND name = $2;

-- name: DeleteSubscription :execresult
DELETE FROM subscriptions
WHERE id = $1;

-- name: ResetSubscriptions :many
DELETE FROM subscriptions
RETURNING *;

-- name: UpdateSubscription :one
UPDATE subscriptions
SET name = $2, monthly_cost = $3, currency=$4, unsubscribe_url=$5, description=$6, category_id=$7, updated_at=NOW()
WHERE id = $1
RETURNING *;
