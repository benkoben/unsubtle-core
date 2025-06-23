-- name: CreateActiveSubscription :one
INSERT INTO active_subscriptions (subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled)
VALUES (
        $1,
        $2,
        $3,
        NOW(),
        $4,
        $5,
        $6
    )
RETURNING *;

-- name: EnableAutoRenew :exec
UPDATE active_subscriptions
SET auto_renew_enabled = true
WHERE id = $1;

-- name: DisableAutoRenew :exec
UPDATE active_subscriptions
SET auto_renew_enabled = false
WHERE id = $1;

-- name: ResetActiveSubscriptions :many
DELETE
FROM active_subscriptions
RETURNING *;

-- name: ListActiveSubscriptions :many
SELECT *
FROM active_subscriptions
ORDER BY created_at ASC;

-- name: ListActiveSubscriptionByUserId :many
SELECT *
FROM active_subscriptions
WHERE user_id = $1;

-- name: GetActiveSubscriptionById :one
SELECT *
FROM active_subscriptions
WHERE id = $1;

-- name: UpdateActiveSubscription :one
UPDATE active_subscriptions
SET billing_frequency  = $2,
    auto_renew_enabled = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING *;
