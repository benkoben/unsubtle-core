// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: active_subscriptions.sql

package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createActiveSubscription = `-- name: CreateActiveSubscription :one
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
RETURNING id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
`

type CreateActiveSubscriptionParams struct {
	SubscriptionID   uuid.UUID    `json:"subscription_id"`
	UserID           uuid.UUID    `json:"user_id"`
	CardID           uuid.UUID    `json:"card_id"`
	UpdatedAt        time.Time    `json:"updated_at"`
	BillingFrequency string       `json:"billing_frequency"`
	AutoRenewEnabled sql.NullBool `json:"auto_renew_enabled"`
}

func (q *Queries) CreateActiveSubscription(ctx context.Context, arg CreateActiveSubscriptionParams) (ActiveSubscription, error) {
	row := q.db.QueryRowContext(ctx, createActiveSubscription,
		arg.SubscriptionID,
		arg.UserID,
		arg.CardID,
		arg.UpdatedAt,
		arg.BillingFrequency,
		arg.AutoRenewEnabled,
	)
	var i ActiveSubscription
	err := row.Scan(
		&i.ID,
		&i.SubscriptionID,
		&i.UserID,
		&i.CardID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.BillingFrequency,
		&i.AutoRenewEnabled,
	)
	return i, err
}

const deleteActiveSubscription = `-- name: DeleteActiveSubscription :execresult
DELETE FROM active_subscriptions
WHERE id = $1
`

func (q *Queries) DeleteActiveSubscription(ctx context.Context, id uuid.UUID) (sql.Result, error) {
	return q.db.ExecContext(ctx, deleteActiveSubscription, id)
}

const disableAutoRenew = `-- name: DisableAutoRenew :exec
UPDATE active_subscriptions
SET auto_renew_enabled = false
WHERE id = $1
`

func (q *Queries) DisableAutoRenew(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, disableAutoRenew, id)
	return err
}

const enableAutoRenew = `-- name: EnableAutoRenew :exec
UPDATE active_subscriptions
SET auto_renew_enabled = true
WHERE id = $1
`

func (q *Queries) EnableAutoRenew(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, enableAutoRenew, id)
	return err
}

const getActiveSubscriptionById = `-- name: GetActiveSubscriptionById :one
SELECT id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
FROM active_subscriptions
WHERE id = $1
`

func (q *Queries) GetActiveSubscriptionById(ctx context.Context, id uuid.UUID) (ActiveSubscription, error) {
	row := q.db.QueryRowContext(ctx, getActiveSubscriptionById, id)
	var i ActiveSubscription
	err := row.Scan(
		&i.ID,
		&i.SubscriptionID,
		&i.UserID,
		&i.CardID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.BillingFrequency,
		&i.AutoRenewEnabled,
	)
	return i, err
}

const getActiveSubscriptionByUserIdAndSubId = `-- name: GetActiveSubscriptionByUserIdAndSubId :one
SELECT id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
FROM active_subscriptions
WHERE user_id = $1 AND subscription_id = $2
`

type GetActiveSubscriptionByUserIdAndSubIdParams struct {
	UserID         uuid.UUID `json:"user_id"`
	SubscriptionID uuid.UUID `json:"subscription_id"`
}

func (q *Queries) GetActiveSubscriptionByUserIdAndSubId(ctx context.Context, arg GetActiveSubscriptionByUserIdAndSubIdParams) (ActiveSubscription, error) {
	row := q.db.QueryRowContext(ctx, getActiveSubscriptionByUserIdAndSubId, arg.UserID, arg.SubscriptionID)
	var i ActiveSubscription
	err := row.Scan(
		&i.ID,
		&i.SubscriptionID,
		&i.UserID,
		&i.CardID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.BillingFrequency,
		&i.AutoRenewEnabled,
	)
	return i, err
}

const listActiveSubscriptionByUserId = `-- name: ListActiveSubscriptionByUserId :many
SELECT id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
FROM active_subscriptions
WHERE user_id = $1
`

func (q *Queries) ListActiveSubscriptionByUserId(ctx context.Context, userID uuid.UUID) ([]ActiveSubscription, error) {
	rows, err := q.db.QueryContext(ctx, listActiveSubscriptionByUserId, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ActiveSubscription
	for rows.Next() {
		var i ActiveSubscription
		if err := rows.Scan(
			&i.ID,
			&i.SubscriptionID,
			&i.UserID,
			&i.CardID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.BillingFrequency,
			&i.AutoRenewEnabled,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listActiveSubscriptions = `-- name: ListActiveSubscriptions :many
SELECT id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
FROM active_subscriptions
ORDER BY created_at ASC
`

func (q *Queries) ListActiveSubscriptions(ctx context.Context) ([]ActiveSubscription, error) {
	rows, err := q.db.QueryContext(ctx, listActiveSubscriptions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ActiveSubscription
	for rows.Next() {
		var i ActiveSubscription
		if err := rows.Scan(
			&i.ID,
			&i.SubscriptionID,
			&i.UserID,
			&i.CardID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.BillingFrequency,
			&i.AutoRenewEnabled,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const resetActiveSubscriptions = `-- name: ResetActiveSubscriptions :many
DELETE
FROM active_subscriptions
RETURNING id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
`

func (q *Queries) ResetActiveSubscriptions(ctx context.Context) ([]ActiveSubscription, error) {
	rows, err := q.db.QueryContext(ctx, resetActiveSubscriptions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ActiveSubscription
	for rows.Next() {
		var i ActiveSubscription
		if err := rows.Scan(
			&i.ID,
			&i.SubscriptionID,
			&i.UserID,
			&i.CardID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.BillingFrequency,
			&i.AutoRenewEnabled,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateActiveSubscription = `-- name: UpdateActiveSubscription :one
UPDATE active_subscriptions
SET billing_frequency  = $2,
    auto_renew_enabled = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING id, subscription_id, user_id, card_id, created_at, updated_at, billing_frequency, auto_renew_enabled
`

type UpdateActiveSubscriptionParams struct {
	ID               uuid.UUID    `json:"id"`
	BillingFrequency string       `json:"billing_frequency"`
	AutoRenewEnabled sql.NullBool `json:"auto_renew_enabled"`
}

func (q *Queries) UpdateActiveSubscription(ctx context.Context, arg UpdateActiveSubscriptionParams) (ActiveSubscription, error) {
	row := q.db.QueryRowContext(ctx, updateActiveSubscription, arg.ID, arg.BillingFrequency, arg.AutoRenewEnabled)
	var i ActiveSubscription
	err := row.Scan(
		&i.ID,
		&i.SubscriptionID,
		&i.UserID,
		&i.CardID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.BillingFrequency,
		&i.AutoRenewEnabled,
	)
	return i, err
}
