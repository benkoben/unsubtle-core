// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0

package database

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type ActiveSubscription struct {
	SubscriptionID   uuid.UUID    `json:"subscription_id"`
	UserID           uuid.UUID    `json:"user_id"`
	CardID           uuid.UUID    `json:"card_id"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	BillingFrequency string       `json:"billing_frequency"`
	AutoRenewEnabled sql.NullBool `json:"auto_renew_enabled"`
}

type ActiveTrail struct {
	ID             uuid.UUID `json:"id"`
	SubscriptionID uuid.UUID `json:"subscription_id"`
	UserID         uuid.UUID `json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Card struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Owner     uuid.UUID `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Category struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   uuid.UUID `json:"created_by"`
}

type Subscription struct {
	ID             uuid.UUID      `json:"id"`
	Name           string         `json:"name"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	MonthlyCostSek int32          `json:"monthly_cost_sek"`
	UnsubscribeUrl sql.NullString `json:"unsubscribe_url"`
	CategoryID     uuid.UUID      `json:"category_id"`
	CreatedBy      uuid.UUID      `json:"created_by"`
}

type User struct {
	ID             uuid.UUID `json:"id"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"hashed_password,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
