package main

import (
	"database/sql"
	"github.com/google/uuid"
	"time"
)

// -- Data that is expected by various requests
type userRequestData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponseData struct {
	Id           uuid.UUID `json:"id"`
	Email        string    `json:"email,omitempty"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type subscriptionRequest struct {
	Name           string         `json:"name"`
	MonthlyCost    int32          `json:"monthly_cost"`
	Currency       string         `json:"currency"`
	UnsubscribeUrl sql.NullString `json:"unsubscribe_url,omitempty"`
	Description    sql.NullString `json:"description,omitempty"`
	CategoryId     uuid.NullUUID  `json:"category_id,omitempty"`
}

type cardRequest struct {
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type activeSubscriptionUpdateRequest struct {
	BillingFrequency string `json:"billing_frequency"`
	AutoRenewEnabled *bool  `json:"auto_renew_enabled"`
}

type activeSubscriptionRequest struct {
	SubscriptionID   uuid.UUID    `json:"subscription_id"`
	CardID           uuid.UUID    `json:"card_id"`
	BillingFrequency string       `json:"billing_frequency"`
	AutoRenewEnabled sql.NullBool `json:"auto_renew_enabled"`
}
