package supabase

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

type Session struct {
	AccessToken  *string    `json:"access_token"`
	RefreshToken *string    `json:"refresh_token"`
	Email        *string    `json:"email"`
	ExpiresAt    *int64     `json:"expires_at"`
	UserId       *uuid.UUID `json:"user_id"`
}

func GetSessionFromContext(ctx context.Context) (*Session, error) {
	session, ok := ctx.Value(SessionContextKey).(*Session)
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}
