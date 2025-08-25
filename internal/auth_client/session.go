package auth_client

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const SessionContextKey = "session"

// Session is used to pass session details around. It does not contain any sensitive information.
type Session struct {
	AccessToken  *string    `json:"access_token,omitempty"`
	RefreshToken *string    `json:"refresh_token,omitempty"`
	Email        *string    `json:"email,omitempty"`
	UserId       *uuid.UUID `json:"user_id,omitempty"`
}

// GetSessionFromContext retrieves a session from a context. The SessionContextKey is not found an error is returned.
func GetSessionFromContext(ctx context.Context) (*Session, error) {
	session, ok := ctx.Value(SessionContextKey).(*Session)
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func SetSessionToContext(ctx context.Context, session *Session) context.Context {
	ctx = context.WithValue(ctx, SessionContextKey, session)
	return ctx
}

// setEmailFromToken parses a JWT token and adds the email value to Session if found.
// if no email claim is found in the token an error is returned.
func (s *Session) setEmailFromToken(token *jwt.Token) error {
	email, ok := token.Claims.(jwt.MapClaims)["email"].(string)
	if !ok {
		return errors.New("email not found in token claims")
	}
	s.Email = &email
	return nil
}

// setUserIdFromToken parses a JWT token and adds the email value to Session if found.
// if no subject claim is found in the token an error is returned.
func (s *Session) setUserIdFromToken(token *jwt.Token) error {
	userStr, ok := token.Claims.(jwt.MapClaims)["sub"].(string)
	if !ok {
		return errors.New("subject not found in token claims")
	}

	userId, err := uuid.Parse(userStr)
	if err != nil {
		return err
	}
	s.UserId = &userId
	return nil
}

func newSessionFromToken(token *jwt.Token) (*Session, error) {
	var s Session
	if err := s.setEmailFromToken(token); err != nil {
		return nil, err
	}
	return &s, nil
}
