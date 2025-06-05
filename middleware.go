package main

import (
	"context"
	"net/http"

	"github.com/benkoben/unsubtle-core/internal/auth"
	"github.com/google/uuid"
)

// Packages should define keys as an unexported type to avoid collisions.
type authenticatedUserId string

const userIdCtxKey authenticatedUserId = "userId"

// Use setters and getters for extra type safety of context values
func WithUserId(ctx context.Context, userId uuid.UUID) context.Context {
	return context.WithValue(ctx, userIdCtxKey, userId)
}

func GetUserId(ctx context.Context) *uuid.UUID {
  userId, ok := ctx.Value(userIdCtxKey).(*uuid.UUID)
  if !ok {
    // Log this issue
    return nil
  }
  return userId
}

func authenticate(next http.Handler, jwtSecret string) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the bearer token from request header
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Validate the bearer token
		userId, err := auth.ValidateJWT(token, jwtSecret)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
				
		next.ServeHTTP(w, r.WithContext(WithUserId(r.Context(), userId)))
	})
}
