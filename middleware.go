package main

import (
	"net/http"

	"github.com/benkoben/unsubtle-core/internal/auth"
)

func authenticate(next http.Handler, jwtSecret string) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the bearer token from request header
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Validate the bearer token
		if _, err := auth.ValidateJWT(token, jwtSecret); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
