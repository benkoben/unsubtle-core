package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/benkoben/unsubtle-core/internal/auth"
	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/google/uuid"
	"github.com/wagslane/go-password-validator"

	_ "github.com/lib/pq"
)

const ()

var (
	minPasswordLength = 12
	// 26 lowercase letters
	// 26 uppercase letters
	// 10 digits
	// 5 replacement characters - !@$&*
	// 5 seperator characters - _-.,
	// 22 less common special characters - "#%'()+/:;<=>?[\]^{|}~
	minPasswordComplexity = 89 // Product of adding the above criteria
	passwordBase          = math.Pow(float64(minPasswordComplexity), float64(minPasswordLength))
	minEntropy            = math.Log2(passwordBase)
)

// dbQuerier is an interface that allows us to use dependency injection on handlers.
// It's purpose is to enable self-contained unit testing. While this wont allow us to test queries, it does allow us to test the logic defined within a handler.
type dbQuerier interface {
	// User interactions
	GetUserById(context.Context, uuid.UUID) (database.User, error)
	CreateUser(context.Context, database.CreateUserParams) (database.CreateUserRow, error)
	GetUserByEmail(ctx context.Context, email string) (database.User, error)
	DeleteUser(ctx context.Context, id uuid.UUID) (sql.Result, error)

	// RefreshToken interactions
	CreateRefreshToken(ctx context.Context, arg database.CreateRefreshTokenParams) (database.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, arg database.UpdateRefreshTokenParams) (database.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, userID uuid.UUID) (database.RefreshToken, error)
	GetRefreshToken(ctx context.Context, userId uuid.UUID) (database.RefreshToken, error)

	// Subscription interactions

	// Category interactions

	// Card interactions

	// ActiveTrails interactions

	// ActiveSubscriptions interactions
}

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

func handleHelloWorld(_ *Config) http.Handler {
	// This pattern gives each handler its own closure environment. You can do initialization work in this space, and the data will be available to the handlers when they are called.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := w.Write([]byte("Hello world"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Printf("%d bytes written\n", n)
		w.WriteHeader(http.StatusOK)
	})
}

// --- Authentication handlers
func handleRevoke(db dbQuerier, cfg *Config) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, err := auth.GetBearerToken(r.Header)
		if err != nil {
			// No bearer token found in headers
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		userId, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
		if err != nil {
			// Bearer token was found but is not valid
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		refreshToken, err := db.RevokeRefreshToken(r.Context(), userId)
		if err != nil {
			log.Printf("revoke refresh token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		if err := encode(w, r, http.StatusOK, refreshToken); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})
}

func handleRefresh(db dbQuerier, cfg *Config) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, err := auth.GetBearerToken(r.Header)
		if err != nil {
			// No bearer token found in headers
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		userId, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
		if err != nil {
			// Bearer token was found but is not valid
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		// Check if there exists a refresh token
		refreshToken, err := db.GetRefreshToken(r.Context(), userId)
		if err != nil {
			// Normally this is not possible but in rare cases where
			// an valid JWT is used but no refreshToken exists we need to handle this.
			if err == sql.ErrNoRows {
				// Bearer token was found but is not valid
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(http.StatusText(http.StatusForbidden)))
				return
			} else {
				// Should not happend under normal circumstances
				log.Printf("retrieve refresh token: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// validate if the existing refresh token is not revoked
		// if the token is revoked or expired
		if refreshToken.RevokedAt.Valid || refreshToken.ExpiresAt.Unix() < time.Now().Unix() {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		// Make JWT token, a token lives for 60 minutes.
		jwt, err := auth.MakeJWT(userId, cfg.JWTSecret, time.Minute*60)
		if err != nil {
			log.Printf("could not create jwt token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		if err := encode(w, r, http.StatusOK, map[string]string{"token": jwt}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})
}

func handleLogin(db dbQuerier, cfg *Config) http.Handler {
	res := response{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Retrieve credentials from body
		defer r.Body.Close()

		// Lookup user in database
		loginCredentials, err := decode[userRequestData](r.Body)
		if err != nil {
			log.Printf("invalid json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		registeredUser, err := db.GetUserByEmail(r.Context(), loginCredentials.Email)
		if err != nil {
			// TODO: This if error is ErrNoRows else internal error pattern is reused in quite a lot of different places
			if err == sql.ErrNoRows {
				// User does not exist in database
				res.Status = http.StatusForbidden
				res.Error = http.StatusText(http.StatusForbidden)
				if err := encode(w, r, res.Status, res); err != nil {
					log.Printf("could not encode response: %v", err)
				}
				return
			} else {
				// Unexpected error
				log.Printf("retrieving user by email: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// Validate password
		if ok := auth.IsValid(loginCredentials.Password, registeredUser.HashedPassword); !ok {
			res.Status = http.StatusForbidden
			res.Error = "invalid password"
			if err := encode(w, r, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}
			return
		}

		// Make JWT token, a token lives for 60 minutes.
		jwt, err := auth.MakeJWT(registeredUser.ID, cfg.JWTSecret, time.Minute*60)
		if err != nil {
			log.Printf("could not create jwt token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		// Check if we need to create a refresh token or not
		refreshToken, err := db.GetRefreshToken(r.Context(), registeredUser.ID)
		if err != nil {
			if err == sql.ErrNoRows {
				newTokenString, err := auth.MakeRefreshToken()
				if err != nil {
					log.Printf("could not create refresh token: %w", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
					return
				}
				refreshTokenOpts := database.CreateRefreshTokenParams{
					UserID:    registeredUser.ID,
					ExpiresAt: time.Now().Add(time.Hour * 1440), // 60 days
					Token:     newTokenString,
				}

				newToken, err := db.CreateRefreshToken(r.Context(), refreshTokenOpts)
				if err != nil {
					log.Printf("could not save refresh token to database: %w", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
					return
				}
				refreshToken = newToken
			} else {
				// Unexpected error
				log.Printf("retrieving refresh token: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// TODO: What if we login a user that has a revoked refreshToken? I believe that the current implementation allows successful logins 
		// while keeping revoked refresh tokens. Making it impossible for a user to refresh their bearer token.

		// Create response body
		responseBody := loginResponseData{
			Id:           registeredUser.ID,
			Email:        registeredUser.Email,
			CreatedAt:    registeredUser.CreatedAt,
			UpdatedAt:    registeredUser.UpdatedAt,
			Token:        jwt,
			RefreshToken: refreshToken.Token,
		}

		if err := encode(w, r, http.StatusOK, responseBody); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})

}

// --- User handlers
func handleCreateUser(query dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the email and password from the request body
		defer r.Body.Close()

		newUserData, err := decode[userRequestData](r.Body)
		if err != nil {
			log.Printf("error decoding json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate the email
		if ok := validEmail(newUserData.Email); !ok {
			res.Status = http.StatusBadRequest
			res.Error = "invalid email"
			if err := encode(w, r, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}
			return
		}

		// Check if the email is already registered
		existingUser, err := query.GetUserByEmail(r.Context(), newUserData.Email)
		if err != nil && err != sql.ErrNoRows {
			// If any error other than ErrNoRows is returned this means something unexpected happened.
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)

			if err := encode(w, r, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// If existingUser contains data, this means there already exists a database entry for the requested email
		if existingUser.Email != "" {
			res.Status = http.StatusConflict
			res.Error = "email is already registered"

			if err := encode(w, r, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write(fmt.Appendf([]byte{}, "invalid password: %v", err))
			if err != nil {
				log.Printf("error writing response: %v", err)
			}
			return
		}

		// Hash the password
		hash, err := auth.CreateHash(newUserData.Password)
		if err != nil {
			log.Printf("error hashing password: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Save the user to the database
		createUserParams := database.CreateUserParams{
			Email:          newUserData.Email,
			HashedPassword: hash,
		}

		dbResponse, err := query.CreateUser(r.Context(), createUserParams)
		statusCode := http.StatusCreated
		if err != nil {
			log.Printf("error creating user: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := encode(w, r, statusCode, dbResponse); err != nil {
			log.Printf("error encoding response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
}

func handleListUsers(query *database.Queries) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		users, err := query.ListUsers(r.Context())
		if err != nil {
			log.Printf("error listing users: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := encode(w, r, http.StatusOK, users); err != nil {
			log.Printf("error encoding response: %v", err)
			return
		}
	})
}

func handleGetUser(query dbQuerier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse id from URL path
		log.Println(r.PathValue("id"))
		log.Println(r.URL.String())
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
			return
		}

		user, err := query.GetUserById(r.Context(), id)

		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Sanitize output
		user.HashedPassword = ""

		if err := encode(w, r, http.StatusOK, user); err != nil {
			log.Printf("error encoding response: %v", err)
			return
		}
	})
}

func handleUpdateUser(query *database.Queries) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		log.Printf("user id %s update", id.String())

		newUserData, err := decode[userRequestData](r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Println(newUserData)

		if _, err := query.GetUserById(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("user not found"))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(fmt.Sprintf("invalid password: %v", err)))
			if err != nil {
				log.Printf("error writing response: %v", err)
			}
			return
		}

		// Hash password
		hashedPw, err := auth.CreateHash(newUserData.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("new hash calculated %s", hashedPw)

		params := database.UpdateUserParams{
			ID:             id,
			Email:          newUserData.Email,
			HashedPassword: hashedPw,
			UpdatedAt:      time.Now(),
		}

		updatedUser, err := query.UpdateUser(r.Context(), params)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := encode(w, r, http.StatusOK, updatedUser); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
}

func handleDeleteUser(query dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		if _, err := query.DeleteUser(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Error = "id not found"
				res.Status = http.StatusNotFound
			} else {
				res.Error = http.StatusText(http.StatusInternalServerError)
				res.Status = http.StatusInternalServerError
			}
			encode(w, r, res.Status, res)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

// --- Card handlers

// --- Category handlers

// --- Subscription handlers

// --- Active subscription handlers

// --- Active trails handlers
