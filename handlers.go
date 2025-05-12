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
	_ "github.com/lib/pq"
	"github.com/wagslane/go-password-validator"
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
