package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/benkoben/unsubtle-core/internal/auth"
	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/google/uuid"
	"github.com/lib/pq"
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

type userRequestData struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func handleHelloWorld(config *Config) http.Handler {
	// This pattern gives each handler its own closure environment. You can do initialization work in this space, and the data will be available to the handlers when they are called.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := w.Write([]byte(fmt.Sprintf("Hello World, I want to connect to database %s", config.Database.ConnectionString)))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Printf("%d bytes written\n", n)
		w.WriteHeader(http.StatusOK)
	})
}

// --- User handlers
func handleCreateUser(query *database.Queries) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the email and password from the request body
		defer r.Body.Close()

		newUserData, err := decode[userRequestData](w, r)
		if err != nil {
			log.Printf("error decoding json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate the email
		if ok := validEmail(newUserData.Email); !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("invalid email"))
			if err != nil {
				log.Printf("error writing response: %v", err)
			}
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(fmt.Sprintf("invalid password: %v", err)))
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
			pgErr, ok := err.(*pq.Error)
			if ok {
				if pgErr.Code == "23505" {
					// Row already exists. Return a StatusOK back to the client instead of StatusCreated
					statusCode = http.StatusOK
				}
			} else {
				log.Printf("error creating user: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
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

func handleGetUser(query *database.Queries) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
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

		newUserData, err := decode[userRequestData](w, r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

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
		}

		// Hash password
		hashedPw, err := auth.CreateHash(newUserData.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

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

func handleDeleteUser(query *database.Queries) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}
        
        if _, err := query.DeleteUser(r.Context(), id); err != nil {
            if err == sql.ErrNoRows {
                w.WriteHeader(http.StatusNotFound)
                return
            }
            w.WriteHeader(http.StatusInternalServerError)
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
