package main

import (
	"encoding/json"
	"fmt"
	"github.com/benkoben/unsubtle-core/internal/auth"
	"github.com/benkoben/unsubtle-core/internal/database"
	"log"
	"math"
	"net/http"

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

		userRequestData := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&userRequestData); err != nil {
			log.Printf("error decoding json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Validate the email
		if ok := validEmail(userRequestData.Email); !ok {
			// TODO: Write a response helper that reports errors back to the client
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte("invalid email"))
			if err != nil {
				log.Printf("error writing response: %v", err)
			}
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(userRequestData.Password, minEntropy); err != nil {
			// TODO: Write a response helper that reports errors back to the client
			w.WriteHeader(http.StatusBadRequest)
			_, err := w.Write([]byte(fmt.Sprintf("invalid password: %v", err)))
			if err != nil {
				log.Printf("error writing response: %v", err)
			}
		}

		// Hash the password
		hash, err := auth.CreateHash(userRequestData.Password)
		if err != nil {
			log.Printf("error hashing password: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Save the user to the database
		createUserParams := database.CreateUserParams{
			Email:          userRequestData.Email,
			HashedPassword: hash,
		}

		if _, err := query.CreateUser(r.Context(), createUserParams); err != nil {
			log.Printf("error creating user: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})
}

// --- Card handlers

// --- Category handlers

// --- Subscription handlers

// --- Active subscription handlers

// --- Active trails handlers
