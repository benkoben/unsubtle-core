package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/benkoben/unsubtle-core/internal/password"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"io"
	"log"
	"net/http"
	"net/mail"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func encode[T any](w http.ResponseWriter, status int, v T) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

func decode[T any](r io.Reader) (T, error) {
	var v T
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		return v, fmt.Errorf("decoding JSON: %w", err)
	}
	return v, nil
}

func toPtr[T any](v T) *T {
	return &v
}

func createUser(ctx context.Context, db dbQuerier, userData userRequestData) *response {
	var res response
	// Validate the email
	if ok := validEmail(userData.Email); !ok {
		res.Status = http.StatusBadRequest
		res.Error = toPtr("invalid email")
		return &res
	}

	// Check if the email is already registered
	existingUser, err := db.GetUserByEmail(ctx, userData.Email)
	if err != nil && err != sql.ErrNoRows {
		// If any error other than ErrNoRows is returned this means something unexpected happened.
		res.Status = http.StatusInternalServerError
		res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
		return &res
	}

	// If existingUser contains data, this means there already exists a database entry for the requested email
	if existingUser.Email != "" {
		res.Status = http.StatusConflict
		res.Error = toPtr("email is already registered")
		return &res
	}

	// Validate the password criteria
	if err := passwordvalidator.Validate(userData.Password, minEntropy); err != nil {
		res.Status = http.StatusBadRequest
		res.Error = toPtr(fmt.Sprintf("invalid password: %v", err))
		return &res
	}

	// Hash the password
	hash, err := password.CreateHash(userData.Password)
	if err != nil {
		log.Printf("error hashing password: %v", err)
		res.Status = http.StatusInternalServerError
		res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
		return &res
	}

	// Save the user to the database
	createUserParams := database.CreateUserParams{
		Email:          userData.Email,
		HashedPassword: hash,
	}

	dbResponse, err := db.CreateUser(ctx, createUserParams)
	if err != nil {
		log.Printf("error creating user: %v", err)
		res.Status = http.StatusInternalServerError
		res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
		return &res
	}

	res.Status = http.StatusCreated
	res.Content = dbResponse
	return &res
}
