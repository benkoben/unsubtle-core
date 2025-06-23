package main

import (
	"encoding/json"
	"fmt"
	"net/http"
    "io"
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
