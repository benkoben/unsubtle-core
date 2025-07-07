package main

import (
	"fmt"
	"net/http"
)

type response struct {
	Content any     `json:"content,omitempty"`
	Status  int     `json:"status"`
	Error   *string `json:"error,omitempty"`
}

func (res *response) respond(w http.ResponseWriter) error {
	if err := encode(w, res.Status, res); err != nil {
		return fmt.Errorf("%w: %w", ResponseFailureError, err)
	}
	return nil
}
