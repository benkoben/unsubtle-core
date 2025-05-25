package main

import (
	"encoding/json"
	"log"
	"net/http"
	"github.com/benkoben/unsubtle-core/internal/database"
)

type response struct {
	Content any `json:"content,omitempty"`
	Status  int    `json:"status"`
	Error   string `json:"error,omitempty"`
}

func (res *response) respond(w http.ResponseWriter) {
	
	if res.Content != nil {
		body, err := json.Marshal(res.Content)
		if err != nil {
			log.Printf("%s: %s", MarhalResponseBodyError, err)
		}
		res.Content = string(body)
	}

	if err := encode(w, res.Status, res); err != nil {
		log.Printf("%w: %w", ResponseFailureError, err)
	}
}

