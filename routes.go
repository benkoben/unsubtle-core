package main

import (
	"github.com/benkoben/unsubtle-core/internal/database"
	"net/http"
)

// addRoutes accepts a pointer to a mux together all possible dependencies that we can think of using when defining the routes
func addRoutes(
	mux *http.ServeMux,
	config *Config,
	dbStore *database.Queries,
	// --- More different stores can be added below if necessary
) {
	mux.Handle("GET /", handleHelloWorld(config))
}
