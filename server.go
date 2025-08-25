package main

import (
	auth "github.com/benkoben/unsubtle-core/internal/auth_client"
	"github.com/benkoben/unsubtle-core/internal/database"
	"net/http"
)

func NewServerHandler(
	config *Config,
	dbStore *database.Queries,
	authClient auth.Client,
) http.Handler {
	// Prepare the mux
	mux := http.NewServeMux()

	// Add routes to the mux, provide the necessary dependencies
	addRoutes(mux, config, dbStore, authClient)

	var handler http.Handler = mux
	// The NewServer constructor is responsible for all the top-level HTTP stuff that applies to all endpoints, like CORS, password middleware, and logging
	// TODO: Implement global middleware here
	// handler = logging.Middleware(logger, handler)
	// handler = checkAuthHeaders(handler)
	return handler
}
