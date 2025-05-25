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
	// Frontend request are defined below
	mux.Handle("GET /", handleHelloWorld(config))

	// API requests are defined below
	//
	// -- Authentication handlers
	mux.Handle("POST /api/login", handleLogin(dbStore, config))
	mux.Handle("POST /api/refresh", authenticate(handleRefresh(dbStore, config), config.JWTSecret))
	mux.Handle("POST /api/revoke", authenticate(handleRevoke(dbStore, config), config.JWTSecret))

	// -- Users
	mux.Handle("POST /api/users", handleCreateUser(dbStore))
	// --- Authenticated user handlers
	mux.Handle("GET /api/users", authenticate(handleListUsers(dbStore), config.JWTSecret))
	mux.Handle("GET /api/users/{id}", authenticate(handleGetUser(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/users/{id}", authenticate(handleUpdateUser(dbStore), config.JWTSecret))
	mux.Handle("DELETE /api/users/{id}", authenticate(handleDeleteUser(dbStore), config.JWTSecret))

	// -- Categories

	// -- Subscriptions

	// -- ActiveSubscriptions

	// -- ActiveTrails
}
