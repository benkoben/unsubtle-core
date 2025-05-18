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
	mux.Handle("POST /api/refresh", handleRefresh(dbStore, config))
	mux.Handle("POST /api/revoke", handleRevoke(dbStore, config))

	// -- Users
	mux.Handle("POST /api/users", handleCreateUser(dbStore))
	mux.Handle("GET /api/users", handleListUsers(dbStore))
	mux.Handle("GET /api/users/{id}", handleGetUser(dbStore))
	mux.Handle("PUT /api/users/{id}", handleUpdateUser(dbStore))
	mux.Handle("DELETE /api/users/{id}", handleDeleteUser(dbStore))

	// -- Categories

	// -- Subscriptions

	// -- ActiveSubscriptions

	// -- ActiveTrails
}
