package main

import (
	"github.com/benkoben/unsubtle-core/internal/database"
	"net/http"
	"path/filepath"
)

// addRoutes accepts a pointer to a mux together all possible dependencies that we can think of using when defining the routes
func addRoutes(
	mux *http.ServeMux,
	config *Config,
	dbStore *database.Queries,
	// --- More different stores can be added below if necessary
) {
	// Serve static HTML files
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("frontend", "index.html"))
	}))

	mux.Handle("GET /dashboard", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("frontend", "dashboard.html"))
	}))

	// API requests are defined below
	//
	// -- Authentication handlers
	mux.Handle("POST /login", handleLoginForm(dbStore, config))
	mux.Handle("POST /register", handleRegisterForm(dbStore))
	mux.Handle("POST /refresh", authenticate(handleRefresh(dbStore, config), config.JWTSecret))
	mux.Handle("POST /revoke", authenticate(handleRevoke(dbStore, config), config.JWTSecret))

	// -- Users
	// TODO: Authorization (These handlers should only be available to admin users)
	mux.Handle("GET /api/users", authenticate(handleListUsers(dbStore), config.JWTSecret))
	mux.Handle("GET /api/users/{id}", authenticate(handleGetUser(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/users/{id}", authenticate(handleUpdateUser(dbStore), config.JWTSecret))
	mux.Handle("DELETE /api/users/{id}", authenticate(handleDeleteUser(dbStore), config.JWTSecret))

	// -- Categories
	mux.Handle("POST /api/categories", authenticate(handleCreateCategory(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/categories/{id}", authenticate(handleUpdateCategory(dbStore), config.JWTSecret))
	mux.Handle("GET /api/categories", authenticate(handleListCategory(dbStore), config.JWTSecret))
	mux.Handle("GET /api/categories/{id}", authenticate(handleGetCategory(dbStore), config.JWTSecret))
	mux.Handle("DELETE /api/categories/{id}", authenticate(handleDeleteCategory(dbStore), config.JWTSecret))

	// -- Subscriptions
	mux.Handle("POST /api/subscriptions", authenticate(handleCreateSubscription(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/subscriptions/{id}", authenticate(handleUpdateSubscription(dbStore), config.JWTSecret))
	mux.Handle("GET /api/subscriptions", authenticate(handleListSubscription(dbStore), config.JWTSecret))
	mux.Handle("GET /api/subscriptions/{id}", authenticate(handleGetSubscription(dbStore), config.JWTSecret))
	mux.Handle("DELETE /api/subscriptions/{id}", authenticate(handleDeleteSubscription(dbStore), config.JWTSecret))

	// -- Cards
	mux.Handle("POST /api/cards", authenticate(handleCreateCard(dbStore), config.JWTSecret))
	mux.Handle("GET /api/cards/{id}", authenticate(handleGetCard(dbStore), config.JWTSecret))
	mux.Handle("GET /api/cards", authenticate(handleListCards(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/cards/{id}", authenticate(handleUpdateCard(dbStore), config.JWTSecret))
	mux.Handle("DELETE /api/cards/{id}", authenticate(handleDeleteCard(dbStore), config.JWTSecret))

	// -- ActiveSubscriptions
	mux.Handle("GET /api/activesubscriptions/{id}", authenticate(handleGetActiveSubscription(dbStore), config.JWTSecret))
	mux.Handle("GET /api/activesubscriptions", authenticate(handleListActiveSubscription(dbStore), config.JWTSecret))
	mux.Handle("PUT /api/activesubscriptions/{id}", authenticate(handleUpdateActiveSubscription(dbStore), config.JWTSecret))

	// -- ActiveTrails
}
