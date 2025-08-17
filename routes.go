package main

import (
	"github.com/benkoben/unsubtle-core/frontend"
	"github.com/benkoben/unsubtle-core/internal/database"
	"net/http"
)

// addRoutes accepts a pointer to a mux together all possible dependencies that we can think of using when defining the routes
func addRoutes(
	mux *http.ServeMux,
	config *Config,
	dbStore *database.Queries,
	authClient AuthClient,
	// --- More different stores can be added below if necessary
) {
	// Serve static HTML files
	mux.Handle("GET /", frontend.HandleIndex())
	mux.Handle("GET /dashboard", frontend.HandleDashboard())
	mux.Handle("GET /static/", frontend.HandleStatic())

	// API requests are defined below
	//
	// -- Authentication handlers
	mux.Handle("POST /login", handleLoginForm(authClient))
	mux.Handle("POST /register", handleRegisterForm(dbStore))
	mux.Handle("POST /token", handleTokenRequest(authClient))

	// -- Users
	// TODO: Authorization (These handlers should only be available to admin users)
	// mux.Handle("GET /api/token", handleLoginToken(config)
	mux.Handle("GET /api/users", authClient.ValidateTokenFromHandler(handleListUsers(dbStore)))
	mux.Handle("GET /api/users/{id}", authClient.ValidateTokenFromHandler(handleGetUser(dbStore)))
	mux.Handle("PUT /api/users/{id}", authClient.ValidateTokenFromHandler(handleUpdateUser(dbStore)))
	mux.Handle("DELETE /api/users/{id}", authClient.ValidateTokenFromHandler(handleDeleteUser(dbStore)))

	// -- Categories
	mux.Handle("POST /api/categories", authClient.ValidateTokenFromHandler(handleCreateCategory(dbStore)))
	mux.Handle("PUT /api/categories/{id}", authClient.ValidateTokenFromHandler(handleUpdateCategory(dbStore)))
	mux.Handle("GET /api/categories", authClient.ValidateTokenFromHandler(handleListCategory(dbStore)))
	mux.Handle("GET /api/categories/{id}", authClient.ValidateTokenFromHandler(handleGetCategory(dbStore)))
	mux.Handle("DELETE /api/categories/{id}", authClient.ValidateTokenFromHandler(handleDeleteCategory(dbStore)))

	// -- Subscriptions
	mux.Handle("POST /api/subscriptions", authClient.ValidateTokenFromHandler(handleCreateSubscription(dbStore)))
	mux.Handle("PUT /api/subscriptions/{id}", authClient.ValidateTokenFromHandler(handleUpdateSubscription(dbStore)))
	mux.Handle("GET /api/subscriptions", authClient.ValidateTokenFromHandler(handleListSubscription(dbStore)))
	mux.Handle("GET /api/subscriptions/{id}", authClient.ValidateTokenFromHandler(handleGetSubscription(dbStore)))
	mux.Handle("DELETE /api/subscriptions/{id}", authClient.ValidateTokenFromHandler(handleDeleteSubscription(dbStore)))

	// -- Cards
	mux.Handle("POST /api/cards", authClient.ValidateTokenFromHandler(handleCreateCard(dbStore)))
	mux.Handle("GET /api/cards/{id}", authClient.ValidateTokenFromHandler(handleGetCard(dbStore)))
	mux.Handle("GET /api/cards", authClient.ValidateTokenFromHandler(handleListCards(dbStore)))
	mux.Handle("PUT /api/cards/{id}", authClient.ValidateTokenFromHandler(handleUpdateCard(dbStore)))
	mux.Handle("DELETE /api/cards/{id}", authClient.ValidateTokenFromHandler(handleDeleteCard(dbStore)))

	// -- ActiveSubscriptions
	mux.Handle("GET /api/activesubscriptions/{id}", authClient.ValidateTokenFromHandler(handleGetActiveSubscription(dbStore)))
	mux.Handle("GET /api/activesubscriptions", authClient.ValidateTokenFromHandler(handleListActiveSubscription(dbStore)))
	mux.Handle("PUT /api/activesubscriptions/{id}", authClient.ValidateTokenFromHandler(handleUpdateActiveSubscription(dbStore)))

	// -- ActiveTrails
}
