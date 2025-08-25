package main

import (
	"github.com/benkoben/unsubtle-core/frontend"
	auth "github.com/benkoben/unsubtle-core/internal/auth_client"
	"github.com/benkoben/unsubtle-core/internal/database"
	"net/http"
)

// addRoutes accepts a pointer to a mux together all possible dependencies that we can think of using when defining the routes
func addRoutes(
	mux *http.ServeMux,
	config *Config,
	dbStore *database.Queries,
	authClient auth.Client,
	// --- More different stores can be added below if necessary
) {
	// Serve static HTML files
	mux.Handle("GET /", frontend.HandleIndex())
	mux.Handle("GET /dashboard", authClient.ValidateToken(frontend.HandleDashboard()))
	mux.Handle("GET /static/", authClient.ValidateToken(frontend.HandleStatic()))

	// API requests are defined below
	//
	// -- Authentication handlers
	mux.Handle("POST /login", handleLoginForm(authClient))
	mux.Handle("POST /register", handleRegisterForm(dbStore))
	mux.Handle("POST /token", handleTokenRequest(authClient))
	mux.Handle("POST /auth/refresh", handleRefreshToken(authClient))

	mux.Handle("POST /api/authcheck", authClient.ValidateToken(handleAuthCheck()))

	// -- Users
	// TODO: Authorization (These handlers should only be available to admin users)
	// mux.Handle("GET /api/token", handleLoginToken(config)
	mux.Handle("GET /api/users", authClient.ValidateToken(handleListUsers(dbStore)))
	mux.Handle("GET /api/users/{id}", authClient.ValidateToken(handleGetUser(dbStore)))
	mux.Handle("PUT /api/users/{id}", authClient.ValidateToken(handleUpdateUser(dbStore)))
	mux.Handle("DELETE /api/users/{id}", authClient.ValidateToken(handleDeleteUser(dbStore)))

	// -- Categories
	mux.Handle("POST /api/categories", authClient.ValidateToken(handleCreateCategory(dbStore)))
	mux.Handle("PUT /api/categories/{id}", authClient.ValidateToken(handleUpdateCategory(dbStore)))
	mux.Handle("GET /api/categories", authClient.ValidateToken(handleListCategory(dbStore)))
	mux.Handle("GET /api/categories/{id}", authClient.ValidateToken(handleGetCategory(dbStore)))
	mux.Handle("DELETE /api/categories/{id}", authClient.ValidateToken(handleDeleteCategory(dbStore)))

	// -- Subscriptions
	mux.Handle("POST /api/subscriptions", authClient.ValidateToken(handleCreateSubscription(dbStore)))
	mux.Handle("PUT /api/subscriptions/{id}", authClient.ValidateToken(handleUpdateSubscription(dbStore)))
	mux.Handle("GET /api/subscriptions", authClient.ValidateToken(handleListSubscription(dbStore)))
	mux.Handle("GET /api/subscriptions/{id}", authClient.ValidateToken(handleGetSubscription(dbStore)))
	mux.Handle("DELETE /api/subscriptions/{id}", authClient.ValidateToken(handleDeleteSubscription(dbStore)))

	// -- Cards
	mux.Handle("POST /api/cards", authClient.ValidateToken(handleCreateCard(dbStore)))
	mux.Handle("GET /api/cards/{id}", authClient.ValidateToken(handleGetCard(dbStore)))
	mux.Handle("GET /api/cards", authClient.ValidateToken(handleListCards(dbStore)))
	mux.Handle("PUT /api/cards/{id}", authClient.ValidateToken(handleUpdateCard(dbStore)))
	mux.Handle("DELETE /api/cards/{id}", authClient.ValidateToken(handleDeleteCard(dbStore)))

	// -- ActiveSubscriptions
	mux.Handle("GET /api/activesubscriptions/{id}", authClient.ValidateToken(handleGetActiveSubscription(dbStore)))
	mux.Handle("GET /api/activesubscriptions", authClient.ValidateToken(handleListActiveSubscription(dbStore)))
	mux.Handle("PUT /api/activesubscriptions/{id}", authClient.ValidateToken(handleUpdateActiveSubscription(dbStore)))

	// -- ActiveTrails
}
