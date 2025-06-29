package main

import (
	"context"
	"database/sql"

	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/google/uuid"
)

// dbQuerier is an interface that allows us to use dependency injection on handlers.
// It's purpose is to enable self-contained unit testing. While this wont allow us to test queries, it does allow us to test the logic defined within a handler.
type dbQuerier interface {
	// User interactions
	GetUserById(context.Context, uuid.UUID) (database.User, error)
	CreateUser(context.Context, database.CreateUserParams) (database.CreateUserRow, error)
	GetUserByEmail(context.Context, string) (database.User, error)
	DeleteUser(context.Context, uuid.UUID) (sql.Result, error)

	// RefreshToken interactions
	CreateRefreshToken(context.Context, database.CreateRefreshTokenParams) (database.RefreshToken, error)
	UpdateRefreshToken(context.Context, database.UpdateRefreshTokenParams) (database.RefreshToken, error)
	RevokeRefreshToken(context.Context, uuid.UUID) (database.RefreshToken, error)
	GetRefreshToken(context.Context, uuid.UUID) (database.RefreshToken, error)

	// Subscription interactions
	CreateSubscription(ctx context.Context, arg database.CreateSubscriptionParams) (database.Subscription, error)
	DeleteSubscription(ctx context.Context, id uuid.UUID) (sql.Result, error)
	GetSubscription(ctx context.Context, id uuid.UUID) (database.Subscription, error)
	ListSubscriptions(ctx context.Context) ([]database.Subscription, error)
	ListSubscriptionsForUserId(ctx context.Context, createdBy uuid.UUID) ([]database.Subscription, error)
	ResetSubscriptions(ctx context.Context) ([]database.Subscription, error)
	UpdateSubscription(ctx context.Context, arg database.UpdateSubscriptionParams) (database.Subscription, error)
	GetSubscriptionByNameAndCreator(ctx context.Context, arg database.GetSubscriptionByNameAndCreatorParams) (database.Subscription, error)

	// Category interactions
	UpdateCategory(context.Context, database.UpdateCategoryParams) (database.Category, error)
	ResetCategories(context.Context) ([]database.Category, error) // TODO - implement this
	ListCategories(context.Context) ([]database.Category, error)
	GetCategory(context.Context, uuid.UUID) (database.Category, error)
	CreateCategory(context.Context, database.CreateCategoryParams) (database.Category, error)
	CheckExistingCategory(ctx context.Context, arg database.CheckExistingCategoryParams) (database.Category, error)
	ListCategoriesForUserId(ctx context.Context, createdBy uuid.UUID) ([]database.Category, error)
	DeleteCategory(ctx context.Context, id uuid.UUID) (sql.Result, error)

	// Card interactions
	CreateCard(ctx context.Context, arg database.CreateCardParams) (database.CreateCardRow, error)
	UpdateCard(ctx context.Context, arg database.UpdateCardParams) (database.Card, error)
	GetCard(ctx context.Context, id uuid.UUID) (database.Card, error)
	ListCards(ctx context.Context) ([]database.Card, error)
	ListCardsForOwner(context.Context, uuid.UUID) ([]database.Card, error)
	DeleteCard(ctx context.Context, id uuid.UUID) (sql.Result, error)
	GetCardByName(ctx context.Context, params database.GetCardByNameParams) (database.Card, error)

	// ActiveTrails interactions

	// ActiveSubscriptions interactions
	ListActiveSubscriptionByUserId(ctx context.Context, userID uuid.UUID) ([]database.ActiveSubscription, error)
	GetActiveSubscriptionById(ctx context.Context, id uuid.UUID) (database.ActiveSubscription, error)
	UpdateActiveSubscription(ctx context.Context, arg database.UpdateActiveSubscriptionParams) (database.ActiveSubscription, error)
	DeleteActiveSubscription(ctx context.Context, id uuid.UUID) (sql.Result, error)
	CreateActiveSubscription(ctx context.Context, arg database.CreateActiveSubscriptionParams) (database.ActiveSubscription, error)
	GetActiveSubscriptionByUserIdAndSubId(ctx context.Context, arg database.GetActiveSubscriptionByUserIdAndSubIdParams) (database.ActiveSubscription, error)
}
