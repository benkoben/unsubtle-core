package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/benkoben/unsubtle-core/frontend"
	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/benkoben/unsubtle-core/internal/password"
	auth "github.com/benkoben/unsubtle-core/internal/supabase"
	"github.com/google/uuid"
	"github.com/wagslane/go-password-validator"

	_ "github.com/lib/pq"
)

// TODO: Input sanitazation
// Roles (Especially on the List handlers
// TODO: Cross Site request forgery (?)

var (
	minPasswordLength = 12
	// 26 lowercase letters
	// 26 uppercase letters
	// 10 digits
	// 5 replacement characters - !@$&*
	// 5 seperator characters - _-.,
	// 22 less common special characters - "#%'()+/:;<=>?[\]^{|}~
	minPasswordComplexity = 89 // Product of adding the above criteria
	passwordBase          = math.Pow(float64(minPasswordComplexity), float64(minPasswordLength))
	minEntropy            = math.Log2(passwordBase)
)

// --- User handlers

func handleListUsers(query *database.Queries) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		users, err := query.ListUsers(r.Context())
		if err != nil {
			log.Printf("error listing users: %v", err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		res.Status = http.StatusOK
		res.Content = users
	})
}

func handleGetUser(query dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)
		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = toPtr("invalid id")
			return
		}

		user, err := query.GetUserById(r.Context(), id)
		if err != nil {
			if err == sql.ErrNoRows {
				res.Status = http.StatusNotFound
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}

		// Sanitize output
		user.HashedPassword = ""

		res.Status = http.StatusOK
		res.Content = user
	})
}

func handleUpdateUser(query *database.Queries) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = toPtr("invalid id")
			return
		}

		log.Printf("user id %s update", id.String())

		newUserData, err := decode[userRequestData](r.Body)
		if err != nil {
			res.Status = http.StatusBadRequest
			return
		}

		log.Println(newUserData)

		if _, err := query.GetUserById(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Status = http.StatusBadRequest
				res.Error = toPtr("user not found")
				return
			}
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			res.Error = toPtr(fmt.Sprintf("invalid password: %v", err))
			return
		}

		// Hash password
		hashedPw, err := password.CreateHash(newUserData.Password)
		if err != nil {
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		log.Printf("new hash calculated %s", hashedPw)

		params := database.UpdateUserParams{
			ID:             id,
			Email:          newUserData.Email,
			HashedPassword: hashedPw,
			UpdatedAt:      time.Now(),
		}

		updatedUser, err := query.UpdateUser(r.Context(), params)
		if err != nil {
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}
		res.Status = http.StatusOK
		res.Content = updatedUser
	})
}

func handleDeleteUser(query dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)
		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
		}

		if _, err := query.DeleteUser(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr("user not found")
				res.Status = http.StatusNotFound
			} else {
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
			}
			return
		}
		res.Status = http.StatusNoContent
	})
}

// --- Card handlers
func handleListCards(query *database.Queries) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		// TODO: Authorization should be added to differentiate between all and user specific database entries.
		dbCards, err := query.ListCardsForOwner(r.Context(), *session.UserId)
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		res.Content = dbCards
		res.Status = http.StatusOK
	})
}

func handleDeleteCard(query dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = toPtr("invalid id")
			res.Status = http.StatusBadRequest
		}

		card, err := query.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		if card.Owner != *session.UserId {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
		}

		if _, err := query.DeleteCard(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		res.Status = http.StatusNoContent
	})
}

func handleCreateCard(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		newCard, err := decode[cardRequest](r.Body)
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			res.Status = http.StatusBadRequest
			return
		}

		if _, err := db.GetCardByName(r.Context(), database.GetCardByNameParams{
			Name:  newCard.Name,
			Owner: *session.UserId,
		}); err != nil {
			// If the card does not exist, this is a good thing. Otherwise something unexpected happened
			if !errors.Is(err, sql.ErrNoRows) {
				log.Printf("error getting existing card: %v", err)
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
				return
			}
		}

		card, err := db.CreateCard(r.Context(), database.CreateCardParams{
			Name:      newCard.Name,
			ExpiresAt: newCard.ExpiresAt,
			Owner:     *session.UserId,
		})

		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}

		res.Status = http.StatusCreated
		res.Content = card
	})
}

func handleGetCard(query dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = toPtr("invalid id")
			res.Status = http.StatusBadRequest
		}

		card, err := query.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		if card.Owner != *session.UserId {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		res.Content = card
		res.Status = http.StatusOK
	})
}

func handleUpdateCard(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = toPtr("invalid id")
			res.Status = http.StatusBadRequest
			return
		}

		existingCard, err := db.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			log.Printf("error getting existing card: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		if existingCard.Owner != *session.UserId {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		requestBody, err := decode[cardRequest](r.Body)
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			res.Status = http.StatusBadRequest
			return
		}

		card, err := db.UpdateCard(r.Context(), database.UpdateCardParams{
			Name:      requestBody.Name,
			ExpiresAt: requestBody.ExpiresAt,
		})
		if err != nil {
			log.Printf("error updating card: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}

		res.Content = card
		res.Status = http.StatusOK
	})
}

// --- Category handlers

/*
handleCreateCategory handles the creation of a category.
It assumes that the request.Context userId key has been set.
*/
func handleCreateCategory(db dbQuerier) http.Handler {
	var res response

	type categoryRequestBody = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the category Name and description from the request
		defer r.Body.Close()
		defer res.respond(w)

		requestBody, err := decode[categoryRequestBody](r.Body)
		if err != nil {
			log.Println("could not decode body")
			res.Status = http.StatusBadRequest
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			return
		}

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		if _, err := db.CheckExistingCategory(r.Context(), database.CheckExistingCategoryParams{
			Name:      requestBody.Name,
			CreatedBy: *session.UserId,
		}); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
				return
			}
		} else {
			res.Content = "category already exists"
			res.Status = http.StatusConflict
			return
		}

		// Submit to database
		category, err := db.CreateCategory(r.Context(), database.CreateCategoryParams{
			Name:        requestBody.Name,
			Description: requestBody.Description,
			CreatedBy:   *session.UserId,
		})

		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			return
		}

		res.Status = http.StatusOK
		res.Content = category
	})
}

func handleUpdateCategory(db dbQuerier) http.Handler {
	var res response

	type categoryUpdateRequestBody = struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: try out this pattern and refactor if it works
		defer res.respond(w)

		requestBody, err := decode[categoryUpdateRequestBody](r.Body)
		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			if err := encode(w, res.Status, res); err != nil {
				log.Printf("%w: %w", ResponseFailureError, err)
			}
			return
		}

		// Get CategoryId from path
		categoryId, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		existingCategory, err := db.GetCategory(r.Context(), categoryId)
		if err != nil {
			if err == sql.ErrNoRows {
				res.Status = http.StatusNotFound
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
			} else {
				log.Printf("%w: %w", UnexpectedDbError, &err)
				res.Status = http.StatusInternalServerError
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			}
			return
		}

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		if *session.UserId != existingCategory.CreatedBy {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		// Submit changes to database
		updatedCategory, err := db.UpdateCategory(r.Context(), database.UpdateCategoryParams{
			ID:          categoryId,
			Name:        requestBody.Name,
			Description: requestBody.Description,
		})
		if err != nil {
			log.Printf("%w: %w", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		res.Status = http.StatusOK
		res.Content = updatedCategory
	})
}

func handleListCategory(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		// TODO: In future we can do role filtering
		// - Admin = ListAllCategories
		// - Normal user = ListByUserID

		// Retrieve userId from Context (set by middleware)
		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		categories, err := db.ListCategoriesForUserId(r.Context(), *session.UserId)
		if err != nil {
			log.Printf("%w: %w", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		res.Status = http.StatusOK
		res.Content = categories
	})
}

func handleGetCategory(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		// Parse id from URL path
		log.Println(r.PathValue("id"))
		log.Println(r.URL.String())
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
			return
		}

		category, err := db.GetCategory(r.Context(), id)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if category.CreatedBy != *session.UserId {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		res.Status = http.StatusOK
		res.Content = category
	})
}

func handleDeleteCategory(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)
		// Retrieve the currently authenticated user from context

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		// Retrieve the existing category
		category, err := db.GetCategory(r.Context(), id)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Check if the currently authenticated user is allowed to delete
		if category.CreatedBy != *session.UserId {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		// Delete the category
		if _, err := db.DeleteCategory(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
			} else {
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
			}
			return
		}

		res.Status = http.StatusNoContent
	})
}

// --- Subscription handlers
func handleCreateSubscription(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the email and password from the request body
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		newSubscriptionData, err := decode[subscriptionRequest](r.Body)
		if err != nil {
			log.Printf("error decoding json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check if the subscriptions is already registered
		existingSubscription, err := db.GetSubscriptionByNameAndCreator(r.Context(), database.GetSubscriptionByNameAndCreatorParams{
			CreatedBy: *session.UserId,
			Name:      newSubscriptionData.Name,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			// If any error other than ErrNoRows is returned this means something unexpected happened.
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))

			if err := encode(w, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// If existingSubscription contains data, this means there already exists a database entry for the requested email
		if existingSubscription.Name != "" {
			res.Status = http.StatusConflict
			res.Error = toPtr("subscription is already registered")

			if err := encode(w, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// Save the user to the database
		createSubscriptionParams := database.CreateSubscriptionParams{
			CreatedBy:      *session.UserId,
			Name:           newSubscriptionData.Name,
			MonthlyCost:    newSubscriptionData.MonthlyCost,
			Currency:       newSubscriptionData.Currency,
			Description:    newSubscriptionData.Description,
			UnsubscribeUrl: newSubscriptionData.UnsubscribeUrl,
			CategoryID:     newSubscriptionData.CategoryId,
		}

		dbResponse, err := db.CreateSubscription(r.Context(), createSubscriptionParams)
		if err != nil {
			log.Printf("error creating user: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		res.Content = dbResponse
		res.Status = http.StatusCreated
	})
}

func handleDeleteSubscription(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the currently authenticated user from context
		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		// Retrieve the existing category
		subscription, err := db.GetSubscription(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Check if the currently authenticated user is allowed to delete
		if subscription.CreatedBy != *session.UserId {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		// Delete the category
		if _, err := db.DeleteSubscription(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
			} else {
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
			}
			encode(w, res.Status, res)
			return
		}

		res.Status = http.StatusNoContent
	})
}

func handleGetSubscription(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer res.respond(w)

		// Retrieve the currently authenticated user from context
		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		// Parse id from URL path
		log.Println(r.PathValue("id"))
		log.Println(r.URL.String())
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		subscription, err := db.GetSubscription(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if subscription.CreatedBy != *session.UserId {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		res.Status = http.StatusOK
		res.Content = subscription
	})
}

func handleListSubscription(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer res.respond(w)

		// TODO: In future we can do role filtering
		// - Admin = ListAllCategories
		// - Normal user = ListByUserID

		// Retrieve userId from Context (set by middleware)
		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		subscriptions, err := db.ListSubscriptionsForUserId(r.Context(), *session.UserId)
		if err != nil {
			log.Printf("%v: %v", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}
		log.Println(subscriptions)

		res.Status = http.StatusOK
		res.Content = subscriptions
	})
}

func handleUpdateSubscription(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer res.respond(w)

		requestBody, err := decode[subscriptionRequest](r.Body)
		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			if err := encode(w, res.Status, res); err != nil {
				log.Printf("%w: %w", ResponseFailureError, err)
			}
			return
		}

		// Get CategoryId from path
		subscriptionId, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		existingSubscription, err := db.GetSubscription(r.Context(), subscriptionId)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Status = http.StatusNotFound
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
			} else {
				log.Printf("%v: %v", UnexpectedDbError, &err)
				res.Status = http.StatusInternalServerError
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			}
			return
		}

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		if *session.UserId != existingSubscription.CreatedBy {
			res.Status = http.StatusForbidden
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			return
		}

		// Submit changes to database
		updatedSubscription, err := db.UpdateSubscription(r.Context(), database.UpdateSubscriptionParams{
			ID:             subscriptionId,
			Name:           requestBody.Name,
			MonthlyCost:    requestBody.MonthlyCost,
			Currency:       requestBody.Currency,
			UnsubscribeUrl: requestBody.UnsubscribeUrl,
			Description:    requestBody.Description,
			CategoryID:     requestBody.CategoryId,
		})
		if err != nil {
			log.Printf("%v: %v", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		res.Status = http.StatusOK
		res.Content = updatedSubscription
	})
}

// --- Active subscription handlers
func handleListActiveSubscription(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		active_subscriptions, err := db.ListActiveSubscriptionByUserId(r.Context(), *session.UserId)
		if err != nil {
			log.Printf("%v: %v", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			return
		}

		res.Status = http.StatusOK
		res.Content = active_subscriptions
	})
}

func handleGetActiveSubscription(db dbQuerier) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer res.respond(w)
		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = toPtr("invalid id")
			res.Status = http.StatusBadRequest
		}

		active_subscription, err := db.GetActiveSubscriptionById(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		if active_subscription.UserID != *session.UserId {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		res.Content = active_subscription
		res.Status = http.StatusOK
	})
}

func handleUpdateActiveSubscription(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			log.Printf("error getting session key from context: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = toPtr("invalid id")
			res.Status = http.StatusBadRequest
			return
		}

		existingActiveSub, err := db.GetActiveSubscriptionById(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr(http.StatusText(http.StatusNotFound))
				res.Status = http.StatusNotFound
				return
			}
			log.Printf("error getting existing card: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}
		if existingActiveSub.UserID != *session.UserId {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		requestBody, err := decode[activeSubscriptionUpdateRequest](r.Body)
		if err != nil {
			log.Println("Bad request body: ", err)
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			res.Status = http.StatusBadRequest
			return
		}

		activeSub, err := db.UpdateActiveSubscription(r.Context(), database.UpdateActiveSubscriptionParams{
			ID:               id,
			BillingFrequency: requestBody.BillingFrequency,
			AutoRenewEnabled: sql.NullBool{
				Bool:  *requestBody.AutoRenewEnabled,
				Valid: true,
			},
		})
		if err != nil {
			log.Printf("error updating active subscription: %v", err)
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}

		res.Content = activeSub
		res.Status = http.StatusOK
	})
}

func handleDeleteActiveSubscription(query dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)
		// Parse id from URL query
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}

		if _, err := query.DeleteActiveSubscription(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = toPtr("user not found")
				res.Status = http.StatusNotFound
			} else {
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
			}
			return
		}
		res.Status = http.StatusNoContent
	})
}

func handleCreateActiveSubscription(db dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		session, err := auth.GetSessionFromContext(r.Context())
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusForbidden))
			res.Status = http.StatusForbidden
			return
		}

		newActiveSubscription, err := decode[activeSubscriptionRequest](r.Body)
		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusBadRequest))
			res.Status = http.StatusBadRequest
			return
		}

		if _, err := db.GetActiveSubscriptionByUserIdAndSubId(r.Context(), database.GetActiveSubscriptionByUserIdAndSubIdParams{UserID: *session.UserId, SubscriptionID: newActiveSubscription.SubscriptionID}); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Printf("error getting existing card: %v", err)
				res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
				res.Status = http.StatusInternalServerError
				return
			}
		}

		activeSubscription, err := db.CreateActiveSubscription(r.Context(), database.CreateActiveSubscriptionParams{
			SubscriptionID:   newActiveSubscription.SubscriptionID,
			UserID:           *session.UserId,
			CardID:           newActiveSubscription.CardID,
			UpdatedAt:        time.Now(),
			BillingFrequency: newActiveSubscription.BillingFrequency,
			AutoRenewEnabled: newActiveSubscription.AutoRenewEnabled,
		})

		if err != nil {
			res.Error = toPtr(http.StatusText(http.StatusInternalServerError))
			res.Status = http.StatusInternalServerError
			return
		}

		res.Status = http.StatusCreated
		res.Content = activeSubscription
	})
}

// --- Active trails handlers

// Add these new handlers to your existing handlers.go file

func handleLoginForm(authClient AuthClient) http.Handler {
	var htmxAlert frontend.HtmxResponse
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer htmxAlert.Respond(w)
		defer r.Body.Close()

		err := r.ParseForm()
		if err != nil {
			htmxAlert = frontend.InvalidFormDataError
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		if email == "" || password == "" {
			htmxAlert = frontend.EmailAndPasswordError
			return
		}

		// Here we add Supabase login
		session, err := authClient.LoginWithEmailAndPassword(email, password)
		if err != nil {
			htmxAlert = frontend.InvalidEmailOrPasswordError
			return
		}

		// Return JSON response for successful login
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		loginJSON, err := json.Marshal(session)
		if err != nil {
			htmxAlert = frontend.ServerError
			return
		}

		w.WriteHeader(http.StatusOK)
		htmxAlert = frontend.HtmxResponse(loginJSON)
	})
}

func handleRegisterForm(dbStore dbQuerier) http.Handler {
	var htmxAlert frontend.HtmxResponse
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer htmxAlert.Respond(w)
		defer r.Body.Close()

		err := r.ParseForm()
		if err != nil {
			htmxAlert = frontend.InvalidFormDataError
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		if email == "" || password == "" {
			htmxAlert = frontend.EmailAndPasswordError
			return
		}

		// Create user request data
		userData := userRequestData{
			Email:    email,
			Password: password,
		}

		// Call existing user creation logic
		response := createUser(r.Context(), dbStore, userData)
		if response.Error != nil {
			log.Printf("error creating user: %v", *response.Error)
			// TODO: Convert error into their own types
			if strings.Contains(*response.Error, "insecure password") || strings.Contains(*response.Error, "invalid password") {
				htmxAlert = frontend.InsecurePasswordError
				return
			}
			htmxAlert = frontend.DuplicateUserError
			return
		}

		htmxAlert = frontend.RegistrationSuccess
	})
}

func handleTokenValidation(authClient AuthClient) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := authClient.ValidateTokenFromHeader(r.Header); err != nil {
			log.Printf("error validating token: %v", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func handleTokenRequest(authClient AuthClient) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var userCredentials userRequestData
		if err := json.NewDecoder(r.Body).Decode(&userCredentials); err != nil {
			log.Printf("error decoding token request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		session, err := authClient.LoginWithEmailAndPassword(userCredentials.Email, userCredentials.Password)
		if err != nil {
			log.Printf("error getting session: %v", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		if err := json.NewEncoder(w).Encode(session); err != nil {
			log.Printf("error encoding session: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}
