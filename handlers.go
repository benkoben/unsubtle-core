package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/benkoben/unsubtle-core/internal/auth"
	"github.com/benkoben/unsubtle-core/internal/database"
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

// --- Authentication handlers
func handleRevoke(db dbQuerier, cfg *Config) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, err := auth.GetBearerToken(r.Header)
		if err != nil {
			// No bearer token found in headers
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		userId, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
		if err != nil {
			// Bearer token was found but is not valid
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		refreshToken, err := db.RevokeRefreshToken(r.Context(), userId)
		if err != nil {
			log.Printf("revoke refresh token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		if err := encode(w, http.StatusOK, refreshToken); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})
}

func handleRefresh(db dbQuerier, cfg *Config) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, err := auth.GetBearerToken(r.Header)
		if err != nil {
			// No bearer token found in headers
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		userId, err := auth.ValidateJWT(bearer, cfg.JWTSecret)
		if err != nil {
			// Bearer token was found but is not valid
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		// Check if there exists a refresh token
		refreshToken, err := db.GetRefreshToken(r.Context(), userId)
		if err != nil {
			// Normally this is not possible but in rare cases where
			// an valid JWT is used but no refreshToken exists we need to handle this.
			if err == sql.ErrNoRows {
				// Bearer token was found but is not valid
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(http.StatusText(http.StatusForbidden)))
				return
			} else {
				// Should not happend under normal circumstances
				log.Printf("retrieve refresh token: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// validate if the existing refresh token is not revoked
		// if the token is revoked or expired
		if refreshToken.RevokedAt.Valid || refreshToken.ExpiresAt.Unix() < time.Now().Unix() {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(http.StatusText(http.StatusForbidden)))
			return
		}

		// Make JWT token, a token lives for 60 minutes.
		jwt, err := auth.MakeJWT(userId, cfg.JWTSecret, time.Minute*60)
		if err != nil {
			log.Printf("could not create jwt token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		if err := encode(w, http.StatusOK, map[string]string{"token": jwt}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})
}

func handleLogin(db dbQuerier, cfg *Config) http.Handler {
	res := response{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Retrieve credentials from body
		defer r.Body.Close()

		// Lookup user in database
		loginCredentials, err := decode[userRequestData](r.Body)
		if err != nil {
			log.Printf("invalid json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		registeredUser, err := db.GetUserByEmail(r.Context(), loginCredentials.Email)
		if err != nil {
			// TODO: This if error is ErrNoRows else internal error pattern is reused in quite a lot of different places
			if err == sql.ErrNoRows {
				// User does not exist in database
				res.Status = http.StatusForbidden
				res.Error = http.StatusText(http.StatusForbidden)
				if err := encode(w, res.Status, res); err != nil {
					log.Printf("could not encode response: %v", err)
				}
				return
			} else {
				// Unexpected error
				log.Printf("retrieving user by email: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// Validate password
		if ok := auth.IsValid(loginCredentials.Password, registeredUser.HashedPassword); !ok {
			res.Status = http.StatusForbidden
			res.Error = "invalid password"
			if err := encode(w, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}
			return
		}

		// Make JWT token, a token lives for 60 minutes.
		jwt, err := auth.MakeJWT(registeredUser.ID, cfg.JWTSecret, time.Minute*60)
		if err != nil {
			log.Printf("could not create jwt token: %w", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}

		// Check if we need to create a refresh token or not
		refreshToken, err := db.GetRefreshToken(r.Context(), registeredUser.ID)
		if err != nil {
			if err == sql.ErrNoRows {
				newTokenString, err := auth.MakeRefreshToken()
				if err != nil {
					log.Printf("could not create refresh token: %w", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
					return
				}
				refreshTokenOpts := database.CreateRefreshTokenParams{
					UserID:    registeredUser.ID,
					ExpiresAt: time.Now().Add(time.Hour * 1440), // 60 days
					Token:     newTokenString,
				}

				newToken, err := db.CreateRefreshToken(r.Context(), refreshTokenOpts)
				if err != nil {
					log.Printf("could not save refresh token to database: %w", err)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
					return
				}
				refreshToken = newToken
			} else {
				// Unexpected error
				log.Printf("retrieving refresh token: %w", err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
				return
			}
		}

		// TODO: BUG where a user cannot login when they have a revoked refresh token (because a new one is generated by cannot be inserted into the db)

		// Create response body
		responseBody := loginResponseData{
			Id:           registeredUser.ID,
			Email:        registeredUser.Email,
			CreatedAt:    registeredUser.CreatedAt,
			UpdatedAt:    registeredUser.UpdatedAt,
			Token:        jwt,
			RefreshToken: refreshToken.Token,
		}

		if err := encode(w, http.StatusOK, responseBody); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	})

}

// --- User handlers
func handleCreateUser(query dbQuerier) http.Handler {
	var res response

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the email and password from the request body
		defer r.Body.Close()
		defer res.respond(w)

		newUserData, err := decode[userRequestData](r.Body)
		if err != nil {
			log.Printf("error decoding json: %v", err)
			res.Status = http.StatusBadRequest
			return
		}

		// Validate the email
		if ok := validEmail(newUserData.Email); !ok {
			res.Status = http.StatusBadRequest
			res.Error = "invalid email"
			return
		}

		// Check if the email is already registered
		existingUser, err := query.GetUserByEmail(r.Context(), newUserData.Email)
		if err != nil && err != sql.ErrNoRows {
			// If any error other than ErrNoRows is returned this means something unexpected happened.
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
			return
		}

		// If existingUser contains data, this means there already exists a database entry for the requested email
		if existingUser.Email != "" {
			res.Status = http.StatusConflict
			res.Error = "email is already registered"
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			res.Status = http.StatusBadRequest
			res.Error = fmt.Sprintf("invalid password: %v", err)
			return
		}

		// Hash the password
		hash, err := auth.CreateHash(newUserData.Password)
		if err != nil {
			log.Printf("error hashing password: %v", err)
			res.Status = http.StatusInternalServerError
			return
		}

		// Save the user to the database
		createUserParams := database.CreateUserParams{
			Email:          newUserData.Email,
			HashedPassword: hash,
		}

		dbResponse, err := query.CreateUser(r.Context(), createUserParams)
		if err != nil {
			log.Printf("error creating user: %v", err)
			res.Status = http.StatusInternalServerError
			return
		}

		res.Status = http.StatusCreated
		res.Content = dbResponse
	})
}

func handleListUsers(query *database.Queries) http.Handler {
	var res response
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		defer res.respond(w)

		users, err := query.ListUsers(r.Context())
		if err != nil {
			log.Printf("error listing users: %v", err)
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			res.Error = "invalid id"
			return
		}

		user, err := query.GetUserById(r.Context(), id)
		if err != nil {
			if err == sql.ErrNoRows {
				res.Status = http.StatusNotFound
				res.Error = http.StatusText(http.StatusNotFound)
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
			res.Error = "invalid id"
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
				res.Error = "user not found"
				return
			}
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
			return
		}

		// Validate the password criteria
		if err := passwordvalidator.Validate(newUserData.Password, minEntropy); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			res.Error = fmt.Sprintf("invalid password: %v", err)
			return
		}

		// Hash password
		hashedPw, err := auth.CreateHash(newUserData.Password)
		if err != nil {
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		if _, err := query.DeleteUser(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = "user not found"
				res.Status = http.StatusNotFound
			} else {
				res.Error = http.StatusText(http.StatusInternalServerError)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		// TODO: Authorization should be added to differentiate between all and user specific database entries.
		dbCards, err := query.ListCardsForOwner(r.Context(), userId)
		if err != nil {
			res.Error = http.StatusText(http.StatusInternalServerError)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = "invalid id"
			res.Status = http.StatusBadRequest
		}

		card, err := query.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}
		if card.Owner != userId {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
		}

		if _, err := query.DeleteCard(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			res.Error = http.StatusText(http.StatusInternalServerError)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		newCard, err := decode[cardRequest](r.Body)
		if err != nil {
			res.Error = http.StatusText(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			return
		}

		if _, err := db.GetCardByName(r.Context(), database.GetCardByNameParams{
			Name:  newCard.Name,
			Owner: userId,
		}); err != nil {
			// If the card does not exist, this is a good thing. Otherwise something unexpected happened
			if !errors.Is(err, sql.ErrNoRows) {
				log.Printf("error getting existing card: %v", err)
				res.Error = http.StatusText(http.StatusInternalServerError)
				res.Status = http.StatusInternalServerError
				return
			}
		}

		card, err := db.CreateCard(r.Context(), database.CreateCardParams{
			Name:      newCard.Name,
			ExpiresAt: newCard.ExpiresAt,
			Owner:     userId,
		})

		if err != nil {
			res.Error = http.StatusText(http.StatusInternalServerError)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = "invalid id"
			res.Status = http.StatusBadRequest
		}

		card, err := query.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}
		if card.Owner != userId {
			res.Error = http.StatusText(http.StatusForbidden)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = "invalid id"
			res.Status = http.StatusBadRequest
			return
		}

		existingCard, err := db.GetCard(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			log.Printf("error getting existing card: %v", err)
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}
		if existingCard.Owner != userId {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		requestBody, err := decode[cardRequest](r.Body)
		if err != nil {
			res.Error = http.StatusText(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			return
		}

		card, err := db.UpdateCard(r.Context(), database.UpdateCardParams{
			Name:      requestBody.Name,
			ExpiresAt: requestBody.ExpiresAt,
		})
		if err != nil {
			log.Printf("error updating card: %v", err)
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}

		// Retrieve userId from Context (set by middleware)
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		if _, err := db.CheckExistingCategory(r.Context(), database.CheckExistingCategoryParams{
			Name:      requestBody.Name,
			CreatedBy: userId,
		}); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusInternalServerError)
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
			CreatedBy:   userId,
		})

		if err != nil {
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
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
			res.Error = http.StatusText(http.StatusBadRequest)
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
				res.Error = http.StatusText(http.StatusNotFound)
			} else {
				log.Printf("%w: %w", UnexpectedDbError, &err)
				res.Status = http.StatusInternalServerError
				res.Error = http.StatusText(http.StatusInternalServerError)
			}
			return
		}

		authenticatedUserId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			// Check that the userId is not malformed
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}

		if authenticatedUserId != existingCategory.CreatedBy {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
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
			res.Error = http.StatusText(http.StatusInternalServerError)
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
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		categories, err := db.ListCategoriesForUserId(r.Context(), userId)
		if err != nil {
			log.Printf("%w: %w", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
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

		// Retrieve the currently authenticated user from context
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

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

		if category.CreatedBy != userId {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
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
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
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
		if category.CreatedBy != userId {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
			return
		}

		// Delete the category
		if _, err := db.DeleteCategory(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
			} else {
				res.Error = http.StatusText(http.StatusInternalServerError)
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

		// Retrieve userId from Context (set by middleware)
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		newSubscriptionData, err := decode[subscriptionRequest](r.Body)
		if err != nil {
			log.Printf("error decoding json: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check if the subscriptions is already registered
		existingSubscription, err := db.GetSubscriptionByNameAndCreator(r.Context(), database.GetSubscriptionByNameAndCreatorParams{
			CreatedBy: userId,
			Name:      newSubscriptionData.Name,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			// If any error other than ErrNoRows is returned this means something unexpected happened.
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)

			if err := encode(w, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// If existingSubscription contains data, this means there already exists a database entry for the requested email
		if existingSubscription.Name != "" {
			res.Status = http.StatusConflict
			res.Error = "subscription is already registered"

			if err := encode(w, res.Status, res); err != nil {
				log.Printf("could not encode response: %v", err)
			}

			return
		}

		// Save the user to the database
		createSubscriptionParams := database.CreateSubscriptionParams{
			CreatedBy:      userId,
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
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		// Parse id from URL path
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
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
		if subscription.CreatedBy != userId {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
			return
		}

		// Delete the category
		if _, err := db.DeleteSubscription(r.Context(), id); err != nil {
			if err == sql.ErrNoRows {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
			} else {
				res.Error = http.StatusText(http.StatusInternalServerError)
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
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		// Parse id from URL path
		log.Println(r.PathValue("id"))
		log.Println(r.URL.String())
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
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

		if subscription.CreatedBy != userId {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
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
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		subscriptions, err := db.ListSubscriptionsForUserId(r.Context(), userId)
		if err != nil {
			log.Printf("%v: %v", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			res.Error = http.StatusText(http.StatusBadRequest)
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
				res.Error = http.StatusText(http.StatusNotFound)
			} else {
				log.Printf("%v: %v", UnexpectedDbError, &err)
				res.Status = http.StatusInternalServerError
				res.Error = http.StatusText(http.StatusInternalServerError)
			}
			return
		}

		authenticatedUserId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			// Will fail if the userId value cannot be cast into an uuid.UUID
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}

		if authenticatedUserId != existingSubscription.CreatedBy {
			res.Status = http.StatusForbidden
			res.Error = http.StatusText(http.StatusForbidden)
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
			res.Error = http.StatusText(http.StatusInternalServerError)
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

		// Retrieve userId from Context (set by middleware)
		val := r.Context().Value(userIdCtxKey)
		if val == nil {
			log.Println("could not retrieve userId from context")
			res.Status = http.StatusBadRequest
			res.Error = http.StatusText(http.StatusBadRequest)
			return
		}
		userId := val.(uuid.UUID)

		active_subscriptions, err := db.ListActiveSubscriptionByUserId(r.Context(), userId)
		if err != nil {
			log.Printf("%v: %v", UnexpectedDbError, &err)
			res.Status = http.StatusInternalServerError
			res.Error = http.StatusText(http.StatusInternalServerError)
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
		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = "invalid id"
			res.Status = http.StatusBadRequest
		}

		active_subscription, err := db.GetActiveSubscriptionById(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}
		if active_subscription.UserID != userId {
			res.Error = http.StatusText(http.StatusForbidden)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			res.Error = "invalid id"
			res.Status = http.StatusBadRequest
			return
		}

		existingActiveSub, err := db.GetActiveSubscriptionById(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = http.StatusText(http.StatusNotFound)
				res.Status = http.StatusNotFound
				return
			}
			log.Printf("error getting existing card: %v", err)
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}
		if existingActiveSub.UserID != userId {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		requestBody, err := decode[activeSubscriptionUpdateRequest](r.Body)
		if err != nil {
			log.Println("Bad request body: ", err)
			res.Error = http.StatusText(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			return
		}

		activeSub, err := db.UpdateActiveSubscription(r.Context(), database.UpdateActiveSubscriptionParams{
			ID: id,
			BillingFrequency: requestBody.BillingFrequency,
			AutoRenewEnabled: sql.NullBool{
				Bool: *requestBody.AutoRenewEnabled,
				Valid: true,
			},
		})
		if err != nil {
			log.Printf("error updating active subscription: %v", err)
			res.Error = http.StatusText(http.StatusInternalServerError)
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
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid id"))
		}

		if _, err := query.DeleteActiveSubscription(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				res.Error = "user not found"
				res.Status = http.StatusNotFound
			} else {
				res.Error = http.StatusText(http.StatusInternalServerError)
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

		userId, ok := r.Context().Value(userIdCtxKey).(uuid.UUID)
		if !ok {
			res.Error = http.StatusText(http.StatusForbidden)
			res.Status = http.StatusForbidden
			return
		}

		newActiveSubscription, err := decode[activeSubscriptionRequest](r.Body)
		if err != nil {
			res.Error = http.StatusText(http.StatusBadRequest)
			res.Status = http.StatusBadRequest
			return
		}

		if _, err := db.GetActiveSubscriptionByUserIdAndSubId(r.Context(), database.GetActiveSubscriptionByUserIdAndSubIdParams{UserID: userId, SubscriptionID: newActiveSubscription.SubscriptionID}); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Printf("error getting existing card: %v", err)
				res.Error = http.StatusText(http.StatusInternalServerError)
				res.Status = http.StatusInternalServerError
				return
			}
		}
		
		activeSubscription, err := db.CreateActiveSubscription(r.Context(), database.CreateActiveSubscriptionParams{
			SubscriptionID: newActiveSubscription.SubscriptionID,
			UserID: userId,
			CardID: newActiveSubscription.CardID,
			UpdatedAt: time.Now(),
			BillingFrequency: newActiveSubscription.BillingFrequency,
			AutoRenewEnabled: newActiveSubscription.AutoRenewEnabled,
		})

		if err != nil {
			res.Error = http.StatusText(http.StatusInternalServerError)
			res.Status = http.StatusInternalServerError
			return
		}

		res.Status = http.StatusCreated
		res.Content = activeSubscription
	})
}

// --- Active trails handlers
