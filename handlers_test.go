package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/google/uuid"
)

type fakeDatabaseOptions struct {
	// Enables us to test error handling
	raiseError error

	// Controls the behaviour of all GetUserXX methods
	userExists bool
}

type fakeDatabaseQueries struct {
	err        error
	userExists bool
}

func (db fakeDatabaseQueries) GetUserById(_ context.Context, id uuid.UUID) (database.User, error) {
	if db.err != nil {
		return database.User{}, db.err
	}

	log.Println("Returning mocked user")
	// Create a mock user
	u := database.User{
		ID:        id,
		Email:     "example@unsubtle-unit-test.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return u, nil
}
func (db fakeDatabaseQueries) DeleteUser(ctx context.Context, id uuid.UUID) (sql.Result, error) {
	if db.err != nil {
		return nil, db.err
	}

    return nil, nil
}

func (db fakeDatabaseQueries) CreateUser(_ context.Context, _ database.CreateUserParams) (database.CreateUserRow, error) {
	if db.err != nil {
		return database.CreateUserRow{}, db.err
	}

	return database.CreateUserRow{
		ID:        uuid.New(),
		Email:     "example@unsubtle-unit-test.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (db fakeDatabaseQueries) GetUserByEmail(ctx context.Context, email string) (database.User, error) {
	if db.err != nil {
		return database.User{}, db.err
	}

	if db.userExists {
		// return a mock user
		u := database.User{
			ID:        uuid.New(),
			Email:     "example@unsubtle-unit-test.com",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		return u, nil
	}

	return database.User{}, nil
}

func TestHandlerDeleteUser(t *testing.T) {
	pattern := fmt.Sprintf("%s /api/users/{id}", http.MethodDelete)

	t.Run("StatusNotFound when the requested user ID does not exist", func(t *testing.T) {
		srv := newHttpServer(pattern, handleDeleteUser, fakeDatabaseOptions{raiseError: sql.ErrNoRows})

		request := newDeleteUserRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusNotFound)
	})

	t.Run("StatusInternalServerError when an unexpected database interaction failure", func(t *testing.T) {
		srv := newHttpServer(pattern, handleDeleteUser, fakeDatabaseOptions{raiseError: errors.New("random error")})

		request := newDeleteUserRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusInternalServerError)
	})

	t.Run("Successful deletion", func(t *testing.T) {
		srv := newHttpServer(pattern, handleDeleteUser, fakeDatabaseOptions{raiseError: nil})

		request := newDeleteUserRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusNoContent)
	})

}

func TestHandlerCreateUser(t *testing.T) {
	pattern := fmt.Sprintf("%s /api/users/", http.MethodPost)

	t.Run("Mailformed json should return status bad request", func(t *testing.T) {
		body := strings.NewReader("{\"email: \"ben@example.com\"")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusBadRequest)
	})

	t.Run("Invalid email should return status bad request", func(t *testing.T) {
		body := strings.NewReader("{\"email\": \"benexample.com\", \"password\": \"Syp9393\"}")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusBadRequest)
	})

	t.Run("If the mail already exists status conflict is expected", func(t *testing.T) {
		body := strings.NewReader("{\"email\": \"ben@example.com\", \"password\": \"Syp9393\"}")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{userExists: true})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusConflict)
	})

	t.Run("Unexpected errors in database interactions should return internal server error", func(t *testing.T) {
		body := strings.NewReader("{\"email\": \"ben@example.com\", \"password\": \"Syp9393\"}")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{raiseError: errors.New("something is about to go wrong")})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusInternalServerError)
	})

	t.Run("If a weak password is used then a BadRequest is expected", func(t *testing.T) {
		body := strings.NewReader("{\"email\": \"ben@example.com\", \"password\": \"Syp9393\"}")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{raiseError: nil, userExists: false})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusBadRequest)
	})

	t.Run("Successful user creation", func(t *testing.T) {

		body := strings.NewReader("{\"email\": \"ben@example.com\", \"password\": \"Syp9393-Syp9292-Syp9191\"}")
		srv := newHttpServer(pattern, handleCreateUser, fakeDatabaseOptions{raiseError: nil, userExists: false})

		request := newCreateUserRequest(body)
		response := httptest.NewRecorder()

		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusCreated)
	})

}

func TestHandlerGetUserById(t *testing.T) {
	pattern := fmt.Sprintf("%s /api/users/{id}", http.MethodGet)

	t.Run("Ensure hashed password is not present", func(t *testing.T) {

		srv := newHttpServer(pattern, handleGetUser, fakeDatabaseOptions{})
		// Compose request and response
		request := newGetUserByIdRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		// Wanted behaviour
		expectErr := false

		// Send request
		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusOK)

		log.Println(response.Body)
		got, gotErr := decode[database.User](response.Body)
		if gotErr != nil && !expectErr {
			t.Errorf("handleGetUserById -> got err but none was expected")
		}

		if got.HashedPassword != "" {
			t.Errorf("handleGetUserById -> response includes sensitive data")
		}

	})

	t.Run("No row found should return status code 404", func(t *testing.T) {

		srv := newHttpServer(pattern, handleGetUser, fakeDatabaseOptions{raiseError: sql.ErrNoRows})
		// Compose request and response
		request := newGetUserByIdRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		// Send request
		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusNotFound)
	})

	t.Run("Any error other than sql.ErrNoRows should return internal server error", func(t *testing.T) {

		srv := newHttpServer(pattern, handleGetUser, fakeDatabaseOptions{raiseError: errors.New("this is an error")})
		// Compose request and response
		request := newGetUserByIdRequest("7231ee05-b199-4364-83df-94fabb0c1a41")
		response := httptest.NewRecorder()

		// Send request
		srv.Handler.ServeHTTP(response, request)

		// Assert the response
		assertStatusCode(t, response.Code, http.StatusInternalServerError)
	})
}

// -- helpers

// newHttpServer is used to create a server with a single route configured. Which is useful for testing handlers.
func newHttpServer(pattern string, handler func(dbQuerier) http.Handler, dbOptions fakeDatabaseOptions) *http.Server {
	// TODO: An improvement would be to use the real server implementation to get more testing coverate.
	db := fakeDatabaseQueries{
		err:        dbOptions.raiseError,
		userExists: dbOptions.userExists,
	}

	mux := http.NewServeMux()
	mux.Handle(pattern, handler(db))
	srv := http.Server{
		Handler: mux,
	}
	return &srv
}

func newGetUserByIdRequest(id string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/api/users/"+id, nil)
	return req
}

func newCreateUserRequest(body io.Reader) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/api/users/", body)
	return req
}

func newDeleteUserRequest(id string) *http.Request {
	req, _ := http.NewRequest(http.MethodDelete, "/api/users/"+id, nil)
	return req
}


func assertStatusCode(t testing.TB, got, want int) {
	t.Helper()

	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}
}
