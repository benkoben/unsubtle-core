package auth_client

import (
	"context"
	"errors"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"time"
)

const (
	tokenExpiredError        = "token expired"
	tokenIssuedInFutureError = "token issued in the future"
	tokenInvalidClaimsError  = "token invalid claims"
)

type authClient interface {
	SignInWithEmailPassword(email, password string) (Session, error)
	RefreshToken(refreshToken string) (Session, error)
	GetJwksUri() (string, error)
}

type Client struct {
	authClient authClient
	Jwks       keyfunc.Keyfunc
}

// RefreshToken wraps around authClient.RefreshToken to return a auth_client.Session
func (c Client) RefreshToken(refreshToken string) (*Session, error) {
	session, err := c.authClient.RefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

// SignInWithEmailPassword wraps around authClient.SignInWithEmailPassword and parses the bearer token to enrich the session before returning it.
func (c Client) SignInWithEmailPassword(email, password string) (*Session, error) {
	session, err := c.authClient.SignInWithEmailPassword(email, password)
	if err != nil {
		return nil, err
	}

	// Add more data to returned session
	token, err := c.parseJwt(*session.AccessToken)
	if err != nil {
		return nil, err
	}
	if err := session.setEmailFromToken(token); err != nil {
		return nil, err
	}
	if err := session.setUserIdFromToken(token); err != nil {
		return nil, err
	}
	return &session, nil
}

func NewClient(client authClient) (*Client, error) {
	if client == nil {
		return nil, errors.New("auth client is nil")
	}

	jwksUri, err := client.GetJwksUri()
	if err != nil {
		return nil, err
	}

	jwksKeyfunc, err := keyfunc.NewDefault([]string{jwksUri})
	if err != nil {
		log.Fatalf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
		return nil, err
	}

	return &Client{
		authClient: client,
		Jwks:       jwksKeyfunc,
	}, nil
}

// ValidateToken can be used as http.Handler middleware to validate the request token
func (c Client) ValidateToken(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := cookie.Value
		tokenObj, err := c.parseJwt(tokenStr)
		if err != nil {
			log.Println("cannot parse token", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		session, err := newSessionFromToken(tokenObj)
		if err != nil {
			// The only case where an error is returned is
			// when there is no email claim in the Jwt token.
			// Meaning it was either tampered with, or we have a bug.
			// Either way the client is not authorized.
			log.Println("cannot parse session", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}

		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c Client) parseJwt(tokenStr string) (*jwt.Token, error) {
	// Validate key
	token, err := jwt.Parse(tokenStr, c.Jwks.Keyfunc, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate the before and after
	now := time.Now().Unix()
	issuedAt, issuedAtErr := token.Claims.GetIssuedAt()
	expireAt, expireAtErr := token.Claims.GetExpirationTime()

	if expireAtErr != nil || issuedAtErr != nil {
		return nil, errors.New(tokenInvalidClaimsError)
	}

	if issuedAt.Unix()-60 >= now { // Remove 60 second to account for different in time between server and client
		return nil, errors.New(tokenIssuedInFutureError)
	}

	if expireAt.Unix() <= now {
		return nil, errors.New(tokenExpiredError)
	}

	return token, nil
}
