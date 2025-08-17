package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase-community/gotrue-go/types"
	"github.com/supabase-community/supabase-go"
	"log"
	"net/http"
	"strings"
	"time"
)

const SessionContextKey = "session"

type Client struct {
	*supabase.Client
	Jwks keyfunc.Keyfunc
}

func NewClient(url, key string) (*Client, error) {
	supabaseClient, err := supabase.NewClient(url, key, &supabase.ClientOptions{})
	if err != nil {
		fmt.Println("cannot initalize client", err)
	}

	jwksUri := fmt.Sprintf("%s/%s/.well-known/jwks.json", url, supabase.AUTH_URL)
	jwksKeyfunc, err := keyfunc.NewDefault([]string{jwksUri})
	if err != nil {
		log.Fatalf("Failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
		return nil, err
	}

	return &Client{
		supabaseClient,
		jwksKeyfunc,
	}, nil
}

// LoginWithEmailAndPassword logs in a user
func (c Client) LoginWithEmailAndPassword(email, password string) (types.Session, error) {
	return c.Client.SignInWithEmailPassword(email, password)
}

func (c Client) ValidateTokenFromHeader(header http.Header) (*types.Session, error) {
	if header == nil {
		return nil, errors.New("no header provided")
	}

	tokenStr, err := getBearerTokenFromHeaders(header)
	if err != nil {
		return nil, err
	}

	return c.parseJwt(tokenStr)
}

// ValidateToken can be used as http.Handler middleware to validate the request token
func (c Client) ValidateTokenFromHandler(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, err := c.ValidateTokenFromHeader(r.Header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), SessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c Client) parseJwt(tokenStr string) (*types.Session, error) {
	// Validate key
	token, err := jwt.Parse(tokenStr, c.Jwks.Keyfunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate the before and after
	now := time.Now().Unix()
	issuedAt, issuedAtOK := token.Claims.(jwt.MapClaims)["issued_at"].(int64)
	expireAt, expireAtOk := token.Claims.(jwt.MapClaims)["expire_at"].(int64)
	if !expireAtOk || !issuedAtOK {
		return nil, errors.New("invalid token claims")
	}

	if issuedAt > now {
		return nil, errors.New("token issued in the future")
	}

	if expireAt < now {
		return nil, errors.New("token expired")
	}

	// Validate the signing key
	alg := strings.ToLower(token.Method.Alg())
	if alg != "RS256" {
		return nil, errors.New("invalid jwt algorithm")
	}

	session := &types.Session{}
	if err := json.Unmarshal([]byte(token.Raw), session); err != nil {
		return nil, err
	}
	return session, nil
}
