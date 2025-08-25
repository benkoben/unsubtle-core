package auth_client

import (
	"errors"
	"log"
	"net/http"
	"strings"
)

/*
Retrieves the bearer token from HTTP headers. If no Authorization header is found, or if the header is
not formated correctly an error is returned.
*/
func getBearerTokenFromHeaders(headers http.Header) (string, error) {
	headerVal := headers.Get("Authorization")
	if headerVal == "" {
		return "", errors.New("Authorization header is not set")
	}

	bearer := strings.Fields(headerVal)
	log.Println(bearer)
	if len(bearer) < 2 || bearer[0] != "Bearer" {
		return "", errors.New("invalid bearer token format")
	}

	return bearer[1], nil
}
