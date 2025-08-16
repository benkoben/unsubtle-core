package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

/*
MakeJWT creates a new signed JWT token. If there is an error with signing the token an error is returned.
*/
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	if expiresIn == 0 {
		return "", errors.New("expiresIn cannot be zero")
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "unsubtle-core", // TODO: perhaps this should be a more dynamic value if we are going to run containers.
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

/*
ValidateJWT validates the tokenString with tokenSecret and returns the subject. Any verification errors are returned.
*/
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}
	// Validate that the token is signed with the correct tokenSecret
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		log.Println("received invalid token (not signed with trusted secret): ", err)
		return uuid.UUID{}, err
	}

	userID, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("could not get subject: %w", err)
	}

	if userID == "" {
		return uuid.UUID{}, errors.New("userID is empty")
	}

	// Validates the UUID format as well
	return uuid.Parse(userID)
}

/*
Retrieves the bearer token from HTTP headers. If no Authorization header is found, or if the header is
not formated correctly an error is returned.
*/
func GetBearerToken(headers http.Header) (string, error) {
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

/*
Generates a new 256 bit string
*/
func MakeRefreshToken() (string, error) {
	bToken := make([]byte, 1<<5)
	random := rand.New(rand.NewSource(time.Now().Unix()))
	n, _ := random.Read(bToken)
	return hex.EncodeToString(bToken[:n]), nil
}
