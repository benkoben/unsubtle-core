package auth

import (
    "testing"
    "time"
    "net/http"
    "fmt"

	"github.com/google/uuid"
)


func TestMakeAndValidateJWT(t *testing.T) {
	tests := []struct {
		name                 string
		userID               uuid.UUID
		tokenSecret          string        // Secret to use to sign the new token with
		expiresIn            time.Duration // How long the token should be valid
		alterSecret          bool          // Wether or not the tokenSecret should be altered between MakeJWT and ValidateJWT (assertion of token signature's secret)
		waitBeforeValidation time.Duration // How long the test should wait between MakeJWT and ValidateJWT (assertion of token expiration date)
		wantCreationErr      bool
		wantValidationErr    bool
	}{
		{
			name:                 "valid token",
			userID:               uuid.New(),
			tokenSecret:          "mySuperSecretSecret",
			expiresIn:            time.Hour,
			alterSecret:          false,
			waitBeforeValidation: 0,
			wantCreationErr:      false,
			wantValidationErr:    false,
		},
		{
			name:                 "invalid duration",
			userID:               uuid.New(),
			tokenSecret:          "mySuperSecretSecret",
			expiresIn:            0,
			alterSecret:          false,
			waitBeforeValidation: 0,
			wantCreationErr:      true,
			wantValidationErr:    true,
		},
		{
			name:                 "has expired",
			userID:               uuid.New(),
			tokenSecret:          "mySuperSecretSecret",
			expiresIn:            time.Second,
			alterSecret:          false,
			waitBeforeValidation: time.Second * 5,
			wantCreationErr:      false,
			wantValidationErr:    true,
		},
		{
			name:                 "mismatched token secret",
			userID:               uuid.New(),
			tokenSecret:          "mySuperSecretSecret",
			expiresIn:            time.Second,
			alterSecret:          true,
			waitBeforeValidation: 0,
			wantCreationErr:      false,
			wantValidationErr:    true,
		},
	}

	for _, tt := range tests {
		tokenString, tokenStringErr := MakeJWT(tt.userID, tt.tokenSecret, tt.expiresIn)
		if tt.wantCreationErr == true && tokenStringErr == nil {
			t.Errorf("%s -> MakeJWT(%v, %s, %v) expected and error but none was received", tt.name, tt.userID, tt.tokenSecret, tt.expiresIn)
		}

		if tt.alterSecret {
			tt.tokenSecret = "altered_" + tt.tokenSecret
		}

		time.Sleep(tt.waitBeforeValidation)
		// Validate the token
		userID, err := ValidateJWT(tokenString, tt.tokenSecret)
		if tt.wantValidationErr == true && err == nil {
			t.Errorf("%s -> ValidateJWT(%v, %s, %v) expected and error but none was received", tt.name, tt.userID, tt.tokenSecret, tt.expiresIn)
		}
        
        // If no errors as expected then we validate the the returned userID matches the tt.userID
        if !tt.wantCreationErr && !tt.wantValidationErr {
		    if userID != tt.userID {
		    	t.Errorf("%s -> ValidateJWT(%v, %s, %v) got %v, want %v", tt.name, tt.userID, tt.tokenSecret, tt.expiresIn, userID, tt.userID)
		    }
        }
	}
}

func TestGetBearerToken(t *testing.T) {
    t.Run("valid header", func(t *testing.T) {
        headers := http.Header{}
        jwt, _ := MakeJWT(uuid.New(), "secret", time.Hour)
        headers.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))

        if token, gotErr := GetBearerToken(headers); gotErr != nil {
            t.Errorf("GetBearerToken(%v) got an error but expected none", headers)
        } else if token == "" {
            t.Errorf("GetBearerToken(%v) got %v, want %v", headers, token, jwt)
        } else if jwt != token {
            t.Errorf("GetBearerToken(%v) got %v, want %v", headers, token, jwt)
        }
    })

    t.Run("invalid header format", func(t *testing.T) {
        headers := http.Header{}
        jwt, _ := MakeJWT(uuid.New(), "secret", time.Hour)
        headers.Set("Authorization", fmt.Sprintf("BEARER %s", jwt))
        if _, gotErr := GetBearerToken(headers); gotErr == nil {
            t.Errorf("GetBearerToken(%v) expected and error but received none", headers)
        }
    })

    t.Run("missing header", func(t *testing.T) {
        headers := http.Header{}
        if _, gotErr := GetBearerToken(headers); gotErr == nil {
            t.Errorf("GetBearerToken(%v) expected and error but received none", headers)
        }
    })
}

