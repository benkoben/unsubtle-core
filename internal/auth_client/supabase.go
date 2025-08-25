package auth_client

import (
	"fmt"
	"github.com/supabase-community/supabase-go"
	"log"
	"net/url"
)

type SupabaseClient struct {
	*supabase.Client
	apiUrl string
}

func (c SupabaseClient) GetJwksUri() (string, error) {
	jwksUrl := fmt.Sprintf("%s%s/.well-known/jwks.json", c.apiUrl, supabase.AUTH_URL)

	log.Printf("Using JWKS Uri: %s", jwksUrl)

	return jwksUrl, nil
}

func NewSupabaseClient(apiUrl, apiKey string) (*SupabaseClient, error) {

	// Validate if the uri is valid
	if _, err := url.Parse(apiUrl); err != nil {
		return nil, err
	}

	client, err := supabase.NewClient(apiUrl, apiKey, nil)
	if err != nil {
		return nil, err
	}
	return &SupabaseClient{
		client,
		apiUrl,
	}, nil
}

func (c *SupabaseClient) SignInWithEmailPassword(email, password string) (Session, error) {
	supabaseSession, err := c.Client.SignInWithEmailPassword(email, password)
	if err != nil {
		return Session{}, err
	}
	return Session{
		AccessToken:  &supabaseSession.AccessToken,
		RefreshToken: &supabaseSession.RefreshToken,
	}, nil
}

func (c *SupabaseClient) RefreshToken(refreshToken string) (Session, error) {
	supabaseSession, err := c.Client.RefreshToken(refreshToken)
	if err != nil {
		return Session{}, err
	}

	return Session{
		AccessToken:  &supabaseSession.AccessToken,
		RefreshToken: &supabaseSession.RefreshToken,
	}, nil
}
