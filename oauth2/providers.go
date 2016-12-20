package oauth2

import (
	"encoding/json"
	"net/http"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"gopkg.in/authboss.v1"
)

const (
	googleInfoEndpoint   = `https://www.googleapis.com/userinfo/v2/me`
	facebookInfoEndpoint = `https://graph.facebook.com/me?fields=name,email`
)

type googleMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// testing
var clientGet = (*http.Client).Get

// Google is a callback appropriate for use with Google's OAuth2 configuration.
func Google(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (authboss.Attributes, error) {
	client := cfg.Client(ctx, token)
	resp, err := clientGet(client, googleInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var jsonResp googleMeResponse
	if err = dec.Decode(&jsonResp); err != nil {
		return nil, err
	}

	return authboss.Attributes{
		authboss.StoreOAuth2UID: jsonResp.ID,
		authboss.StoreEmail:     jsonResp.Email,
	}, nil
}

type facebookMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Facebook is a callback appropriate for use with Facebook's OAuth2 configuration.
func Facebook(ctx context.Context, cfg oauth2.Config, token *oauth2.Token) (authboss.Attributes, error) {
	client := cfg.Client(ctx, token)
	resp, err := clientGet(client, facebookInfoEndpoint)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var jsonResp facebookMeResponse
	if err = dec.Decode(&jsonResp); err != nil {
		return nil, err
	}

	return authboss.Attributes{
		"name":                  jsonResp.Name,
		authboss.StoreOAuth2UID: jsonResp.ID,
		authboss.StoreEmail:     jsonResp.Email,
	}, nil
}
