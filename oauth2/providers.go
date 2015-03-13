package oauth2

import (
	"encoding/json"

	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
)

var (
	// GoogleEndpoint can be used to
	GoogleEndpoint = oauth2.Endpoint{
		AuthURL:  `https://accounts.google.com/o/oauth2/auth`,
		TokenURL: `https://accounts.google.com/o/oauth2/token`,
	}
	googleInfoEndpoint = `https://www.googleapis.com/userinfo/v2/me`
)

type googleMeResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// Google is a callback appropriate for use with Google's OAuth2 configuration.
func Google(cfg oauth2.Config, token *oauth2.Token) (cred authboss.OAuth2Credentials, err error) {
	client := cfg.Client(oauth2.NoContext, token)
	resp, err := client.Get(googleInfoEndpoint)
	if err != nil {
		return cred, err
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var jsonResp googleMeResponse
	if err = dec.Decode(&jsonResp); err != nil {
		return cred, err
	}

	cred.UID = jsonResp.ID
	cred.Email = jsonResp.Email
	return cred, nil
}
