package authboss

import (
	"net/url"

	"golang.org/x/oauth2"
)

// OAuth2Provider is the entire configuration
// required to authenticate with this provider.
//
// The OAuth2Config does not need a redirect URL because it will
// be automatically created by the
type OAuthProvider struct {
	OAuth2Config     *oauth2.Config
	AdditionalParams url.Values
	Callback         func(oauth2.Config, *oauth2.Token) (OAuth2Credentials, error)
}

// OAuth2Credentials are used to store in the database.
// Email is optional
type OAuth2Credentials struct {
	UID   string
	Email string
}
