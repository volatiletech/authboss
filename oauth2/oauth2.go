package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
)

var (
	errOAuthStateValidation = errors.New("Could not validate oauth2 state param")
)

// OAuth2Storer is required to do OAuth2 storing.
type OAuth2Storer interface {
	authboss.Storer
	// NewOrUpdate should retrieve the user if he already exists, or create
	// a new one. The key is composed of the provider:UID together and is stored
	// in the authboss.StoreUsername field.
	OAuth2NewOrUpdate(key string, attr authboss.Attributes) error
}

type OAuth2 struct{}

func init() {
	authboss.RegisterModule("oauth2", &OAuth2{})
}

func (o *OAuth2) Initialize() error {
	if _, ok := authboss.Cfg.Storer.(OAuth2Storer); !ok {
		return errors.New("oauth2: need an OAuth2Storer")
	}
	return nil
}

func (o *OAuth2) Routes() authboss.RouteTable {
	routes := make(authboss.RouteTable)

	for prov, cfg := range authboss.Cfg.OAuth2Providers {
		prov = strings.ToLower(prov)

		init := fmt.Sprintf("/oauth2/%s", prov)
		callback := fmt.Sprintf("/oauth2/callback/%s", prov)

		if len(authboss.Cfg.MountPath) > 0 {
			init = path.Join(authboss.Cfg.MountPath, init)
			callback = path.Join(authboss.Cfg.MountPath, callback)
		}

		routes[init] = oauthInit
		routes[callback] = oauthCallback

		cfg.OAuth2Config.RedirectURL = authboss.Cfg.RootURL + callback
	}

	return routes
}

func (o *OAuth2) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		authboss.StoreUsername:      authboss.String,
		authboss.StoreEmail:         authboss.String,
		authboss.StoreOAuth2Token:   authboss.String,
		authboss.StoreOAuth2Refresh: authboss.String,
		authboss.StoreOAuth2Expiry:  authboss.DateTime,
	}
}

func oauthInit(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	cfg, ok := authboss.Cfg.OAuth2Providers[provider]
	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	random := make([]byte, 32)
	_, err := rand.Read(random)
	if err != nil {
		return err
	}

	state := base64.URLEncoding.EncodeToString(random)
	ctx.SessionStorer.Put(authboss.SessionOAuth2State, state)

	url := cfg.OAuth2Config.AuthCodeURL(state)

	extraParams := cfg.AdditionalParams.Encode()
	if len(extraParams) > 0 {
		url = fmt.Sprintf("%s&%s", url, extraParams)
	}

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

// for testing
var exchanger = (*oauth2.Config).Exchange

func oauthCallback(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		return authboss.ErrAndRedirect{
			Err:        errors.New(r.FormValue("error_reason")),
			Location:   authboss.Cfg.AuthLoginFailPath,
			FlashError: fmt.Sprintf("%s login cancelled or failed.", strings.Title(provider)),
		}
	}

	sessState, err := ctx.SessionStorer.GetErr(authboss.SessionOAuth2State)
	if err != nil {
		return err
	}

	cfg, ok := authboss.Cfg.OAuth2Providers[provider]
	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	// Ensure request is genuine
	state := r.FormValue("state")
	if state != sessState {
		return errOAuthStateValidation
	}

	// Get the code
	code := r.FormValue("code")
	token, err := exchanger(cfg.OAuth2Config, oauth2.NoContext, code)
	if err != nil {
		return fmt.Errorf("Could not validate oauth2 code: %v", err)
	}

	credentials, err := cfg.Callback(*cfg.OAuth2Config, token)
	if err != nil {
		return err
	}

	// User is authenticated
	key := fmt.Sprintf("%s:%s", provider, credentials.UID)
	user := make(authboss.Attributes)
	user[authboss.StoreUsername] = key
	user[authboss.StoreOAuth2Expiry] = token.Expiry
	user[authboss.StoreOAuth2Token] = token.AccessToken
	if len(token.RefreshToken) != 0 {
		user[authboss.StoreOAuth2Refresh] = token.RefreshToken
	}
	if len(credentials.Email) > 0 {
		user[authboss.StoreEmail] = credentials.Email
	}

	// Log user in
	ctx.SessionStorer.Put(authboss.SessionKey, key)

	storer := authboss.Cfg.Storer.(OAuth2Storer)
	if err = storer.OAuth2NewOrUpdate(key, user); err != nil {
		return err
	}

	http.Redirect(w, r, authboss.Cfg.AuthLoginOKPath, http.StatusFound)
	return nil
}
