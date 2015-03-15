package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
)

var (
	errOAuthStateValidation = errors.New("Could not validate oauth2 state param")
)

type OAuth2 struct{}

func init() {
	authboss.RegisterModule("oauth2", &OAuth2{})
}

func (o *OAuth2) Initialize() error {
	if authboss.Cfg.OAuth2Storer == nil {
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

		routes[init] = oauthInit
		routes[callback] = oauthCallback

		if len(authboss.Cfg.MountPath) > 0 {
			callback = path.Join(authboss.Cfg.MountPath, callback)
		}

		cfg.OAuth2Config.RedirectURL = authboss.Cfg.RootURL + callback
	}

	return routes
}

func (o *OAuth2) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		authboss.StoreEmail:          authboss.String,
		authboss.StoreOAuth2UID:      authboss.String,
		authboss.StoreOAuth2Provider: authboss.String,
		authboss.StoreOAuth2Token:    authboss.String,
		authboss.StoreOAuth2Refresh:  authboss.String,
		authboss.StoreOAuth2Expiry:   authboss.DateTime,
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

	var passAlongs []string
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs = append(passAlongs, fmt.Sprintf("%s=%s", k, val))
		}
	}
	if len(passAlongs) > 0 {
		state += ";" + strings.Join(passAlongs, ";")
	}

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
		if err := authboss.Cfg.Callbacks.FireAfter(authboss.EventOAuthFail, ctx); err != nil {
			return err
		}

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
	ctx.SessionStorer.Del(authboss.SessionOAuth2State)

	cfg, ok := authboss.Cfg.OAuth2Providers[provider]
	if !ok {
		return fmt.Errorf("OAuth2 provider %q not found", provider)
	}

	// Ensure request is genuine
	state := r.FormValue(authboss.FormValueOAuth2State)
	splState := strings.Split(state, ";")
	if len(splState) == 0 || splState[0] != sessState {
		return errOAuthStateValidation
	}

	// Get the code
	code := r.FormValue("code")
	token, err := exchanger(cfg.OAuth2Config, oauth2.NoContext, code)
	if err != nil {
		return fmt.Errorf("Could not validate oauth2 code: %v", err)
	}

	user, err := cfg.Callback(*cfg.OAuth2Config, token)
	if err != nil {
		return err
	}

	// OAuth2UID is required.
	uid, err := user.StringErr(authboss.StoreOAuth2UID)
	if err != nil {
		return err
	}

	user[authboss.StoreOAuth2UID] = uid
	user[authboss.StoreOAuth2Provider] = provider
	user[authboss.StoreOAuth2Expiry] = token.Expiry
	user[authboss.StoreOAuth2Token] = token.AccessToken
	if len(token.RefreshToken) != 0 {
		user[authboss.StoreOAuth2Refresh] = token.RefreshToken
	}

	if err = authboss.Cfg.OAuth2Storer.PutOAuth(uid, provider, user); err != nil {
		return err
	}

	// Fully log user in
	ctx.SessionStorer.Put(authboss.SessionKey, fmt.Sprintf("%s;%s", uid, provider))
	ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)

	if err = authboss.Cfg.Callbacks.FireAfter(authboss.EventOAuth, ctx); err != nil {
		return nil
	}

	redirect := authboss.Cfg.AuthLoginOKPath
	values := make(url.Values)
	if len(splState) > 0 {
		for _, arg := range splState[1:] {
			spl := strings.Split(arg, "=")
			switch spl[0] {
			case authboss.CookieRemember:
			case authboss.FormValueRedirect:
				redirect = spl[1]
			default:
				values.Set(spl[0], spl[1])
			}
		}
	}

	if len(values) > 0 {
		redirect = fmt.Sprintf("%s?%s", redirect, values.Encode())
	}

	http.Redirect(w, r, redirect, http.StatusFound)
	return nil
}
