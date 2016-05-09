package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/response"
)

var (
	errOAuthStateValidation = errors.New("Could not validate oauth2 state param")
)

// OAuth2 module
type OAuth2 struct {
	*authboss.Authboss
}

func init() {
	authboss.RegisterModule("oauth2", &OAuth2{})
}

// Initialize module
func (o *OAuth2) Initialize(ab *authboss.Authboss) error {
	o.Authboss = ab
	if o.OAuth2Storer == nil && o.OAuth2StoreMaker == nil {
		return errors.New("oauth2: need an OAuth2Storer")
	}
	return nil
}

// Routes for module
func (o *OAuth2) Routes() authboss.RouteTable {
	routes := make(authboss.RouteTable)

	for prov, cfg := range o.OAuth2Providers {
		prov = strings.ToLower(prov)

		init := fmt.Sprintf("/oauth2/%s", prov)
		callback := fmt.Sprintf("/oauth2/callback/%s", prov)

		routes[init] = o.oauthInit
		routes[callback] = o.oauthCallback

		if len(o.MountPath) > 0 {
			callback = path.Join(o.MountPath, callback)
		}

		cfg.OAuth2Config.RedirectURL = o.RootURL + callback
	}

	routes["/oauth2/logout"] = o.logout

	return routes
}

// Storage requirements
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

func (o *OAuth2) oauthInit(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))
	cfg, ok := o.OAuth2Providers[provider]
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

	passAlongs := make(map[string]string)
	for k, vals := range r.URL.Query() {
		for _, val := range vals {
			passAlongs[k] = val
		}
	}

	if len(passAlongs) > 0 {
		str, err := json.Marshal(passAlongs)
		if err != nil {
			return err
		}
		ctx.SessionStorer.Put(authboss.SessionOAuth2Params, string(str))
	} else {
		ctx.SessionStorer.Del(authboss.SessionOAuth2Params)
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

func (o *OAuth2) oauthCallback(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	provider := strings.ToLower(filepath.Base(r.URL.Path))

	sessState, err := ctx.SessionStorer.GetErr(authboss.SessionOAuth2State)
	ctx.SessionStorer.Del(authboss.SessionOAuth2State)
	if err != nil {
		return err
	}

	sessValues, ok := ctx.SessionStorer.Get(authboss.SessionOAuth2Params)
	// Don't delete this value from session immediately, callbacks use this too
	var values map[string]string
	if ok {
		if err := json.Unmarshal([]byte(sessValues), &values); err != nil {
			return err
		}
	}

	hasErr := r.FormValue("error")
	if len(hasErr) > 0 {
		if err := o.Callbacks.FireAfter(authboss.EventOAuthFail, ctx); err != nil {
			return err
		}

		return authboss.ErrAndRedirect{
			Err:        errors.New(r.FormValue("error_reason")),
			Location:   o.AuthLoginFailPath,
			FlashError: fmt.Sprintf("%s login cancelled or failed.", strings.Title(provider)),
		}
	}

	cfg, ok := o.OAuth2Providers[provider]
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
	token, err := exchanger(cfg.OAuth2Config, o.Config.ContextProvider(r), code)
	if err != nil {
		return fmt.Errorf("Could not validate oauth2 code: %v", err)
	}

	user, err := cfg.Callback(o.Config.ContextProvider(r), *cfg.OAuth2Config, token)
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

	if err = ctx.OAuth2Storer.PutOAuth(uid, provider, user); err != nil {
		return err
	}

	// Fully log user in
	ctx.SessionStorer.Put(authboss.SessionKey, fmt.Sprintf("%s;%s", uid, provider))
	ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)

	if err = o.Callbacks.FireAfter(authboss.EventOAuth, ctx); err != nil {
		return nil
	}

	ctx.SessionStorer.Del(authboss.SessionOAuth2Params)

	redirect := o.AuthLoginOKPath
	query := make(url.Values)
	for k, v := range values {
		switch k {
		case authboss.CookieRemember:
		case authboss.FormValueRedirect:
			redirect = v
		default:
			query.Set(k, v)
		}
	}

	if len(query) > 0 {
		redirect = fmt.Sprintf("%s?%s", redirect, query.Encode())
	}

	sf := fmt.Sprintf("Logged in successfully with %s.", strings.Title(provider))
	response.Redirect(ctx, w, r, redirect, sf, "", false)
	return nil
}

func (o *OAuth2) logout(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)

		response.Redirect(ctx, w, r, o.AuthLogoutOKPath, "You have logged out", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
