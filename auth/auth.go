// Package auth implements password based user logins.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/response"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin = "login.html.tpl"
)

func init() {
	authboss.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authboss.Authboss
	templates response.Templates
}

// Initialize module
func (a *Auth) Initialize(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if a.Storer == nil {
		return errors.New("auth: Need a Storer")
	}

	if len(a.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if a.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	a.templates, err = response.LoadTemplates(a.Authboss, a.Layout, a.ViewsPath, tplLogin)
	if err != nil {
		return err
	}

	return nil
}

// Routes for the module
func (a *Auth) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/login":  a.loginHandlerFunc,
		"/logout": a.logoutHandlerFunc,
	}
}

// Storage requirements
func (a *Auth) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		a.PrimaryID:            authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		data := authboss.NewHTMLData(
			"showRemember", a.IsLoaded("remember"),
			"showRecover", a.IsLoaded("recover"),
			"showRegister", a.IsLoaded("register"),
			"primaryID", a.PrimaryID,
			"primaryIDValue", "",
		)
		return a.templates.Render(ctx, w, r, tplLogin, data)
	case methodPOST:
		key := r.FormValue(a.PrimaryID)
		password := r.FormValue("password")

		errData := authboss.NewHTMLData(
			"error", fmt.Sprintf("invalid %s and/or password", a.PrimaryID),
			"primaryID", a.PrimaryID,
			"primaryIDValue", key,
			"showRemember", a.IsLoaded("remember"),
			"showRecover", a.IsLoaded("recover"),
			"showRegister", a.IsLoaded("register"),
		)

		if valid, err := validateCredentials(ctx, key, password); err != nil {
			errData["error"] = "Internal server error"
			fmt.Fprintf(a.LogWriter, "auth: validate credentials failed: %v\n", err)
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		} else if !valid {
			if err := a.Callbacks.FireAfter(authboss.EventAuthFail, ctx); err != nil {
				fmt.Fprintf(a.LogWriter, "EventAuthFail callback error'd out: %v\n", err)
			}
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		interrupted, err := a.Callbacks.FireBefore(authboss.EventAuth, ctx)
		if err != nil {
			return err
		} else if interrupted != authboss.InterruptNone {
			var reason string
			switch interrupted {
			case authboss.InterruptAccountLocked:
				reason = "Your account has been locked."
			case authboss.InterruptAccountNotConfirmed:
				reason = "Your account has not been confirmed."
			}
			response.Redirect(ctx, w, r, a.AuthLoginFailPath, "", reason, false)
			return nil
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)
		ctx.Values = map[string]string{authboss.CookieRemember: r.FormValue(authboss.CookieRemember)}

		if err := a.Callbacks.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}
		response.Redirect(ctx, w, r, a.AuthLoginOKPath, "", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func validateCredentials(ctx *authboss.Context, key, password string) (bool, error) {
	if err := ctx.LoadUser(key); err == authboss.ErrUserNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	actualPassword, err := ctx.User.StringErr(authboss.StorePassword)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

func (a *Auth) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)

		response.Redirect(ctx, w, r, a.AuthLogoutOKPath, "You have logged out", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
