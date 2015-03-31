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
	templates response.Templates
}

// Initialize module
func (a *Auth) Initialize() (err error) {
	if authboss.a.Storer == nil {
		return errors.New("auth: Need a Storer")
	}

	if len(authboss.a.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if authboss.a.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	a.templates, err = response.LoadTemplates(authboss.a.Layout, authboss.a.ViewsPath, tplLogin)
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
		authboss.a.PrimaryID:   authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok {
			if halfAuthed, ok := ctx.SessionStorer.Get(authboss.SessionHalfAuthKey); !ok || halfAuthed == "false" {
				//http.Redirect(w, r, authboss.a.AuthLoginOKPath, http.StatusFound, true)
				response.Redirect(ctx, w, r, authboss.a.AuthLoginOKPath, "", "", true)
				return nil
			}
		}

		data := authboss.NewHTMLData(
			"showRemember", authboss.IsLoaded("remember"),
			"showRecover", authboss.IsLoaded("recover"),
			"primaryID", authboss.a.PrimaryID,
			"primaryIDValue", "",
		)
		return a.templates.Render(ctx, w, r, tplLogin, data)
	case methodPOST:
		key, _ := ctx.FirstPostFormValue(authboss.a.PrimaryID)
		password, _ := ctx.FirstPostFormValue("password")

		errData := authboss.NewHTMLData(
			"error", fmt.Sprintf("invalid %s and/or password", authboss.a.PrimaryID),
			"primaryID", authboss.a.PrimaryID,
			"primaryIDValue", key,
			"showRemember", authboss.IsLoaded("remember"),
			"showRecover", authboss.IsLoaded("recover"),
		)

		policies := authboss.FilterValidators(authboss.a.Policies, authboss.a.PrimaryID, authboss.StorePassword)
		if validationErrs := ctx.Validate(policies); len(validationErrs) > 0 {
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		if err := validateCredentials(ctx, key, password); err != nil {
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		interrupted, err := authboss.a.Callbacks.FireBefore(authboss.EventAuth, ctx)
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
			response.Redirect(ctx, w, r, authboss.a.AuthLoginFailPath, "", reason, false)
			return nil
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)

		if err := authboss.a.Callbacks.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}
		response.Redirect(ctx, w, r, authboss.a.AuthLoginOKPath, "", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func validateCredentials(ctx *authboss.Context, key, password string) error {
	if err := ctx.LoadUser(key); err != nil {
		return err
	}

	actualPassword, err := ctx.User.StringErr(authboss.StorePassword)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return err
	}

	return nil
}

func (a *Auth) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		ctx.CookieStorer.Del(authboss.CookieRemember)
		ctx.SessionStorer.Del(authboss.SessionLastAction)

		response.Redirect(ctx, w, r, authboss.a.AuthLogoutOKPath, "You have logged out", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
