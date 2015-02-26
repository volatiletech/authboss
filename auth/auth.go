package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/render"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	tplLogin = "login.tpl"
)

func init() {
	a := &Auth{}
	authboss.RegisterModule("auth", a)
}

type Auth struct {
	templates render.Templates
}

func (a *Auth) Initialize() (err error) {
	if authboss.Cfg.Storer == nil {
		return errors.New("auth: Need a Storer.")
	}

	if len(authboss.Cfg.XSRFName) == 0 {
		return errors.New("auth: XSRFName must be set")
	}

	if authboss.Cfg.XSRFMaker == nil {
		return errors.New("auth: XSRFMaker must be defined")
	}

	a.templates, err = render.LoadTemplates(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, tplLogin)
	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"/login":  a.loginHandlerFunc,
		"/logout": a.logoutHandlerFunc,
	}
}

func (a *Auth) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		authboss.Cfg.PrimaryID: authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok {
			if halfAuthed, ok := ctx.SessionStorer.Get(authboss.SessionHalfAuthKey); !ok || halfAuthed == "false" {
				http.Redirect(w, r, authboss.Cfg.AuthLoginOKPath, http.StatusFound)
				return nil
			}
		}

		data := authboss.NewHTMLData(
			"showRemember", authboss.IsLoaded("remember"),
			"showRecover", authboss.IsLoaded("recover"),
			"primaryID", authboss.Cfg.PrimaryID,
			"primaryIDValue", "",
		)
		return a.templates.Render(ctx, w, r, tplLogin, data)
	case methodPOST:
		key, _ := ctx.FirstPostFormValue(authboss.Cfg.PrimaryID)
		password, _ := ctx.FirstPostFormValue("password")

		errData := authboss.NewHTMLData(
			"error", fmt.Sprintf("invalid %s and/or password", authboss.Cfg.PrimaryID),
			"primaryID", authboss.Cfg.PrimaryID,
			"primaryIDValue", key,
			"showRemember", authboss.IsLoaded("remember"),
			"showRecover", authboss.IsLoaded("recover"),
		)

		policies := authboss.FilterValidators(authboss.Cfg.Policies, authboss.Cfg.PrimaryID, authboss.StorePassword)
		if validationErrs := ctx.Validate(policies); len(validationErrs) > 0 {
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		if err := validateCredentials(ctx, key, password); err != nil {
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		interrupted, err := authboss.Cfg.Callbacks.FireBefore(authboss.EventAuth, ctx)
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
			render.Redirect(ctx, w, r, authboss.Cfg.AuthLoginFailPath, "", reason)
			return nil
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)

		if err := authboss.Cfg.Callbacks.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}
		http.Redirect(w, r, authboss.Cfg.AuthLoginOKPath, http.StatusFound)
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
		http.Redirect(w, r, authboss.Cfg.AuthLogoutOKPath, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
