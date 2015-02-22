package auth

import (
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
	a := &AuthModule{}
	authboss.RegisterModule("auth", a)
}

type AuthModule struct {
	templates        render.Templates
	policies         []authboss.Validator
	isRememberLoaded bool
	isRecoverLoaded  bool
}

func (a *AuthModule) Initialize() (err error) {
	a.templates, err = render.LoadTemplates(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, tplLogin)
	if err != nil {
		return err
	}

	a.policies = authboss.FilterValidators(authboss.Cfg.Policies, authboss.Cfg.PrimaryID, authboss.StorePassword)

	a.isRememberLoaded = authboss.IsLoaded("remember")
	a.isRecoverLoaded = authboss.IsLoaded("recover")

	return nil
}

func (a *AuthModule) Routes() authboss.RouteTable {
	return authboss.RouteTable{
		"login":  a.loginHandlerFunc,
		"logout": a.logoutHandlerFunc,
	}
}

func (a *AuthModule) Storage() authboss.StorageOptions {
	return authboss.StorageOptions{
		authboss.Cfg.PrimaryID: authboss.String,
		authboss.StorePassword: authboss.String,
	}
}

func (a *AuthModule) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok {
			if halfAuthed, ok := ctx.SessionStorer.Get(authboss.SessionHalfAuthKey); !ok || halfAuthed == "false" {
				http.Redirect(w, r, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
			}
		}

		data := authboss.NewHTMLData("showRemember", a.isRememberLoaded, "showRecover", a.isRecoverLoaded)
		return a.templates.Render(ctx, w, r, tplLogin, data)
	case methodPOST:
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
			render.Redirect(ctx, w, r, "/", "", reason)
			return nil
		}

		key, _ := ctx.FirstPostFormValue(authboss.Cfg.PrimaryID)
		password, _ := ctx.FirstPostFormValue("password")

		errData := authboss.NewHTMLData(
			"error", "invalid username and/or password",
			authboss.Cfg.PrimaryID, key,
			"showRemember", a.isRememberLoaded,
			"showRecover", a.isRecoverLoaded,
		)

		if validationErrs := ctx.Validate(a.policies); len(validationErrs) > 0 {
			fmt.Fprintln(authboss.Cfg.LogWriter, "auth: form validation failed:", validationErrs.Map())
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		if err := validateCredentials(ctx, key, password); err != nil {
			fmt.Fprintln(authboss.Cfg.LogWriter, "auth: failed to validate credentials:", err)
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		authboss.Cfg.Callbacks.FireAfter(authboss.EventAuth, ctx)
		http.Redirect(w, r, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
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

func (a *AuthModule) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		http.Redirect(w, r, authboss.Cfg.AuthLogoutRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}
