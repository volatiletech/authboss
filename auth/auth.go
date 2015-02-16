package auth

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/views"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"

	pageLogin = "login.tpl"

	attrUsername = "username"
	attrPassword = "password"
)

func init() {
	a := &Auth{}
	authboss.RegisterModule("auth", a)
}

type AuthPage struct {
	Error    string
	Username string

	ShowRemember bool
	ShowRecover  bool

	FlashSuccess string
	FlashError   string

	XSRFName  string
	XSRFToken string
}

type Auth struct {
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	templates      map[string]*template.Template

	isRememberLoaded bool
	isRecoverLoaded  bool
}

func (a *Auth) Initialize() (err error) {
	if a.templates, err = views.Get(authboss.Cfg.Layout, authboss.Cfg.ViewsPath, pageLogin); err != nil {
		return err
	}

	a.routes = authboss.RouteTable{
		"login":  a.loginHandlerFunc,
		"logout": a.logoutHandlerFunc,
	}
	a.storageOptions = authboss.StorageOptions{
		attrUsername: authboss.String,
		attrPassword: authboss.String,
	}

	a.isRememberLoaded = authboss.IsLoaded("remember")
	a.isRecoverLoaded = authboss.IsLoaded("recover")

	return nil
}

func (a *Auth) Routes() authboss.RouteTable {
	return a.routes
}

func (a *Auth) Storage() authboss.StorageOptions {
	return a.storageOptions
}

func (a *Auth) loginHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		if _, ok := ctx.SessionStorer.Get(authboss.SessionKey); ok {
			if halfAuthed, ok := ctx.SessionStorer.Get(authboss.HalfAuthKey); !ok || halfAuthed == "false" {
				http.Redirect(w, r, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
			}
		}

		page := AuthPage{
			ShowRemember: a.isRememberLoaded,
			ShowRecover:  a.isRecoverLoaded,
			XSRFName:     authboss.Cfg.XSRFName,
			XSRFToken:    authboss.Cfg.XSRFMaker(w, r),
		}

		if msg, ok := ctx.SessionStorer.Get(authboss.FlashSuccessKey); ok {
			page.FlashSuccess = msg
			ctx.SessionStorer.Del(authboss.FlashSuccessKey)
		}

		tpl := a.templates[pageLogin]
		tpl.Execute(w, page)
	case methodPOST:
		u, ok := ctx.FirstPostFormValue("username")
		if !ok {
			fmt.Fprintln(authboss.Cfg.LogWriter, errors.New("auth: Expected postFormValue 'username' to be in the context"))
		}

		if err := authboss.Cfg.Callbacks.FireBefore(authboss.EventAuth, ctx); err != nil {
			w.WriteHeader(http.StatusForbidden)

			tpl := a.templates[pageLogin]
			tpl.ExecuteTemplate(w, tpl.Name(), AuthPage{
				Error:        err.Error(),
				Username:     u,
				ShowRemember: a.isRememberLoaded,
				ShowRecover:  a.isRecoverLoaded,
				XSRFName:     authboss.Cfg.XSRFName,
				XSRFToken:    authboss.Cfg.XSRFMaker(w, r),
			})
		}

		p, ok := ctx.FirstPostFormValue("password")
		if !ok {
			fmt.Fprintln(authboss.Cfg.LogWriter, errors.New("auth: Expected postFormValue 'password' to be in the context"))
		}

		if err := a.authenticate(ctx, u, p); err != nil {
			fmt.Fprintln(authboss.Cfg.LogWriter, err)
			w.WriteHeader(http.StatusForbidden)
			tpl := a.templates[pageLogin]
			tpl.ExecuteTemplate(w, tpl.Name(), AuthPage{
				Error:        "invalid username and/or password",
				Username:     u,
				ShowRemember: a.isRememberLoaded,
				ShowRecover:  a.isRecoverLoaded,
				XSRFName:     authboss.Cfg.XSRFName,
				XSRFToken:    authboss.Cfg.XSRFMaker(w, r),
			})
			return
		}

		ctx.SessionStorer.Put(authboss.SessionKey, u)
		authboss.Cfg.Callbacks.FireAfter(authboss.EventAuth, ctx)

		http.Redirect(w, r, authboss.Cfg.AuthLoginSuccessRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *Auth) authenticate(ctx *authboss.Context, username, password string) error {
	var userInter interface{}
	var err error
	if userInter, err = authboss.Cfg.Storer.Get(username, nil); err != nil {
		return err
	}

	ctx.User = authboss.Unbind(userInter)

	pwdIntf, ok := ctx.User[attrPassword]
	if !ok {
		return errors.New("auth: User attributes did not include a password.")
	}

	pwd, ok := pwdIntf.(string)
	if !ok {
		return errors.New("auth: User password was not a string somehow.")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pwd), []byte(password)); err != nil {
		return errors.New("invalid password")
	}

	return nil
}

func (a *Auth) logoutHandlerFunc(ctx *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		ctx.SessionStorer.Del(authboss.SessionKey)
		http.Redirect(w, r, authboss.Cfg.AuthLogoutRoute, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
