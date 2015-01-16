package auth

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"

	"gopkg.in/authboss.v0"

	"html/template"

	"io"
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
}

type Auth struct {
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	storer         authboss.Storer
	logoutRedirect string
	loginRedirect  string
	logger         io.Writer
	templates      *template.Template
	callbacks      *authboss.Callbacks

	isRememberLoaded bool
}

func (a *Auth) Initialize(c *authboss.Config) (err error) {
	if a.templates, err = template.ParseFiles(filepath.Join(c.ViewsPath, pageLogin)); err != nil {
		var loginTplBytes []byte
		if loginTplBytes, err = views_login_tpl_bytes(); err != nil {
			return err
		}

		if a.templates, err = template.New(pageLogin).Parse(string(loginTplBytes)); err != nil {
			return err
		}
	}

	a.routes = authboss.RouteTable{
		"login":  a.loginHandlerFunc,
		"logout": a.logoutHandlerFunc,
	}
	a.storageOptions = authboss.StorageOptions{
		attrUsername: authboss.String,
		attrPassword: authboss.String,
	}
	a.storer = c.Storer
	a.logoutRedirect = c.AuthLogoutRoute
	a.loginRedirect = c.AuthLoginSuccessRoute
	a.logger = c.LogWriter
	a.callbacks = c.Callbacks

	a.isRememberLoaded = authboss.IsLoaded("remember")

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
				http.Redirect(w, r, a.loginRedirect, http.StatusFound)
			}
		}

		a.templates.ExecuteTemplate(w, pageLogin, AuthPage{ShowRemember: a.isRememberLoaded})
	case methodPOST:
		u, ok := ctx.FirstPostFormValue("username")
		if !ok {
			fmt.Fprintln(a.logger, errors.New("auth: Expected postFormValue 'username' to be in the context"))
		}

		if err := a.callbacks.FireBefore(authboss.EventAuth, ctx); err != nil {
			w.WriteHeader(http.StatusForbidden)
			a.templates.ExecuteTemplate(w, pageLogin, AuthPage{err.Error(), u, a.isRememberLoaded})
		}

		p, ok := ctx.FirstPostFormValue("password")
		if !ok {
			fmt.Fprintln(a.logger, errors.New("auth: Expected postFormValue 'password' to be in the context"))
		}

		if err := a.authenticate(ctx, u, p); err != nil {
			fmt.Fprintln(a.logger, err)
			w.WriteHeader(http.StatusForbidden)
			a.templates.ExecuteTemplate(w, pageLogin, AuthPage{"invalid username and/or password", u, a.isRememberLoaded})
			return
		}

		ctx.SessionStorer.Put(authboss.SessionKey, u)
		a.callbacks.FireAfter(authboss.EventAuth, ctx)

		http.Redirect(w, r, a.loginRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *Auth) authenticate(ctx *authboss.Context, username, password string) error {
	var userInter interface{}
	var err error
	if userInter, err = a.storer.Get(username, nil); err != nil {
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
		http.Redirect(w, r, a.logoutRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
