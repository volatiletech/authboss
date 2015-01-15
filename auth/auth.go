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
}

type Auth struct {
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	storer         authboss.Storer
	logoutRedirect string
	loginRedirect  string
	logger         io.Writer
	templates      *template.Template
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

	return nil
}

func (a *Auth) Routes() authboss.RouteTable {
	return a.routes
}

func (a *Auth) Storage() authboss.StorageOptions {
	return a.storageOptions
}

func (a *Auth) loginHandlerFunc(c *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		a.templates.ExecuteTemplate(w, pageLogin, nil)
	case methodPOST:
		u := r.PostFormValue("username")
		p := r.PostFormValue("password")

		if err := a.authenticate(u, p); err != nil {
			fmt.Fprintln(a.logger, err)
			w.WriteHeader(http.StatusForbidden)
			a.templates.ExecuteTemplate(w, pageLogin, AuthPage{"invalid username and/or password", u})
			return
		}
		http.Redirect(w, r, a.loginRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *Auth) authenticate(username, password string) error {
	var userInter interface{}
	var err error
	if userInter, err = a.storer.Get(username, nil); err != nil {
		return err
	}

	userAttrs := authboss.Unbind(userInter)

	pwdIntf, ok := userAttrs[attrPassword]
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

func (a *Auth) logoutHandlerFunc(c *authboss.Context, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		http.Redirect(w, r, a.logoutRedirect, http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
