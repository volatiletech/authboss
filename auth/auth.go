package auth

import (
	"errors"
	"net/http"
	"path"
	"path/filepath"

	"gopkg.in/authboss.v0"

	"html/template"
	"io/ioutil"

	"bytes"
	"github.com/davecgh/go-spew/spew"
	"io"
	"log"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"
)

var errAuthFailed = errors.New("invalid username and/or password")

func init() {
	a := &Auth{}
	authboss.RegisterModule("auth", a)
}

type Auth struct {
	routes         authboss.RouteTable
	storageOptions authboss.StorageOptions
	users          authboss.Storer
	loginPage      *bytes.Buffer
	logoutRedirect string
	logger         io.Writer
}

func (a *Auth) Initialize(c *authboss.Config) (err error) {
	var data []byte

	if data, err = ioutil.ReadFile(filepath.Join(c.ViewsPath, "login.tpl")); err != nil {
		if data, err = views_login_tpl_bytes(); err != nil {
			return err
		}
	}

	var tpl *template.Template
	if tpl, err = template.New("login.tpl").Parse(string(data)); err != nil {
		return err
	} else {
		a.loginPage = &bytes.Buffer{}
		if err = tpl.Execute(a.loginPage, nil); err != nil {
			return err
		}
	}

	a.storageOptions = authboss.StorageOptions{
		"Username": authboss.String,
		"Password": authboss.String,
	}
	a.routes = authboss.RouteTable{
		"login":  a.loginHandler,
		"logout": a.logoutHandler,
	}
	a.users = c.Storer

	a.logoutRedirect = path.Join(c.MountPath, c.AuthLogoutRoute)

	return nil
}

func (a *Auth) Routes() authboss.RouteTable {
	return a.routes
}

func (a *Auth) Storage() authboss.StorageOptions {
	return a.storageOptions
}

func (a *Auth) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		w.Write(a.loginPage.Bytes())
	case methodPOST:
		log.Println("in post")
		a.authenticate(r.PostFormValue("username"), r.PostFormValue("password"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *Auth) authenticate(username, password string) error {
	userInter, err := a.users.Get(username, nil)
	if err != nil {
		return errAuthFailed
	}

	userAttrs := authboss.Unbind(userInter)
	spew.Dump(userAttrs)

	if pwd, ok := userAttrs["Password"]; !ok {
		return errAuthFailed
	} else if pwd.Value.(string) != password {
		return errAuthFailed
	}

	log.Println("I have all the power")

	return nil
}

func (a *Auth) logoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		http.Redirect(w, r, a.logoutRedirect, http.StatusTemporaryRedirect)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
