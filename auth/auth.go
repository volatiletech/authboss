package auth

import (
	"net/http"
	"path"
	"path/filepath"

	"html/template"
	"io/ioutil"

	"bytes"

	"gopkg.in/authboss.v0"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"
)

func init() {
	a := &Auth{}
	authboss.RegisterModule("auth", a)
}

type Auth struct {
	routes         authboss.RouteTable
	loginPage      *bytes.Buffer
	logoutRedirect string
}

func (a *Auth) Initialize(c *authboss.Config) (err error) {
	var data []byte

	if data, err = ioutil.ReadFile(filepath.Join(c.ViewsPath, "login.html")); err != nil {
		return err
	} else {
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

	a.routes = authboss.RouteTable{
		path.Join(c.MountPath, "login"):  a.loginHandler,
		path.Join(c.MountPath, "logout"): a.logoutHandler,
	}

	a.logoutRedirect = path.Join(c.MountPath, c.AuthLogoutRoute)

	return nil
}

func (a *Auth) Routes() authboss.RouteTable {
	return a.routes
}

func (a *Auth) Storage() authboss.StorageOptions {
	return nil
}

func (a *Auth) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		w.Write(a.loginPage.Bytes())
	case methodPOST:
		// TODO
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *Auth) logoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		http.Redirect(w, r, a.logoutRedirect, http.StatusTemporaryRedirect)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
