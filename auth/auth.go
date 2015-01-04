package auth

import (
	"io"
	"net/http"
	"path"

	"io/ioutil"

	"bytes"

	"github.com/go-authboss/authboss"
)

const (
	methodGET  = "GET"
	methodPOST = "POST"
)

func init() {
	a := &Auth{}
	authboss.Register(a)
}

type Auth struct {
	routes         authboss.Routes
	loginPage      *bytes.Buffer
	logoutRedirect string
}

func (a *Auth) Initialize(c authboss.Config) (err error) {
	var data []byte
	if c.AuthLoginPageURI == "" {
		if data, err = views_login_tpl_bytes(); err != nil {
			return err
		}
	} else {
		if data, err = ioutil.ReadFile(c.AuthLoginPageURI); err != nil {
			return err
		}
	}
	a.loginPage = bytes.NewBuffer(data)

	a.routes = authboss.Routes{
		path.Join(c.MountPath, "login"):  a.loginHandler,
		path.Join(c.MountPath, "logout"): a.logoutHandler,
	}

	a.logoutRedirect = path.Join(c.MountPath, c.AuthLogoutRedirect)

	return nil
}

func (a *Auth) Routes() authboss.Routes {
	return a.routes
}

func (a *Auth) Storage() {

}

func (a *Auth) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case methodGET:
		io.Copy(w, a.loginPage)
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
