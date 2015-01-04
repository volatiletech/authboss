package auth

import (
	"io"
	"net/http"
	"path"

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
	Routes         authboss.Routes
	loginPage      io.Reader
	logoutRedirect string
}

func (a *Auth) Initialize(c authboss.Config) error {
	// create the reader for the default or specified file

	var err error
	a.loginPage, err = views_login_tpl_bytes()

	a.Routes = Routes{
		path.Join(c.MountPath, "login"):  a.loginHandler,
		path.Join(c.MountPath, "logout"): a.logoutHandler,
	}

	return nil
}

func (a *Auth) Routes() authboss.Routes {
	return a.Routes
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
