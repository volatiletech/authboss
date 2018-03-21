// Package logout allows users to log out (from auth or oauth2 logins)
package logout

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

func init() {
	authboss.RegisterModule("logout", &Logout{})
}

// Logout module
type Logout struct {
	*authboss.Authboss
}

// Init the module
func (l *Logout) Init(ab *authboss.Authboss) error {
	l.Authboss = ab

	var logoutRouteMethod func(string, http.Handler)
	switch l.Authboss.Config.Modules.LogoutMethod {
	case "GET":
		logoutRouteMethod = l.Authboss.Config.Core.Router.Get
	case "POST":
		logoutRouteMethod = l.Authboss.Config.Core.Router.Post
	case "DELETE":
		logoutRouteMethod = l.Authboss.Config.Core.Router.Delete
	default:
		return errors.Errorf("logout wants to register a logout route but was given an invalid method: %s", l.Authboss.Config.Modules.LogoutMethod)
	}

	logoutRouteMethod("/logout", l.Authboss.Core.ErrorHandler.Wrap(l.Logout))

	return nil
}

// Logout the user
func (l *Logout) Logout(w http.ResponseWriter, r *http.Request) error {
	logger := l.RequestLogger(r)

	user, err := l.CurrentUser(r)
	if err == nil && user != nil {
		logger.Infof("user %s logged out", user.GetPID())
	} else {
		logger.Info("user (unknown) logged out")
	}

	authboss.DelKnownSession(w)
	authboss.DelKnownCookie(w)

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: l.Authboss.Paths.LogoutOK,
		Success:      "You have been logged out",
	}
	return l.Authboss.Core.Redirector.Redirect(w, r, ro)
}
