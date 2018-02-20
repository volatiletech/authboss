// Package auth implements password based user logins.
package auth

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

const (
	// PageLogin is for identifying the login page for parsing & validation
	PageLogin = "login"
)

func init() {
	authboss.RegisterModule("auth", &Auth{})
}

// Auth module
type Auth struct {
	*authboss.Authboss
}

// Init module
func (a *Auth) Init(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageLogin); err != nil {
		return err
	}

	var logoutRouteMethod func(string, http.Handler)
	switch a.Authboss.Config.Modules.AuthLogoutMethod {
	case "GET":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Get
	case "POST":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Post
	case "DELETE":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Delete
	default:
		return errors.Errorf("auth wants to register a logout route but was given an invalid method: %s", a.Authboss.Config.Modules.AuthLogoutMethod)
	}

	a.Authboss.Config.Core.Router.Get("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginGet))
	a.Authboss.Config.Core.Router.Post("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginPost))
	logoutRouteMethod("/logout", a.Authboss.Core.ErrorHandler.Wrap(a.Logout))

	return nil
}

// LoginGet simply displays the login form
func (a *Auth) LoginGet(w http.ResponseWriter, r *http.Request) error {
	return a.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, nil)
}

// LoginPost attempts to validate the credentials passed in
// to log in a user.
func (a *Auth) LoginPost(w http.ResponseWriter, r *http.Request) error {
	logger := a.RequestLogger(r)

	validatable, err := a.Authboss.Core.BodyReader.Read(PageLogin, r)
	if err != nil {
		return err
	}

	// Skip validation since all the validation happens during the database lookup and
	// password check.
	creds := authboss.MustHaveUserValues(validatable)

	pid := creds.GetPID()
	pidUser, err := a.Authboss.Storage.Server.Load(r.Context(), pid)
	if err == authboss.ErrUserNotFound {
		logger.Infof("failed to load user requested by pid: %s", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return a.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	} else if err != nil {
		return err
	}

	authUser := authboss.MustBeAuthable(pidUser)
	password := authUser.GetPassword()

	var handled bool
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(creds.GetPassword()))
	if err != nil {
		handled, err = a.Authboss.Events.FireAfter(authboss.EventAuthFail, w, r)
		if err != nil {
			return err
		} else if handled {
			return nil
		}

		logger.Infof("user %s failed to log in", pid)
		data := authboss.HTMLData{authboss.DataErr: "Invalid Credentials"}
		return a.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)
	}

	handled, err = a.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	logger.Infof("user %s logged in", pid)
	authboss.PutSession(w, authboss.SessionKey, pid)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)

	handled, err = a.Authboss.Events.FireAfter(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: a.Authboss.Paths.AuthLogoutOK,
	}
	return a.Authboss.Core.Redirector.Redirect(w, r, ro)
}

// Logout a user
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) error {
	logger := a.RequestLogger(r)
	user, err := a.CurrentUser(w, r)
	if err != nil {
		return err
	}

	logger.Infof("user %s logged out", user.GetPID())

	authboss.DelSession(w, authboss.SessionKey)
	authboss.DelSession(w, authboss.SessionLastAction)
	authboss.DelSession(w, authboss.SessionHalfAuthKey)
	authboss.DelCookie(w, authboss.CookieRemember)

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: a.Authboss.Paths.AuthLogoutOK,
		Success:      "You have been logged out",
	}
	return a.Authboss.Core.Redirector.Redirect(w, r, ro)
}
