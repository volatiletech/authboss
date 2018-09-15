/*
Package authboss is a modular authentication system for the web. It tries to
remove as much boilerplate and "hard things" as possible so that each time you
start a new web project in Go, you can plug it in, configure and be off to the
races without having to think about how to store passwords or remember tokens.
*/
package authboss

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// Authboss contains a configuration and other details for running.
type Authboss struct {
	Config
	Events *Events

	loadedModules map[string]Moduler
}

// New makes a new instance of authboss with a default
// configuration.
func New() *Authboss {
	ab := &Authboss{}

	ab.loadedModules = make(map[string]Moduler)
	ab.Events = NewEvents()

	ab.Config.Defaults()
	return ab
}

// Init authboss, modules, renderers
func (a *Authboss) Init(modulesToLoad ...string) error {
	if len(modulesToLoad) == 0 {
		modulesToLoad = RegisteredModules()
	}

	for _, name := range modulesToLoad {
		if err := a.loadModule(name); err != nil {
			return errors.Errorf("module %s failed to load: %+v", name, err)
		}
	}

	return nil
}

// UpdatePassword updates the password field of a user using the same semantics
// that register/auth do to create and verify passwords. It saves this using
// the storer.
//
// In addition to that, it also invalidates any remember me tokens, if the
// storer supports that kind of operation.
//
// If it's also desirable to log the user out, use:
// authboss.DelKnown(Session|Cookie)
func (a *Authboss) UpdatePassword(ctx context.Context, user AuthableUser, newPassword string) error {
	pass, err := bcrypt.GenerateFromPassword([]byte(newPassword), a.Config.Modules.BCryptCost)
	if err != nil {
		return err
	}

	user.PutPassword(string(pass))

	storer := a.Config.Storage.Server
	if err := storer.Save(ctx, user); err != nil {
		return err
	}

	rmStorer, ok := storer.(RememberingServerStorer)
	if !ok {
		return nil
	}

	return rmStorer.DelRememberTokens(ctx, user.GetPID())
}

// Middleware prevents someone from accessing a route that should be
// only allowed for users who are logged in.
// It allows the user through if they are logged in (SessionKey).
//
// If redirectToLogin is true, the user will be redirected to the
// login page, otherwise they will get a 404.
// The redirect goes to: mountPath/login, this means it's expected that
// the auth module is loaded if this is set to true.
//
// If forceFullAuth is true then half-authed users (SessionHalfAuth)
// are not allowed through, otherwise a half-authed user will be allowed through.
//
// If force2fa is true, then users must have been logged in
// with 2fa (Session2FA) otherwise they will not be allowed through.
func Middleware(ab *Authboss, redirectToLogin bool, forceFullAuth bool, force2fa bool) func(http.Handler) http.Handler {
	return MountedMiddleware(ab, false, redirectToLogin, forceFullAuth, force2fa)
}

// MountedMiddleware hides an option from typical users in "mountPathed".
// Normal routes should never need this only authboss routes (since they
// are behind mountPath typically). This method is exported only for use
// by Authboss modules, normal users should use Middleware instead.
//
// If mountPathed is true, then before redirecting to a URL it will add
// the mountpath to the front of it.
func MountedMiddleware(ab *Authboss, mountPathed, redirectToLogin, forceFullAuth, force2fa bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := ab.RequestLogger(r)

			fail := func(w http.ResponseWriter, r *http.Request) {
				if redirectToLogin {
					log.Infof("redirecting unauthorized user to login from: %s", r.URL.Path)
					vals := make(url.Values)

					redirURL := r.URL.Path
					if mountPathed && len(ab.Config.Paths.Mount) != 0 {
						redirURL = path.Join(ab.Config.Paths.Mount, redirURL)
					}
					vals.Set(FormValueRedirect, redirURL)

					ro := RedirectOptions{
						Code:         http.StatusTemporaryRedirect,
						Failure:      "please re-login",
						RedirectPath: path.Join(ab.Config.Paths.Mount, fmt.Sprintf("/login?%s", vals.Encode())),
					}

					if err := ab.Config.Core.Redirector.Redirect(w, r, ro); err != nil {
						log.Errorf("failed to redirect user during authboss.Middleware redirect: %+v", err)
					}
					return
				}

				log.Infof("not found for unauthorized user at: %s", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}

			if forceFullAuth && !IsFullyAuthed(r) || force2fa && !IsTwoFactored(r) {
				fail(w, r)
				return
			}

			if u, err := ab.LoadCurrentUser(&r); err != nil {
				log.Errorf("error fetching current user: %+v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if u == nil {
				fail(w, r)
				return
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
