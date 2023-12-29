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

	"github.com/friendsofgo/errors"
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
	// Create the hasher
	// Have to do it in Init for backwards compatibility.
	// If a user did not previously use defaults.SetCore() then they will
	// suddenly start getting panics
	// We also cannot use config.Defaults() so we can respect the user's BCryptCost
	if a.Config.Core.Hasher == nil {
		a.Config.Core.Hasher = NewBCryptHasher(a.Config.Modules.BCryptCost)
	}

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
// Note that it's best practice after having called this method to also delete
// all the user's logged in sessions. The CURRENT logged in session can be
// deleted with `authboss.DelKnown(Session|Cookie)` but to delete ALL logged
// in sessions for a user requires special mechanisms not currently provided
// by authboss.
func (a *Authboss) UpdatePassword(ctx context.Context, user AuthableUser, newPassword string) error {
	pass, err := a.Config.Core.Hasher.GenerateHash(newPassword)
	if err != nil {
		return err
	}

	user.PutPassword(pass)

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

// VerifyPassword check that the provided password for the user is correct.
// Returns nil on success otherwise there will be an error.
// Simply a wrapper for [a.Core.Hasher.CompareHashAndPassword]
func (a *Authboss) VerifyPassword(user AuthableUser, password string) error {
	return a.Core.Hasher.CompareHashAndPassword(user.GetPassword(), password)
}

// Localizef is a helper to translate a key using the translator
// If the localizer is nil or returns an empty string,
// then the original text will be returned using [fmt.Sprintf] to interpolate the args.
func (a *Authboss) Localizef(ctx context.Context, text string, args ...any) string {
	if a.Config.Core.Localizer == nil {
		return fmt.Sprintf(text, args...)
	}

	if translated := a.Config.Core.Localizer.Localizef(ctx, text, args...); translated != "" {
		return translated
	}

	return fmt.Sprintf(text, args...)
}

// VerifyPassword uses authboss mechanisms to check that a password is correct.
// Returns nil on success otherwise there will be an error. Simply a helper
// to do the bcrypt comparison.
//
// NOTE: This function will work ONLY if no custom hasher was configured in global ab.config
//
// Deperecated: use [a.VerifyPassword] instead
func VerifyPassword(user AuthableUser, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(user.GetPassword()), []byte(password))
}

// MWRequirements are user requirements for authboss.Middleware
// in order to access the routes in protects. Requirements is a bit-set integer
// to be able to easily combine requirements like so:
//
//	authboss.RequireFullAuth | authboss.Require2FA
type MWRequirements int

// MWRespondOnFailure tells authboss.Middleware how to respond to
// a failure to meet the requirements.
type MWRespondOnFailure int

// Middleware requirements
const (
	RequireNone MWRequirements = 0x00
	// RequireFullAuth means half-authed users will also be rejected
	RequireFullAuth MWRequirements = 0x01
	// Require2FA means that users who have not authed with 2fa will
	// be rejected.
	Require2FA MWRequirements = 0x02
)

// Middleware response types
const (
	// RespondNotFound does not allow users who are not logged in to know a
	// route exists by responding with a 404.
	RespondNotFound MWRespondOnFailure = iota
	// RespondRedirect redirects users to the login page
	RespondRedirect
	// RespondUnauthorized provides a 401, this allows users to know the page
	// exists unlike the 404 option.
	RespondUnauthorized
)

// Middleware is deprecated. See Middleware2.
func Middleware(ab *Authboss, redirectToLogin bool, forceFullAuth bool, force2fa bool) func(http.Handler) http.Handler {
	return MountedMiddleware(ab, false, redirectToLogin, forceFullAuth, force2fa)
}

// MountedMiddleware is deprecated. See MountedMiddleware2.
func MountedMiddleware(ab *Authboss, mountPathed, redirectToLogin, forceFullAuth, force2fa bool) func(http.Handler) http.Handler {
	var reqs MWRequirements
	failResponse := RespondNotFound
	if forceFullAuth {
		reqs |= RequireFullAuth
	}
	if force2fa {
		reqs |= Require2FA
	}
	if redirectToLogin {
		failResponse = RespondRedirect
	}
	return MountedMiddleware2(ab, mountPathed, reqs, failResponse)
}

// Middleware2 prevents someone from accessing a route that should be
// only allowed for users who are logged in.
// It allows the user through if they are logged in (SessionKey is present in
// the session).
//
// requirements are set by logical or'ing together requirements. eg:
//
//	authboss.RequireFullAuth | authboss.Require2FA
//
// failureResponse is how the middleware rejects the users that don't meet
// the criteria. This should be chosen from the MWRespondOnFailure constants.
func Middleware2(ab *Authboss, requirements MWRequirements, failureResponse MWRespondOnFailure) func(http.Handler) http.Handler {
	return MountedMiddleware2(ab, false, requirements, failureResponse)
}

// MountedMiddleware2 hides an option from typical users in "mountPathed".
// Normal routes should never need this only authboss routes (since they
// are behind mountPath typically). This method is exported only for use
// by Authboss modules, normal users should use Middleware instead.
//
// If mountPathed is true, then before redirecting to a URL it will add
// the mountpath to the front of it.
func MountedMiddleware2(ab *Authboss, mountPathed bool, reqs MWRequirements, failResponse MWRespondOnFailure) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := ab.RequestLogger(r)

			fail := func(w http.ResponseWriter, r *http.Request) {
				switch failResponse {
				case RespondNotFound:
					log.Infof("not found for unauthorized user at: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				case RespondUnauthorized:
					log.Infof("unauthorized for unauthorized user at: %s", r.URL.Path)
					w.WriteHeader(http.StatusUnauthorized)
				case RespondRedirect:
					log.Infof("redirecting unauthorized user to login from: %s", r.URL.Path)
					vals := make(url.Values)

					redirURL := r.URL.Path
					if mountPathed && len(ab.Config.Paths.Mount) != 0 {
						redirURL = path.Join(ab.Config.Paths.Mount, redirURL)
					}
					if len(r.URL.RawQuery) != 0 {
						redirURL += "?" + r.URL.RawQuery
					}
					vals.Set(FormValueRedirect, redirURL)

					ro := RedirectOptions{
						Code:         http.StatusTemporaryRedirect,
						Failure:      ab.Localizef(r.Context(), TxtAuthFailed),
						RedirectPath: path.Join(ab.Config.Paths.Mount, fmt.Sprintf("/login?%s", vals.Encode())),
					}

					if err := ab.Config.Core.Redirector.Redirect(w, r, ro); err != nil {
						log.Errorf("failed to redirect user during authboss.Middleware redirect: %+v", err)
					}
					return
				}
			}

			if hasBit(reqs, RequireFullAuth) && !IsFullyAuthed(r) || hasBit(reqs, Require2FA) && !IsTwoFactored(r) {
				fail(w, r)
				return
			}

			if _, err := ab.LoadCurrentUser(&r); err == ErrUserNotFound {
				fail(w, r)
				return
			} else if err != nil {
				log.Errorf("error fetching current user: %+v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func hasBit(reqs, req MWRequirements) bool {
	return reqs&req == req
}
