// Package auth implements password based user logins.
package auth

import (
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/response"
	"golang.org/x/crypto/bcrypt"
)

const (
	tplLogin = "login.html.tpl"
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

	if err := a.Authboss.Config.Core.ViewRenderer.Load(tplLogin); err != nil {
		return err
	}

	var logoutRouteMethod func(string, http.Handler)
	switch a.Authboss.Config.Modules.LogoutMethod {
	case "GET":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Get
	case "POST":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Post
	case "DELETE":
		logoutRouteMethod = a.Authboss.Config.Core.Router.Delete
	default:
		return errors.Errorf("auth wants to register a logout route but is given an invalid method: %s", a.Authboss.Config.Modules.LogoutMethod)
	}

	a.Authboss.Config.Core.Router.Get("/login", http.HandlerFunc(loginGet))
	a.Authboss.Config.Core.Router.Post("/login", http.HandlerFunc(loginPost))
	logoutRouteMethod("/logout", http.HandlerFunc(logout))

	return nil
}

func (a *Auth) loginGet(w http.ResponseWriter, r *http.Request) error {
	data := authboss.NewHTMLData(
		"showRemember", a.IsLoaded("remember"),
		"showRecover", a.IsLoaded("recover"),
		"showRegister", a.IsLoaded("register"),
		"primaryID", a.PrimaryID,
		"primaryIDValue", "",
	)
	return a.templates.Render(ctx, w, r, tplLogin, data)
}

func (a *Auth) loginPost(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case methodGET:
	case methodPOST:
		key := r.FormValue(a.PrimaryID)
		password := r.FormValue("password")

		errData := authboss.NewHTMLData(
			"error", fmt.Sprintf("invalid %s and/or password", a.PrimaryID),
			"primaryID", a.PrimaryID,
			"primaryIDValue", key,
			"showRemember", a.IsLoaded("remember"),
			"showRecover", a.IsLoaded("recover"),
			"showRegister", a.IsLoaded("register"),
		)

		if valid, err := validateCredentials(ctx, key, password); err != nil {
			errData["error"] = "Internal server error"
			fmt.Fprintf(ctx.LogWriter, "auth: validate credentials failed: %v\n", err)
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		} else if !valid {
			if err := a.Events.FireAfter(authboss.EventAuthFail, ctx); err != nil {
				fmt.Fprintf(ctx.LogWriter, "EventAuthFail callback error'd out: %v\n", err)
			}
			return a.templates.Render(ctx, w, r, tplLogin, errData)
		}

		interrupted, err := a.Events.FireBefore(authboss.EventAuth, ctx)
		if err != nil {
			return err
		} else if interrupted != authboss.InterruptNone {
			var reason string
			switch interrupted {
			case authboss.InterruptAccountLocked:
				reason = "Your account has been locked."
			case authboss.InterruptAccountNotConfirmed:
				reason = "Your account has not been confirmed."
			}
			response.Redirect(ctx, w, r, a.AuthLoginFailPath, "", reason, false)
			return nil
		}

		ctx.SessionStorer.Put(authboss.SessionKey, key)
		ctx.SessionStorer.Del(authboss.SessionHalfAuthKey)
		ctx.Values = map[string]string{authboss.CookieRemember: r.FormValue(authboss.CookieRemember)}

		if err := a.Events.FireAfter(authboss.EventAuth, ctx); err != nil {
			return err
		}
		response.Redirect(ctx, w, r, a.AuthLoginOKPath, "", "", true)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

	return nil
}

func validateCredentials(key, password string) (bool, error) {
	if err := ctx.LoadUser(key); err == authboss.ErrUserNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}

	actualPassword, err := ctx.User.StringErr(authboss.StorePassword)
	if err != nil {
		return false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(actualPassword), []byte(password)); err != nil {
		return false, nil
	}

	return true, nil
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) error {
	ctx.SessionStorer.Del(authboss.SessionKey)
	ctx.CookieStorer.Del(authboss.CookieRemember)
	ctx.SessionStorer.Del(authboss.SessionLastAction)

	response.Redirect(ctx, w, r, a.AuthLogoutOKPath, "You have logged out", "", true)

	return nil
}
