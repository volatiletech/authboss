// Package hydraconsent implements the hydra user consent flow
package hydraconsent

import (
	"context"
	"net/http"
	"time"

	hconsenter "github.com/Ashtonian/hConsenter"
	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

const (
	// PageLogin is for identifying the login page for parsing & validation
	PageLogin    = "login"
	ChallengeKey = "challenge"
)

func init() {
	authboss.RegisterModule("hydraconsent", &HydraConsent{})
}

// HydraConsent module
type HydraConsent struct {
	*authboss.Authboss
	hClient *hconsenter.Client
}

var (
	CTXKeyChallenge = "challenge" // TODO: populate?
)

// Init module
// TODO: oath events?
func (a *HydraConsent) Init(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageLogin); err != nil {
		return err
	}

	a.Authboss.Config.Core.Router.Get("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginGet))
	a.Authboss.Config.Core.Router.Post("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginPost))
	a.Authboss.Config.Core.Router.Get("/consent", a.Authboss.Core.ErrorHandler.Wrap(a.ConsentGet))
	a.Authboss.Config.Core.Router.Post("/consent", a.Authboss.Core.ErrorHandler.Wrap(a.ConsentPost))

	a.hClient = hconsenter.NewClient("", 30*time.Second) // TODO: ENV

	// TODO: reject post loginRequestOnFailEvent for hydra
	ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		// user, err := model.GetUser(ab, &r)
		// if err != nil {
		// 	return false, err
		// }

		// TODO: how should this play with remember module?
		body := map[string]interface{}{
			"subject":      "TODO", // TODO: PID  user.GetEmail(),
			"remember":     true,   //
			"remember_for": 3600,
		}

		ch := r.Context().Value(CTXKeyChallenge).(string)
		res, err := a.hClient.AcceptLogin(ch, body)
		if err != nil {
			// TODO:
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)

		return true, nil
	})
	return nil
}

// TODO: enable 'auto-consent' flow so user doesn't have to consent if app is 1st
func (a *HydraConsent) ConsentGet(w http.ResponseWriter, r *http.Request) error {
	ch := r.URL.Query().Get("consent_challenge")
	if ch == "" {
		return nil
	}

	// TODO:
	// if skip
	// else render consent views

	getRes, err := a.hClient.GetConsent(ch)
	if err != nil {
		// TODO:
	}

	// TODO: don't think 'every' app needs those in session, should verify ory docs and make sure this isn't any hack,
	// but I think just build session interface on user obj should work
	// if user, err := model.GetUser(ab, &r); err == nil {
	// 	accessToken = AccessToken{
	// 		Role: user.Role,
	// 	}
	// 	idToken = IDToken{
	// 		Name:  user.Name,
	// 		Email: user.Email,
	// 		Role:  user.Role,
	// 	}
	// }
	// 	"session": map[string]interface{}{
	// 		"access_token": accessToken,
	// 		"id_token":     idToken,
	// 	},

	// TODO: review mappings

	body := map[string]interface{}{
		"grant_scope":                 getRes.RequestedScope,
		"grant_access_token_audience": getRes.RequestedAudience,
	}

	accRes, err := a.hClient.AcceptConsent(ch, body)
	if err != nil {
		// TODO:
	}

	http.Redirect(w, r, accRes.RedirectTo, http.StatusFound)
	return nil
}

func (a *HydraConsent) ConsentPost(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// LoginGet checks if the user needs the challenge form (un authenticated)
func (a *HydraConsent) LoginGet(w http.ResponseWriter, r *http.Request) error {
	ch := r.URL.Query().Get("consent_challenge")
	if ch == "" {
		return nil
	}

	res, err := a.hClient.GetLogin(ch)
	if err != nil {
		// TODO:
	}

	if res.Skip {
		body := map[string]interface{}{
			"subject": res.Subject,
		}
		res, err := a.hClient.AcceptLogin(ch, body)
		if err != nil {
			// TODO:
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		return nil
	}

	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

	if d, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData); ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, d.MergeKV("challenge", ch)))
	}

	return nil
}

/*
TODO: Create logout based on logout module and this merged
// 'accepts' logout

func LogoutMiddleware(ab *authboss.Authboss) Middleware {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/logout" && r.Method == http.MethodGet {
				if ch := r.URL.Query().Get("logout_challenge"); ch != "" {
					getLogoutRequest(ch)
					res := acceptLogoutRequest(ch)
					ab.Paths.LogoutOK = res.RedirectTo
				}
			}

			handler.ServeHTTP(w, r)
		})
	}
}
*/

// TODO: merge from middleware
// r = r.WithContext(context.WithValue(r.Context(), CTXKeyChallenge, r.FormValue("challenge")))
// TODO: reject loginRequestOnFailEvent for hydra
// LoginPost attempts to validate the credentials passed in
// to log in a user.
func (a *HydraConsent) LoginPost(w http.ResponseWriter, r *http.Request) error {
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

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, pidUser))

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

	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyValues, validatable))

	handled, err = a.Events.FireBefore(authboss.EventAuth, w, r)
	if err != nil {
		return err
	} else if handled {
		return nil
	}

	handled, err = a.Events.FireBefore(authboss.EventAuthHijack, w, r)
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
		Code:             http.StatusTemporaryRedirect,
		RedirectPath:     a.Authboss.Paths.AuthLoginOK,
		FollowRedirParam: true,
	}
	return a.Authboss.Core.Redirector.Redirect(w, r, ro)
}
