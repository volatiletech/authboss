// Package hydraconsent implements the hydra user consent flow
package hydraconsent

import (
	"context"
	"net/http"
	"os"
	"time"

	hconsenter "github.com/Ashtonian/hConsenter"
	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

const (
	// PageLogin is for identifying the login page for parsing & validation
	PageLogin    = "login"
	PageConsent  = "consent"
	PageLogout   = "logout"
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

// Init module
func (a *HydraConsent) Init(ab *authboss.Authboss) (err error) {
	a.Authboss = ab

	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageLogin); err != nil {
		return err
	}
	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageLogout); err != nil {
		return err
	}
	if err = a.Authboss.Config.Core.ViewRenderer.Load(PageConsent); err != nil {
		return err
	}

	a.Authboss.Config.Core.Router.Get("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginGet))
	a.Authboss.Config.Core.Router.Post("/login", a.Authboss.Core.ErrorHandler.Wrap(a.LoginPost))
	a.Authboss.Config.Core.Router.Get("/consent", a.Authboss.Core.ErrorHandler.Wrap(a.ConsentGet))
	a.Authboss.Config.Core.Router.Post("/consent", a.Authboss.Core.ErrorHandler.Wrap(a.ConsentPost))
	a.Authboss.Config.Core.Router.Get("/logout", a.Authboss.Core.ErrorHandler.Wrap(a.LogoutGet))
	a.Authboss.Config.Core.Router.Post("/logout", a.Authboss.Core.ErrorHandler.Wrap(a.LoginPost))

	hydraURL := os.Getenv("HYDRA_ADMIN_URL")
	a.hClient = hconsenter.NewClient(hydraURL, 30*time.Second)

	ab.Events.After(authboss.EventAuthFail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		// TODO: reject post loginRequestOnFailEvent for hydra after user fails x # of times ?
		return true, nil
	})

	ab.Events.After(authboss.EventAuth, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
		usr, err := ab.CurrentUserID(r)
		if err != nil {
			return false, err
		}

		// TODO: how should this play with remember module?
		body := map[string]interface{}{
			"subject":      usr,
			"remember":     true,
			"remember_for": 3600,
		}

		ch := r.Context().Value(ChallengeKey).(string)
		res, err := a.hClient.AcceptLogin(ch, body)
		if err != nil {
			return false, err
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)

		return true, nil
	})
	return nil
}

func (a *HydraConsent) ConsentGet(w http.ResponseWriter, r *http.Request) error {
	ch := r.URL.Query().Get("consent_challenge")
	if ch == "" {
		return nil
	}

	getRes, err := a.hClient.GetConsent(ch)
	if err != nil {
		return err
	}

	noConsent := true // TODO env ?
	if getRes.Skip || noConsent {

		//  TODO: it would be nice if we could add an event here for people to attach to
		body := map[string]interface{}{
			"grant_scope":                 getRes.RequestedScope,
			"grant_access_token_audience": getRes.RequestedAudience,
			"session":                     map[string]interface{}{}, // TODO:
		}

		accRes, err := a.hClient.AcceptConsent(ch, body)
		if err != nil {
			return err
		}

		http.Redirect(w, r, accRes.RedirectTo, http.StatusFound)
		return nil
	}

	// If authentication can't be skipped must show the consent ui
	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))
	if d, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData); ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, d.MergeKV(ChallengeKey, ch)))
	}

	return nil
}

func (a *HydraConsent) ConsentPost(w http.ResponseWriter, r *http.Request) error {
	ch := "" // TODO source
	deny := true
	if deny {
		res, err := a.hClient.RejectConsent(ch, map[string]interface{}{"error": "access_denied", "error_description": "The resource owner denied the request"})
		if err != nil {
			return err
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		return nil
	}

	grantScope := []string{}

	res, err := a.hClient.GetConsent(ch)
	if err != nil {
		return err
	}

	body := map[string]interface{}{
		"grant_scope":                 grantScope,
		"grant_access_token_audience": res.RequestedAudience,
		"session":                     map[string]interface{}{}, // TODO:
		"remember":                    true,                     // TODO:
		"remember_for":                3600,
	}

	accRes, err := a.hClient.AcceptConsent(ch, body)
	if err != nil {
		return err
	}

	http.Redirect(w, r, accRes.RedirectTo, http.StatusFound)

	return nil
}

// LoginGet checks if the user needs the challenge form (un authenticated)
func (a *HydraConsent) LoginGet(w http.ResponseWriter, r *http.Request) error {
	ch := r.URL.Query().Get("login_challenge")
	if ch == "" {
		return nil
	}

	res, err := a.hClient.GetLogin(ch)
	if err != nil {
		return err
	}

	if res.Skip {
		/* TODO:
		- would be nice to add an event 'LoginSkip' here for users to create a callback for
		*/
		body := map[string]interface{}{
			"subject": res.Subject,
		}
		res, err := a.hClient.AcceptLogin(ch, body)
		if err != nil {
			return err
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		return nil
	}

	// If authentication can't be skipped must show the login ui
	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

	if d, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData); ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, d.MergeKV(ChallengeKey, ch)))
	}

	return nil
}

// TODO: Sourced from auth login, maybe just import that to avoid dupe?
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

// TODO: add get logout flow and prompt user for logout option
func (a *HydraConsent) LogoutGet(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// TODO: original source code sourced from logout module
func (a *HydraConsent) LogoutPost(w http.ResponseWriter, r *http.Request) error {
	userLogout := true // TODO: source from form
	if !userLogout {
		// user doesn't want to logout redirect ?
	}

	logger := a.RequestLogger(r)

	user, err := a.CurrentUser(r)
	if err == nil && user != nil {
		logger.Infof("user %s logged out", user.GetPID())
	} else {
		logger.Info("user (unknown) logged out")
	}

	authboss.DelAllSession(w, a.Config.Storage.SessionStateWhitelistKeys)
	authboss.DelKnownSession(w)
	authboss.DelKnownCookie(w)

	ch := r.URL.Query().Get("challenge")
	if ch == "" {
		return nil
	}

	_, err2 := a.hClient.GetLogout(ch)
	if err2 != nil {
		return err2
	}
	res2, err := a.hClient.AcceptLogout(ch)
	if err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: res2.RedirectTo, // a.Authboss.Paths.LogoutOK,
		Success:      "You have been logged out",
	}
	return a.Authboss.Core.Redirector.Redirect(w, r, ro)
}
