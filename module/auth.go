// Package hydraconsent implements the hydra user consent flow
package hydraconsent

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	hconsenter "github.com/ashtonian/hConsenter"
	"github.com/davecgh/go-spew/spew"
	"github.com/volatiletech/authboss"
	"golang.org/x/crypto/bcrypt"
)

type ConsentValuer interface {
	authboss.Validator

	GetScopes() []string
}

func MustHaveConsent(v authboss.Validator) ConsentValuer {
	if u, ok := v.(ConsentValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to ConsentValuer: %T", v))
}

type ChallengeValuer interface {
	authboss.Validator

	GetChallenge() string
}

func MustHaveChallenge(v authboss.Validator) ChallengeValuer {
	if u, ok := v.(ChallengeValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to ChallengeValuer: %T", v))
}

type LogoutValuer interface {
	authboss.Validator

	GetShouldLogout() bool
}

func MustHaveLougout(v authboss.Validator) LogoutValuer {
	if u, ok := v.(LogoutValuer); ok {
		return u
	}

	panic(fmt.Sprintf("bodyreader returned a type that could not be upgraded to LogoutValuer: %T", v))
}

// TODO: document oauth2 and openID reserved scopes/session keys, potentially type them via an additional module
// TODO: sync scope formulas /get + /post consent/login
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
	if hydraURL == "" {
		hydraURL = "http://localhost:4445"
	}
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

		validatable, err := a.Authboss.Core.BodyReader.Read(PageLogin, r)
		if err != nil {
			return false, err
		}

		// Add challenge to context
		// TODO: Builtin valuer
		// challengeForm := MustHaveChallenge(validatable)
		// ch := challengeForm.GetChallenge()
		ch := r.FormValue("challenge")
		r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

		// add challenge key to view data
		data, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData)
		data = data.MergeKV(ChallengeKey, ch)
		if ok {
			r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
		}

		rememberMe := false
		u, ok := validatable.(authboss.RememberValuer)
		if !ok {
			rememberMe = u.GetShouldRemember()
		}

		body := map[string]interface{}{
			"subject":      usr,
			"remember":     rememberMe,
			"remember_for": 3600, // TODO: env
		}
		res, err := a.hClient.AcceptLogin(ch, body)
		if err != nil {
			return false, err
		}
		// http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		ro := authboss.RedirectOptions{
			Code:             http.StatusFound,
			RedirectPath:     res.RedirectTo,
			FollowRedirParam: true,
		}
		err = a.Authboss.Core.Redirector.Redirect(w, r, ro)
		return true, err

		// return true, nil
	})
	return nil
}

func toMap(clientInfo *hconsenter.ClientInfo) map[string]interface{} {
	client := map[string]interface{}{}
	client["id"] = clientInfo.ClientID
	client["contacts"] = clientInfo.Contacts
	client["client_uri"] = clientInfo.ClientURI
	client["logo_uri"] = clientInfo.LogoURI
	client["metadata"] = clientInfo.Metadata
	client["name"] = clientInfo.Name
	client["owner"] = clientInfo.Owner
	client["policy_uri"] = clientInfo.PolicyURI
	client["post_logout_redirect_ur_is"] = clientInfo.PostLogoutRedirectURIs
	client["redirect_ur_is"] = clientInfo.RedirectURIs
	return client
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
	spew.Dump("ctx", getRes.Context, "acr", getRes.ACR, "scopereq", getRes.RequestedScope, "scopeaud")

	noConsent := false // TODO env skip consent url and check requested uri
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

	// add challenge key to context
	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

	// add challenge and related to view data
	data, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData)
	data = data.MergeKV(ChallengeKey, ch)
	// TODO: pass rememberME from login
	data = data.MergeKV("ctx", getRes.Context)
	data = data.MergeKV("login_session_id", getRes.LoginSessionID)
	data = data.MergeKV("request_url", getRes.RequestURL)
	data = data.MergeKV("requested_audience", getRes.RequestedAudience)
	data = data.MergeKV("requested_scope", getRes.RequestedScope)
	data = data.MergeKV("subject", getRes.Subject)
	client := toMap(getRes.Client)
	data = data.MergeKV("client", client)

	if ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
	}

	// If authentication can't be skipped must show the consent ui
	return a.Core.Responder.Respond(w, r, http.StatusOK, PageConsent, data)
}

func (a *HydraConsent) ConsentPost(w http.ResponseWriter, r *http.Request) error {
	// validatable, err := a.Authboss.Core.BodyReader.Read(PageConsent, r)
	// if err != nil {
	// 	return err
	// }

	ch := r.FormValue("challenge")
	grantedScopes := r.Form["grant_scope"]
	isAllowedRaw := r.FormValue("is_allowed")
	isAllowed, err := strconv.ParseBool(isAllowedRaw)
	requestedAudience := r.Form["requested_audience"]

	if err != nil {
		return err
	}
	// TODO: built in valuer
	// consentForm := MustHaveConsent(validatable)
	// challengeForm := MustHaveChallenge(validatable)

	// ch := challengeForm.GetChallenge()
	// grantedScopes := consentForm.GetScopes()

	if !isAllowed {
		res, err := a.hClient.RejectConsent(ch, map[string]interface{}{"error": "access_denied", "error_description": "The resource owner denied the request"})
		if err != nil {
			return err
		}
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		return nil
	}

	// verify consent ch
	_, err = a.hClient.GetConsent(ch)
	if err != nil {
		return err
	}
	rememberMeRaw := r.FormValue("remember_me")
	rememberMe, _ := strconv.ParseBool(rememberMeRaw)

	// rememberMe := false // TODO: || res.rememberMe
	// if u, ok := validatable.(authboss.RememberValuer); ok {
	// 	rememberMe = u.GetShouldRemember()
	// }

	body := map[string]interface{}{
		"grant_scope":                 grantedScopes,
		"grant_access_token_audience": requestedAudience,        // TODO: res.RequestedAudience
		"session":                     map[string]interface{}{}, // TODO:
		"remember":                    rememberMe,
		"remember_for":                3600, // TODO: envme
	}

	spew.Dump("BODY", body)
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

	// add challenge key to context
	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

	// add challenge key and related to view data
	data, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData)
	data = data.MergeKV(ChallengeKey, ch)
	data = data.MergeKV("request_url", res.RequestURL)
	data = data.MergeKV("requested_audience", res.RequestedAudience)
	data = data.MergeKV("requested_scope", res.RequestedScope)
	data = data.MergeKV("session_id", res.SessionID)
	data = data.MergeKV("subject", res.Subject)
	client := toMap(res.Client)
	data = data.MergeKV("client", client)
	if ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
	}

	// If authentication can't be skipped must show the login ui
	return a.Core.Responder.Respond(w, r, http.StatusOK, PageLogin, data)

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
	ch := r.URL.Query().Get("logout_challenge")
	if ch == "" {
		return nil
	}
	res, err := a.hClient.GetLogout(ch)
	if err != nil {
		return err
	}

	// add challenge key to context
	r = r.WithContext(context.WithValue(r.Context(), ChallengeKey, ch))

	// add challenge key and related to view data
	data, ok := r.Context().Value(authboss.CTXKeyData).(authboss.HTMLData)
	data = data.MergeKV(ChallengeKey, ch)
	data = data.MergeKV("request_url", res.RequestURL)
	data = data.MergeKV("session_id", res.SessionID)
	data = data.MergeKV("subject", res.Subject)
	if ok {
		r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyData, data))
	}

	return nil
}

// TODO: original source code sourced from logout module
func (a *HydraConsent) LogoutPost(w http.ResponseWriter, r *http.Request) error {
	// TODO: built in valuer
	// validatable, err := a.Authboss.Core.BodyReader.Read(PageLogout, r)
	// if err != nil {
	// 	return err
	// }
	// challengeForm := MustHaveChallenge(validatable)
	// ch := challengeForm.GetChallenge()
	// logoutForm := MustHaveLougout(validatable)
	// userLogout := logoutForm.GetShouldLogout()

	ch := r.FormValue("challenge")
	shouldLogoutRaw := r.FormValue("should_logout")
	userLogout, err := strconv.ParseBool(shouldLogoutRaw)
	if err != nil {
		return fmt.Errorf("couldn't convert should_logout to bool")
	}

	if !userLogout {
		res, err := a.hClient.RejectLogout(ch)
		if err != nil {
			return err
		}
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: res.RedirectTo,
			Success:      "You are being redirected away",
		}
		return a.Authboss.Core.Redirector.Redirect(w, r, ro)
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

	// verify challenge
	_, err = a.hClient.GetLogout(ch)
	if err != nil {
		return err
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
