package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/internal/mocks"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

func init() {
	exchanger = func(_ *oauth2.Config, _ context.Context, _ string) (*oauth2.Token, error) {
		return testToken, nil
	}
}

var testProviders = map[string]authboss.OAuth2Provider{
	"google": authboss.OAuth2Provider{
		OAuth2Config: &oauth2.Config{
			ClientID:     `jazz`,
			ClientSecret: `hands`,
			Scopes:       []string{`profile`, `email`},
			Endpoint:     google.Endpoint,
			// This is typically set by Init() but some tests rely on it's existence
			RedirectURL: "https://www.example.com/auth/oauth2/callback/google",
		},
		FindUserDetails:  GoogleUserDetails,
		AdditionalParams: url.Values{"include_requested_scopes": []string{"true"}},
	},
	"facebook": authboss.OAuth2Provider{
		OAuth2Config: &oauth2.Config{
			ClientID:     `jazz`,
			ClientSecret: `hands`,
			Scopes:       []string{`email`},
			Endpoint:     facebook.Endpoint,
			// This is typically set by Init() but some tests rely on it's existence
			RedirectURL: "https://www.example.com/auth/oauth2/callback/facebook",
		},
		FindUserDetails: FacebookUserDetails,
	},
}

var testToken = &oauth2.Token{
	AccessToken:  "token",
	TokenType:    "Bearer",
	RefreshToken: "refresh",
	Expiry:       time.Now().AddDate(0, 0, 1),
}

func TestInit(t *testing.T) {
	// No t.Parallel() since the cfg.RedirectURL is set in Init()

	ab := authboss.New()
	oauth := &OAuth2{}

	router := &mocks.Router{}
	ab.Config.Modules.OAuth2Providers = testProviders
	ab.Config.Core.Router = router
	ab.Config.Core.ErrorHandler = &mocks.ErrorHandler{}

	ab.Config.Paths.Mount = "/auth"
	ab.Config.Paths.RootURL = "https://www.example.com"

	if err := oauth.Init(ab); err != nil {
		t.Fatal(err)
	}

	gets := []string{
		"/oauth2/facebook", "/oauth2/callback/facebook",
		"/oauth2/google", "/oauth2/callback/google",
	}
	if err := router.HasGets(gets...); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	oauth *OAuth2
	ab    *authboss.Authboss

	bodyReader *mocks.BodyReader
	responder  *mocks.Responder
	redirector *mocks.Redirector
	session    *mocks.ClientStateRW
	storer     *mocks.ServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.redirector = &mocks.Redirector{}
	harness.session = mocks.NewClientRW()
	harness.storer = mocks.NewServerStorer()

	harness.ab.Modules.OAuth2Providers = testProviders

	harness.ab.Paths.OAuth2LoginOK = "/auth/oauth2/ok"
	harness.ab.Paths.OAuth2LoginNotOK = "/auth/oauth2/not/ok"

	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.oauth = &OAuth2{harness.ab}

	return harness
}

func TestStart(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)
	r := httptest.NewRequest("GET", "/oauth2/google?cake=yes&death=no", nil)

	if err := h.oauth.Start(w, r); err != nil {
		t.Error(err)
	}

	if h.redirector.Options.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", h.redirector.Options.Code)
	}

	url, err := url.Parse(h.redirector.Options.RedirectPath)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Query()
	if state := query.Get("state"); len(state) == 0 {
		t.Error("our nonce should have been here")
	}
	if callback := query.Get("redirect_uri"); callback != "https://www.example.com/auth/oauth2/callback/google" {
		t.Error("callback was wrong:", callback)
	}
	if clientID := query.Get("client_id"); clientID != "jazz" {
		t.Error("clientID was wrong:", clientID)
	}
	if url.Host != "accounts.google.com" {
		t.Error("host was wrong:", url.Host)
	}

	if h.session.ClientValues[authboss.SessionOAuth2State] != query.Get("state") {
		t.Error("the state should have been saved in the session")
	}
	if v := h.session.ClientValues[authboss.SessionOAuth2Params]; v != `{"cake":"yes","death":"no"}` {
		t.Error("oauth2 session params are wrong:", v)
	}
}

func TestStartBadProvider(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)
	r := httptest.NewRequest("GET", "/oauth2/test", nil)

	err := h.oauth.Start(w, r)
	if e := err.Error(); !strings.Contains(e, `provider "test" not found`) {
		t.Error("it should have errored:", e)
	}
}

func TestEnd(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	h.session.ClientValues[authboss.SessionOAuth2State] = "state"
	r, err := h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=state", nil))
	if err != nil {
		t.Fatal(err)
	}

	if err := h.oauth.End(w, r); err != nil {
		t.Error(err)
	}

	w.WriteHeader(http.StatusOK) // Flush headers

	opts := h.redirector.Options
	if opts.Code != http.StatusTemporaryRedirect {
		t.Error("it should have redirected")
	}
	if opts.RedirectPath != "/auth/oauth2/ok" {
		t.Error("redir path was wrong:", opts.RedirectPath)
	}
	if s := h.session.ClientValues[authboss.SessionKey]; s != "oauth2;;google;;id" {
		t.Error("session id should have been set:", s)
	}
}

func TestEndBadProvider(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)
	r := httptest.NewRequest("GET", "/oauth2/callback/test", nil)

	err := h.oauth.End(w, r)
	if e := err.Error(); !strings.Contains(e, `provider "test" not found`) {
		t.Error("it should have errored:", e)
	}
}

func TestEndBadState(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)
	r := httptest.NewRequest("GET", "/oauth2/callback/google", nil)

	err := h.oauth.End(w, r)
	if e := err.Error(); !strings.Contains(e, `oauth2 endpoint hit without session state`) {
		t.Error("it should have errored:", e)
	}

	h.session.ClientValues[authboss.SessionOAuth2State] = "state"
	r, err = h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=x", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.oauth.End(w, r); err != errOAuthStateValidation {
		t.Error("error was wrong:", err)
	}
}

func TestEndErrors(t *testing.T) {
	t.Parallel()

	h := testSetup()

	rec := httptest.NewRecorder()
	w := h.ab.NewResponse(rec)

	h.session.ClientValues[authboss.SessionOAuth2State] = "state"
	r, err := h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=state&error=badtimes&error_reason=reason", nil))
	if err != nil {
		t.Fatal(err)
	}

	if err := h.oauth.End(w, r); err != nil {
		t.Error(err)
	}

	opts := h.redirector.Options
	if opts.Code != http.StatusTemporaryRedirect {
		t.Error("code was wrong:", opts.Code)
	}
	if opts.RedirectPath != "/auth/oauth2/not/ok" {
		t.Error("path was wrong:", opts.RedirectPath)
	}
}

func TestEndHandling(t *testing.T) {
	t.Parallel()

	t.Run("AfterOAuth2Fail", func(t *testing.T) {
		h := testSetup()

		rec := httptest.NewRecorder()
		w := h.ab.NewResponse(rec)

		h.session.ClientValues[authboss.SessionOAuth2State] = "state"
		r, err := h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=state&error=badtimes&error_reason=reason", nil))
		if err != nil {
			t.Fatal(err)
		}

		called := false
		h.ab.Events.After(authboss.EventOAuth2Fail, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			called = true
			return true, nil
		})

		if err := h.oauth.End(w, r); err != nil {
			t.Error(err)
		}

		if !called {
			t.Error("it should have been called")
		}
		if h.redirector.Options.Code != 0 {
			t.Error("it should not have tried to redirect")
		}
	})
	t.Run("BeforeOAuth2", func(t *testing.T) {
		h := testSetup()

		rec := httptest.NewRecorder()
		w := h.ab.NewResponse(rec)

		h.session.ClientValues[authboss.SessionOAuth2State] = "state"
		r, err := h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=state", nil))
		if err != nil {
			t.Fatal(err)
		}

		called := false
		h.ab.Events.Before(authboss.EventOAuth2, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			called = true
			return true, nil
		})

		if err := h.oauth.End(w, r); err != nil {
			t.Error(err)
		}

		w.WriteHeader(http.StatusOK) // Flush headers

		if !called {
			t.Error("it should have been called")
		}
		if h.redirector.Options.Code != 0 {
			t.Error("it should not have tried to redirect")
		}
		if len(h.session.ClientValues[authboss.SessionKey]) != 0 {
			t.Error("should have not logged the user in")
		}
	})

	t.Run("AfterOAuth2", func(t *testing.T) {
		h := testSetup()

		rec := httptest.NewRecorder()
		w := h.ab.NewResponse(rec)

		h.session.ClientValues[authboss.SessionOAuth2State] = "state"
		r, err := h.ab.LoadClientState(w, httptest.NewRequest("GET", "/oauth2/callback/google?state=state", nil))
		if err != nil {
			t.Fatal(err)
		}

		called := false
		h.ab.Events.After(authboss.EventOAuth2, func(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
			called = true
			return true, nil
		})

		if err := h.oauth.End(w, r); err != nil {
			t.Error(err)
		}

		w.WriteHeader(http.StatusOK) // Flush headers

		if !called {
			t.Error("it should have been called")
		}
		if h.redirector.Options.Code != 0 {
			t.Error("it should not have tried to redirect")
		}
		if s := h.session.ClientValues[authboss.SessionKey]; s != "oauth2;;google;;id" {
			t.Error("session id should have been set:", s)
		}
	})
}

/*
func TestInitialize(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	ab.OAuth2Storer = mocks.NewMockStorer()
	o := OAuth2{}
	if err := o.Initialize(ab); err != nil {
		t.Error(err)
	}
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	root := "https://localhost:8080"
	mount := "/auth"

	ab := authboss.New()
	o := OAuth2{ab}

	ab.RootURL = root
	ab.MountPath = mount
	ab.OAuth2Providers = testProviders

	googleCfg := ab.OAuth2Providers["google"].OAuth2Config
	if 0 != len(googleCfg.RedirectURL) {
		t.Error("RedirectURL should not be set")
	}

	routes := o.Routes()
	authURL := path.Join("/oauth2", "google")
	tokenURL := path.Join("/oauth2", "callback", "google")
	redir := root + path.Join(mount, "oauth2", "callback", "google")

	if _, ok := routes[authURL]; !ok {
		t.Error("Expected an auth url route:", authURL)
	}
	if _, ok := routes[tokenURL]; !ok {
		t.Error("Expected a token url route:", tokenURL)
	}

	if googleCfg.RedirectURL != redir {
		t.Error("The redirect URL should have been set:", googleCfg.RedirectURL)
	}
}

func TestOAuth2Init(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	oauth := OAuth2{ab}
	session := mocks.NewMockClientStorer()

	ab.OAuth2Providers = testProviders

	r, _ := http.NewRequest("GET", "/oauth2/google?redir=/my/redirect%23lol&rm=true", nil)
	w := httptest.NewRecorder()
	ctx := ab.NewContext()
	ctx.SessionStorer = session

	oauth.oauthInit(ctx, w, r)

	if w.Code != http.StatusFound {
		t.Error("Code was wrong:", w.Code)
	}

	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(loc, google.Endpoint.AuthURL) {
		t.Error("Redirected to wrong url:", loc)
	}

	query := parsed.Query()
	if query["include_requested_scopes"][0] != "true" {
		t.Error("Missing extra parameters:", loc)
	}
	state := query[authboss.FormValueOAuth2State][0]
	if len(state) == 0 {
		t.Error("It should have had some state:", loc)
	}

	if params := session.Values[authboss.SessionOAuth2Params]; params != `{"redir":"/my/redirect#lol","rm":"true"}` {
		t.Error("The params were wrong:", params)
	}
}

func TestOAuthSuccess(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	oauth := OAuth2{ab}

	expiry := time.Now().UTC().Add(3600 * time.Second)
	fakeToken := &oauth2.Token{
		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       expiry,
	}

	fakeCallback := func(_ context.Context, _ oauth2.Config, _ *oauth2.Token) (authboss.Attributes, error) {
		return authboss.Attributes{
			authboss.StoreOAuth2UID: "uid",
			authboss.StoreEmail:     "email",
		}, nil
	}

	saveExchange := exchanger
	defer func() {
		exchanger = saveExchange
	}()
	exchanger = func(_ *oauth2.Config, _ context.Context, _ string) (*oauth2.Token, error) {
		return fakeToken, nil
	}

	ab.OAuth2Providers = map[string]authboss.OAuth2Provider{
		"fake": authboss.OAuth2Provider{
			OAuth2Config: &oauth2.Config{
				ClientID:     `jazz`,
				ClientSecret: `hands`,
				Scopes:       []string{`profile`, `email`},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "fakeauth",
					TokenURL: "faketoken",
				},
			},
			Callback:         fakeCallback,
			AdditionalParams: url.Values{"include_requested_scopes": []string{"true"}},
		},
	}

	values := make(url.Values)
	values.Set("code", "code")
	values.Set("state", "state")

	url := fmt.Sprintf("/oauth2/fake?%s", values.Encode())
	r, _ := http.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	ctx := ab.NewContext()
	session := mocks.NewMockClientStorer()
	session.Put(authboss.SessionOAuth2State, authboss.FormValueOAuth2State)
	session.Put(authboss.SessionOAuth2Params, `{"redir":"/myurl?myparam=5","rm":"true"}`)

	storer := mocks.NewMockStorer()
	ctx.SessionStorer = session
	ab.OAuth2Storer = storer
	ab.AuthLoginOKPath = "/fakeloginok"

	if err := oauth.oauthCallback(ctx, w, r); err != nil {
		t.Error(err)
	}

	key := "uidfake"
	user, ok := storer.Users[key]
	if !ok {
		t.Error("Couldn't find user.")
	}

	if val, _ := user.String(authboss.StoreEmail); val != "email" {
		t.Error("Email was wrong:", val)
	}
	if val, _ := user.String(authboss.StoreOAuth2Token); val != "token" {
		t.Error("Token was wrong:", val)
	}
	if val, _ := user.String(authboss.StoreOAuth2Refresh); val != "refresh" {
		t.Error("Refresh was wrong:", val)
	}
	if val, _ := user.DateTime(authboss.StoreOAuth2Expiry); !val.Equal(expiry) {
		t.Error("Expiry was wrong:", val)
	}

	if val, _ := session.Get(authboss.SessionKey); val != "uid;fake" {
		t.Error("User was not logged in:", val)
	}
	if _, ok := session.Get(authboss.SessionOAuth2State); ok {
		t.Error("Expected state to be deleted.")
	}

	if w.Code != http.StatusFound {
		t.Error("It should redirect")
	} else if loc := w.Header().Get("Location"); loc != "/myurl?myparam=5" {
		t.Error("Redirect is wrong:", loc)
	}
}

func TestOAuthXSRFFailure(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	oauth := OAuth2{ab}

	session := mocks.NewMockClientStorer()
	session.Put(authboss.SessionOAuth2State, authboss.FormValueOAuth2State)

	ab.OAuth2Providers = testProviders

	values := url.Values{}
	values.Set(authboss.FormValueOAuth2State, "notstate")
	values.Set("code", "code")

	ctx := ab.NewContext()
	ctx.SessionStorer = session
	r, _ := http.NewRequest("GET", "/oauth2/google?"+values.Encode(), nil)

	err := oauth.oauthCallback(ctx, nil, r)
	if err != errOAuthStateValidation {
		t.Error("Should have gotten an error about state validation:", err)
	}
}

func TestOAuthFailure(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	oauth := OAuth2{ab}

	ab.OAuth2Providers = testProviders

	values := url.Values{}
	values.Set("error", "something")
	values.Set("error_reason", "auth_failure")
	values.Set("error_description", "Failed to auth.")

	ctx := ab.NewContext()
	session := mocks.NewMockClientStorer()
	session.Put(authboss.SessionOAuth2State, authboss.FormValueOAuth2State)
	ctx.SessionStorer = session
	r, _ := http.NewRequest("GET", "/oauth2/google?"+values.Encode(), nil)

	err := oauth.oauthCallback(ctx, nil, r)
	if red, ok := err.(authboss.ErrAndRedirect); !ok {
		t.Error("Should be a redirect error")
	} else if len(red.FlashError) == 0 {
		t.Error("Should have a flash error.")
	} else if red.Err.Error() != "auth_failure" {
		t.Error("It should record the failure.")
	}
}
*/
