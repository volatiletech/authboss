package oauth2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
	"gopkg.in/authboss.v1"
	"gopkg.in/authboss.v1/internal/mocks"
)

var testProviders = map[string]authboss.OAuth2Provider{
	"google": authboss.OAuth2Provider{
		OAuth2Config: &oauth2.Config{
			ClientID:     `jazz`,
			ClientSecret: `hands`,
			Scopes:       []string{`profile`, `email`},
			Endpoint:     google.Endpoint,
		},
		Callback:         Google,
		AdditionalParams: url.Values{"include_requested_scopes": []string{"true"}},
	},
	"facebook": authboss.OAuth2Provider{
		OAuth2Config: &oauth2.Config{
			ClientID:     `jazz`,
			ClientSecret: `hands`,
			Scopes:       []string{`email`},
			Endpoint:     facebook.Endpoint,
		},
		Callback: Facebook,
	},
}

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

func TestLogout(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	oauth := OAuth2{ab}
	ab.AuthLogoutOKPath = "/dashboard"

	r, _ := http.NewRequest("GET", "/oauth2/google?", nil)
	w := httptest.NewRecorder()

	ctx := ab.NewContext()
	session := mocks.NewMockClientStorer(authboss.SessionKey, "asdf", authboss.SessionLastAction, "1234")
	cookies := mocks.NewMockClientStorer(authboss.CookieRemember, "qwert")
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies

	if err := oauth.logout(ctx, w, r); err != nil {
		t.Error(err)
	}

	if val, ok := session.Get(authboss.SessionKey); ok {
		t.Error("Unexpected session key:", val)
	}

	if val, ok := session.Get(authboss.SessionLastAction); ok {
		t.Error("Unexpected last action:", val)
	}

	if val, ok := cookies.Get(authboss.CookieRemember); ok {
		t.Error("Unexpected rm cookie:", val)
	}

	if http.StatusFound != w.Code {
		t.Errorf("Expected status code %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != ab.AuthLogoutOKPath {
		t.Error("Redirect wrong:", location)
	}
}
