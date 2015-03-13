package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

var testAddress = "localhost:23232"

var testProviders = map[string]authboss.OAuthProvider{
	"google": authboss.OAuthProvider{
		OAuth2Config: &oauth2.Config{
			ClientID:     `jazz`,
			ClientSecret: `hands`,
			Scopes:       []string{`profile`, `email`},
			Endpoint:     GoogleEndpoint,
		},
		Callback:         Google,
		AdditionalParams: url.Values{"include_requested_scopes": []string{"true"}},
	},
}

func TestMain(m *testing.M) {
	/*listener, err := net.Listen(testAddress)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_init_success", func(w http.ResponseWriter, r *http.Request) {
		vals := url.Values{
			"code": "test",
		}
		io.WriteString(w, vals.Encode())
	})
	mux.HandleFunc("/oauth_init_fail", func(w http.ResponseWriter, r *http.Request) {
		vals := url.Values{
			"error":             "error",
			"error_reason":      "access_denied",
			"error_description": "The user denied your request.",
		}
		io.WriteString(w, vals.Encode())
	})
	mux.HandleFunc("/oauth_token", func(w http.ResponseWriter, r *http.Request) {
		vals := url.Values{
			"access_token": "ya29.MgEXfCc5ipyWWEXxcyR0fV7oqlbHQ1xQTDARQlciDYoWlQB72VTgsTeD-8diiB_2cxaXEGMvEpvhZQ",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		io.WriteString(w, vals.Encode())
	})
	go http.Serve(listener, mux)*/

	code := m.Run()

	os.Exit(code)
}

func TestOAuth2Init(t *testing.T) {
	cfg := authboss.NewConfig()
	session := mocks.NewMockClientStorer()

	cfg.OAuth2Providers = testProviders
	authboss.Cfg = cfg

	r, _ := http.NewRequest("GET", "/oauth2/google", nil)
	w := httptest.NewRecorder()
	ctx := authboss.NewContext()
	ctx.SessionStorer = session

	oauthInit(ctx, w, r)

	if w.Code != http.StatusFound {
		t.Error("Code was wrong:", w.Code)
	}

	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(loc, GoogleEndpoint.AuthURL) {
		t.Error("Redirected to wrong url:", loc)
	}

	query := parsed.Query()
	if query["include_requested_scopes"][0] != "true" {
		t.Error("Missing extra parameters:", loc)
	}
}
