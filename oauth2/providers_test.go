package oauth2

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGoogle(t *testing.T) {
	saveClientGet := clientGet
	defer func() {
		clientGet = saveClientGet
	}()

	clientGet = func(_ *http.Client, url string) (*http.Response, error) {
		return &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(`{"id":"id", "email":"email"}`)),
		}, nil
	}

	cfg := *testProviders["google"].OAuth2Config
	tok := &oauth2.Token{
		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(60 * time.Minute),
	}

	cred, err := Google(cfg, tok)
	if err != nil {
		t.Error(err)
	}

	if cred.UID != "id" {
		t.Error("UID wrong:", cred.UID)
	}
	if cred.Email != "email" {
		t.Error("Email wrong:", cred.Email)
	}
}
