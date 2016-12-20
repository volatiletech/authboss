package oauth2

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"gopkg.in/authboss.v1"
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

	user, err := Google(context.TODO(), cfg, tok)
	if err != nil {
		t.Error(err)
	}

	if uid, ok := user[authboss.StoreOAuth2UID]; !ok || uid != "id" {
		t.Error("UID wrong:", uid)
	}
	if email, ok := user[authboss.StoreEmail]; !ok || email != "email" {
		t.Error("Email wrong:", email)
	}
}

func TestFacebook(t *testing.T) {
	saveClientGet := clientGet
	defer func() {
		clientGet = saveClientGet
	}()

	clientGet = func(_ *http.Client, url string) (*http.Response, error) {
		return &http.Response{
			Body: ioutil.NopCloser(strings.NewReader(`{"id":"id", "email":"email", "name":"name"}`)),
		}, nil
	}

	cfg := *testProviders["facebook"].OAuth2Config
	tok := &oauth2.Token{
		AccessToken:  "token",
		TokenType:    "Bearer",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(60 * time.Minute),
	}

	user, err := Facebook(context.TODO(), cfg, tok)
	if err != nil {
		t.Error(err)
	}

	if uid, ok := user[authboss.StoreOAuth2UID]; !ok || uid != "id" {
		t.Error("UID wrong:", uid)
	}
	if email, ok := user[authboss.StoreEmail]; !ok || email != "email" {
		t.Error("Email wrong:", email)
	}
	if name, ok := user["name"]; !ok || name != "name" {
		t.Error("Name wrong:", name)
	}
}
