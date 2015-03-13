package remember

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"gopkg.in/authboss.v0"
	"gopkg.in/authboss.v0/internal/mocks"
)

func TestInitialize(t *testing.T) {
	authboss.NewConfig()

	r := &Remember{}
	err := r.Initialize()
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	authboss.Cfg.Storer = mocks.MockFailStorer{}
	err = r.Initialize()
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	authboss.Cfg.Storer = mocks.NewMockStorer()
	err = r.Initialize()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	r := Remember{}
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()

	req, err := http.NewRequest("POST", "http://localhost", bytes.NewBufferString("rm=true"))
	if err != nil {
		t.Error("Unexpected Error:", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx, err := authboss.ContextFromRequest(req)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	ctx.SessionStorer = session
	ctx.CookieStorer = cookies
	ctx.User = authboss.Attributes{authboss.Cfg.PrimaryID: "test@email.com"}

	if err := r.afterAuth(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authboss.CookieRemember]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestAfterOAuth(t *testing.T) {
	r := Remember{}
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()

	uri := fmt.Sprintf("%s?state=%s", "localhost/oauthed", url.QueryEscape("xsrf;rm=true"))
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		t.Error("Unexpected Error:", err)
	}

	ctx, err := authboss.ContextFromRequest(req)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	ctx.SessionStorer = session
	ctx.CookieStorer = cookies
	ctx.User = authboss.Attributes{
		authboss.StoreOAuth2UID:      "uid",
		authboss.StoreOAuth2Provider: "google",
	}

	if err := r.afterOAuth(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authboss.CookieRemember]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestAfterPasswordReset(t *testing.T) {
	r := Remember{}
	authboss.NewConfig()

	id := "test@email.com"

	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	session := mocks.NewMockClientStorer()
	cookies := mocks.NewMockClientStorer()
	storer.Tokens[id] = []string{"one", "two"}
	cookies.Values[authboss.CookieRemember] = "token"

	ctx := authboss.NewContext()
	ctx.User = authboss.Attributes{authboss.Cfg.PrimaryID: id}
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies

	if err := r.afterPassword(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authboss.CookieRemember]; ok {
		t.Error("Expected the remember cookie to be deleted.")
	}

	if len(storer.Tokens) != 0 {
		t.Error("Should have wiped out all tokens.")
	}
}

func TestNew(t *testing.T) {
	r := &Remember{}
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer
	cookies := mocks.NewMockClientStorer()

	key := "tester"
	token, err := r.new(cookies, key)

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if len(token) == 0 {
		t.Error("Expected a token.")
	}

	if tok, ok := storer.Tokens[key]; !ok {
		t.Error("Expected it to store against the key:", key)
	} else if len(tok) != 1 || len(tok[0]) == 0 {
		t.Error("Expected a token to be saved.")
	}

	if token != cookies.Values[authboss.CookieRemember] {
		t.Error("Expected a cookie set with the token.")
	}
}

func TestAuth(t *testing.T) {
	r := &Remember{}
	authboss.NewConfig()
	storer := mocks.NewMockStorer()
	authboss.Cfg.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()
	ctx := authboss.NewContext()
	ctx.CookieStorer = cookies
	ctx.SessionStorer = session

	key := "tester"
	_, err := r.new(cookies, key)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	cookie, _ := cookies.Get(authboss.CookieRemember)

	interrupt, err := r.auth(ctx)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if session.Values[authboss.SessionHalfAuthKey] != "true" {
		t.Error("The user should have been half-authed.")
	}

	if session.Values[authboss.SessionKey] != key {
		t.Error("The user should have been logged in.")
	}

	if chocolateChip, _ := cookies.Get(authboss.CookieRemember); chocolateChip == cookie {
		t.Error("Expected cookie to be different")
	}

	if authboss.InterruptNone != interrupt {
		t.Error("Keys should have matched:", interrupt)
	}
}
