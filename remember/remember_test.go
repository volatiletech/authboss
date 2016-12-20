package remember

import (
	"bytes"
	"net/http"
	"testing"

	"gopkg.in/authboss.v1"
	"gopkg.in/authboss.v1/internal/mocks"
)

func TestInitialize(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	r := &Remember{}
	err := r.Initialize(ab)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	ab.Storer = mocks.MockFailStorer{}
	err = r.Initialize(ab)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	ab.Storer = mocks.NewMockStorer()
	err = r.Initialize(ab)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	t.Parallel()

	r := Remember{authboss.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()

	req, err := http.NewRequest("POST", "http://localhost", bytes.NewBufferString("rm=true"))
	if err != nil {
		t.Error("Unexpected Error:", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx := r.NewContext()
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies
	ctx.User = authboss.Attributes{r.PrimaryID: "test@email.com"}

	ctx.Values = map[string]string{authboss.CookieRemember: "true"}

	if err := r.afterAuth(ctx); err != nil {
		t.Error(err)
	}

	if _, ok := cookies.Values[authboss.CookieRemember]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestAfterOAuth(t *testing.T) {
	t.Parallel()

	r := Remember{authboss.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer(authboss.SessionOAuth2Params, `{"rm":"true"}`)

	ctx := r.NewContext()
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
	t.Parallel()

	r := Remember{authboss.New()}

	id := "test@email.com"

	storer := mocks.NewMockStorer()
	r.Storer = storer
	session := mocks.NewMockClientStorer()
	cookies := mocks.NewMockClientStorer()
	storer.Tokens[id] = []string{"one", "two"}
	cookies.Values[authboss.CookieRemember] = "token"

	ctx := r.NewContext()
	ctx.User = authboss.Attributes{r.PrimaryID: id}
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
	t.Parallel()

	r := &Remember{authboss.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer
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
	t.Parallel()

	r := &Remember{authboss.New()}
	storer := mocks.NewMockStorer()
	r.Storer = storer

	cookies := mocks.NewMockClientStorer()
	session := mocks.NewMockClientStorer()
	ctx := r.NewContext()
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
