package remember

import (
	"bytes"
	"net/http"
	"testing"

	"gopkg.in/authboss.v0"
)

type testClientStorer map[string]string

func (t testClientStorer) Put(key, value string) {
	t[key] = value
}

func (t testClientStorer) Get(key string) (string, bool) {
	s, ok := t[key]
	return s, ok
}

type testStorer struct {
}

func (t testStorer) Create(key string, attr authboss.Attributes) error { return nil }
func (t testStorer) Put(key string, attr authboss.Attributes) error    { return nil }
func (t testStorer) Get(key string, attrMeta authboss.AttributeMeta) (interface{}, error) {
	return nil, nil
}

type testTokenStorer struct {
	testStorer
	key   string
	token string
}

func (t *testTokenStorer) AddToken(key, token string) error {
	t.key = key
	t.token = token
	return nil
}
func (t *testTokenStorer) DelTokens(key string) error {
	t.key = ""
	t.token = ""
	return nil
}
func (t *testTokenStorer) UseToken(givenKey, token string) (key string, err error) {
	if givenKey == t.key {
		ret := t.key
		t.key = ""
		t.token = ""
		return ret, nil
	}
	return "", authboss.TokenNotFound
}

func TestInitialize(t *testing.T) {
	testConfig := authboss.NewConfig()

	r := &Remember{}
	err := r.Initialize(testConfig)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	testConfig.Storer = testStorer{}
	err = r.Initialize(testConfig)
	if err == nil {
		t.Error("Expected error about token storers.")
	}

	testConfig.Storer = &testTokenStorer{}
	err = r.Initialize(testConfig)
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAfterAuth(t *testing.T) {
	storer := &testTokenStorer{}
	R.storer = storer
	cookies := make(testClientStorer)
	session := make(testClientStorer)

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
	ctx.User = authboss.Attributes{"username": "testuser"}

	R.AfterAuth(ctx)

	if _, ok := cookies[ValueKey]; !ok {
		t.Error("Expected a cookie to have been set.")
	}
}

func TestNew(t *testing.T) {
	storer := &testTokenStorer{}
	R.storer = storer
	cookies := make(testClientStorer)

	key := "tester"
	token, err := R.New(cookies, key)

	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if len(token) == 0 {
		t.Error("Expected a token.")
	}

	if storer.key != key {
		t.Error("Expected it to store against the key:", storer.key)
	}

	if token != cookies[ValueKey] {
		t.Error("Expected a cookie set with the token.")
	}

	if len(storer.token) == 0 {
		t.Error("Expected a token to be saved.")
	}
}

func TestAuth(t *testing.T) {
	storer := &testTokenStorer{}
	R.storer = storer
	cookies := make(testClientStorer)
	session := make(testClientStorer)

	key := "tester"
	token, err := R.New(cookies, key)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	outKey, err := R.Auth(cookies, session, token)
	if err != nil {
		t.Error("Unexpected error:", err)
	}

	if session[HalfAuthKey] != "true" {
		t.Error("The user should have been half-authed.")
	}

	if session[authboss.SessionKey] != key {
		t.Error("The user should have been logged in.")
	}

	if key != outKey {
		t.Error("Keys should have matched:", outKey)
	}
}
