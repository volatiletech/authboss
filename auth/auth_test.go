package auth

import (
	"bytes"
	"errors"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/authboss.v1"
	"gopkg.in/authboss.v1/internal/mocks"
)

func testSetup() (a *Auth, s *mocks.MockStorer) {
	s = mocks.NewMockStorer()

	ab := authboss.New()
	ab.LogWriter = ioutil.Discard
	ab.Layout = template.Must(template.New("").Parse(`{{template "authboss" .}}`))
	ab.Storer = s
	ab.XSRFName = "xsrf"
	ab.XSRFMaker = func(_ http.ResponseWriter, _ *http.Request) string {
		return "xsrfvalue"
	}
	ab.PrimaryID = authboss.StoreUsername

	a = &Auth{}
	if err := a.Initialize(ab); err != nil {
		panic(err)
	}

	return a, s
}

func testRequest(ab *authboss.Authboss, method string, postFormValues ...string) (*authboss.Context, *httptest.ResponseRecorder, *http.Request, authboss.ClientStorerErr) {
	sessionStorer := mocks.NewMockClientStorer()
	ctx := ab.NewContext()
	r := mocks.MockRequest(method, postFormValues...)
	ctx.SessionStorer = sessionStorer

	return ctx, httptest.NewRecorder(), r, sessionStorer
}

func TestAuth(t *testing.T) {
	t.Parallel()

	a, _ := testSetup()

	storage := a.Storage()
	if storage[a.PrimaryID] != authboss.String {
		t.Error("Expected storage KV:", a.PrimaryID, authboss.String)
	}
	if storage[authboss.StorePassword] != authboss.String {
		t.Error("Expected storage KV:", authboss.StorePassword, authboss.String)
	}

	routes := a.Routes()
	if routes["/login"] == nil {
		t.Error("Expected route '/login' with handleFunc")
	}
	if routes["/logout"] == nil {
		t.Error("Expected route '/logout' with handleFunc")
	}
}

func TestAuth_loginHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	a, _ := testSetup()
	ctx, w, r, _ := testRequest(a.Authboss, "GET")

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("Should have rendered a form")
	}
	if !strings.Contains(body, `name="`+a.PrimaryID) {
		t.Error("Form should contain the primary ID field:", body)
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("Form should contain password field:", body)
	}
}

func TestAuth_loginHandlerFunc_POST_ReturnsErrorOnCallbackFailure(t *testing.T) {
	t.Parallel()

	a, storer := testSetup()
	storer.Users["john"] = authboss.Attributes{"password": "$2a$10$B7aydtqVF9V8RSNx3lCKB.l09jqLV/aMiVqQHajtL7sWGhCS9jlOu"}

	a.Callbacks = authboss.NewCallbacks()
	a.Callbacks.Before(authboss.EventAuth, func(_ *authboss.Context) (authboss.Interrupt, error) {
		return authboss.InterruptNone, errors.New("explode")
	})

	ctx, w, r, _ := testRequest(a.Authboss, "POST", "username", "john", "password", "1234")

	if err := a.loginHandlerFunc(ctx, w, r); err.Error() != "explode" {
		t.Error("Unexpected error:", err)
	}
}

func TestAuth_loginHandlerFunc_POST_RedirectsWhenInterrupted(t *testing.T) {
	t.Parallel()

	a, storer := testSetup()
	storer.Users["john"] = authboss.Attributes{"password": "$2a$10$B7aydtqVF9V8RSNx3lCKB.l09jqLV/aMiVqQHajtL7sWGhCS9jlOu"}

	a.Callbacks = authboss.NewCallbacks()
	a.Callbacks.Before(authboss.EventAuth, func(_ *authboss.Context) (authboss.Interrupt, error) {
		return authboss.InterruptAccountLocked, nil
	})

	ctx, w, r, sessionStore := testRequest(a.Authboss, "POST", "username", "john", "password", "1234")

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusFound {
		t.Error("Unexpected status:", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc != a.AuthLoginFailPath {
		t.Error("Unexpeced location:", loc)
	}

	expectedMsg := "Your account has been locked."
	if msg, ok := sessionStore.Get(authboss.FlashErrorKey); !ok || msg != expectedMsg {
		t.Error("Expected error flash message:", expectedMsg)
	}

	a.Callbacks = authboss.NewCallbacks()
	a.Callbacks.Before(authboss.EventAuth, func(_ *authboss.Context) (authboss.Interrupt, error) {
		return authboss.InterruptAccountNotConfirmed, nil
	})

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusFound {
		t.Error("Unexpected status:", w.Code)
	}

	loc = w.Header().Get("Location")
	if loc != a.AuthLoginFailPath {
		t.Error("Unexpeced location:", loc)
	}

	expectedMsg = "Your account has not been confirmed."
	if msg, ok := sessionStore.Get(authboss.FlashErrorKey); !ok || msg != expectedMsg {
		t.Error("Expected error flash message:", expectedMsg)
	}
}

func TestAuth_loginHandlerFunc_POST_AuthenticationFailure(t *testing.T) {
	t.Parallel()

	a, _ := testSetup()

	log := &bytes.Buffer{}
	a.LogWriter = log

	ctx, w, r, _ := testRequest(a.Authboss, "POST", "username", "john", "password", "1")

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid username and/or password") {
		t.Error("Should have rendered with error")
	}

	ctx, w, r, _ = testRequest(a.Authboss, "POST", "username", "john", "password", "1234")

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body = w.Body.String()
	if !strings.Contains(body, "invalid username and/or password") {
		t.Error("Should have rendered with error")
	}

	ctx, w, r, _ = testRequest(a.Authboss, "POST", "username", "jake", "password", "1")

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if w.Code != http.StatusOK {
		t.Error("Unexpected status:", w.Code)
	}

	body = w.Body.String()
	if !strings.Contains(body, "invalid username and/or password") {
		t.Error("Should have rendered with error")
	}
}

func TestAuth_loginHandlerFunc_POST(t *testing.T) {
	t.Parallel()

	a, storer := testSetup()
	storer.Users["john"] = authboss.Attributes{"password": "$2a$10$B7aydtqVF9V8RSNx3lCKB.l09jqLV/aMiVqQHajtL7sWGhCS9jlOu"}

	ctx, w, r, _ := testRequest(a.Authboss, "POST", "username", "john", "password", "1234")
	cb := mocks.NewMockAfterCallback()

	a.Callbacks = authboss.NewCallbacks()
	a.Callbacks.After(authboss.EventAuth, cb.Fn)
	a.AuthLoginOKPath = "/dashboard"

	sessions := mocks.NewMockClientStorer()
	ctx.SessionStorer = sessions

	if err := a.loginHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if _, ok := ctx.Values[authboss.CookieRemember]; !ok {
		t.Error("Authboss cookie remember should be set for the callback")
	}
	if !cb.HasBeenCalled {
		t.Error("Expected after callback to have been called")
	}

	if w.Code != http.StatusFound {
		t.Error("Unexpected status:", w.Code)
	}

	loc := w.Header().Get("Location")
	if loc != a.AuthLoginOKPath {
		t.Error("Unexpeced location:", loc)
	}

	val, ok := sessions.Values[authboss.SessionKey]
	if !ok {
		t.Error("Expected session to be set")
	} else if val != "john" {
		t.Error("Expected session value to be authed username")
	}
}

func TestAuth_loginHandlerFunc_OtherMethods(t *testing.T) {
	t.Parallel()

	a, _ := testSetup()
	methods := []string{"HEAD", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		r, err := http.NewRequest(method, "/login", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
		}
		w := httptest.NewRecorder()

		if err := a.loginHandlerFunc(nil, w, r); err != nil {
			t.Errorf("%d> Unexpected error: %s", i, err)
		}

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}

func TestAuth_validateCredentials(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	storer := mocks.NewMockStorer()
	ab.Storer = storer

	ctx := ab.NewContext()
	storer.Users["john"] = authboss.Attributes{"password": "$2a$10$pgFsuQwdhwOdZp/v52dvHeEi53ZaI7dGmtwK4bAzGGN5A4nT6doqm"}
	if _, err := validateCredentials(ctx, "john", "a"); err != nil {
		t.Error("Unexpected error:", err)
	}

	ctx = ab.NewContext()
	if valid, err := validateCredentials(ctx, "jake", "a"); err != nil {
		t.Error("Expect no error when user not found:", err)
	} else if valid {
		t.Error("Expect invalid when not user found")
	}

	ctx = ab.NewContext()
	storer.GetErr = "Failed to load user"
	if _, err := validateCredentials(ctx, "", ""); err.Error() != "Failed to load user" {
		t.Error("Unexpected error:", err)
	}

}

func TestAuth_logoutHandlerFunc_GET(t *testing.T) {
	t.Parallel()

	a, _ := testSetup()

	a.AuthLogoutOKPath = "/dashboard"

	ctx, w, r, sessionStorer := testRequest(a.Authboss, "GET")
	sessionStorer.Put(authboss.SessionKey, "asdf")
	sessionStorer.Put(authboss.SessionLastAction, "1234")

	cookieStorer := mocks.NewMockClientStorer(authboss.CookieRemember, "qwert")
	ctx.CookieStorer = cookieStorer

	if err := a.logoutHandlerFunc(ctx, w, r); err != nil {
		t.Error("Unexpected error:", err)
	}

	if val, ok := sessionStorer.Get(authboss.SessionKey); ok {
		t.Error("Unexpected session key:", val)
	}

	if val, ok := sessionStorer.Get(authboss.SessionLastAction); ok {
		t.Error("Unexpected last action:", val)
	}

	if val, ok := cookieStorer.Get(authboss.CookieRemember); ok {
		t.Error("Unexpected rm cookie:", val)
	}

	if http.StatusFound != w.Code {
		t.Errorf("Expected status code %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("Expected lcoation %s, got %s", "/dashboard", location)
	}
}

func TestAuth_logoutHandlerFunc_OtherMethods(t *testing.T) {
	a, _ := testSetup()

	methods := []string{"HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"}

	for i, method := range methods {
		r, err := http.NewRequest(method, "/logout", nil)
		if err != nil {
			t.Errorf("%d> Unexpected error '%s'", i, err)
		}
		w := httptest.NewRecorder()

		if err := a.logoutHandlerFunc(nil, w, r); err != nil {
			t.Errorf("%d> Unexpected error: %s", i, err)
		}

		if http.StatusMethodNotAllowed != w.Code {
			t.Errorf("%d> Expected status code %d, got %d", i, http.StatusMethodNotAllowed, w.Code)
			continue
		}
	}
}
