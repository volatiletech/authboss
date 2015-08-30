package authboss

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testRouterModName = "testrouter"

func init() {
	RegisterModule(testRouterModName, testRouterModule{})
}

type testRouterModule struct {
	routes RouteTable
}

func (t testRouterModule) Initialize(ab *Authboss) error { return nil }
func (t testRouterModule) Routes() RouteTable            { return t.routes }
func (t testRouterModule) Storage() StorageOptions       { return nil }

func testRouterSetup() (*Authboss, http.Handler, *bytes.Buffer) {
	ab := New()
	logger := &bytes.Buffer{}
	ab.LogWriter = logger
	ab.Init(testRouterModName)
	ab.MountPath = "/prefix"
	ab.SessionStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return mockClientStore{} }
	ab.CookieStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return mockClientStore{} }

	logger.Reset() // Clear out the module load messages

	return ab, ab.NewRouter(), logger
}

// testRouterCallbackSetup is NOT safe for use by multiple goroutines, don't use parallel
func testRouterCallbackSetup(path string, h HandlerFunc) (w *httptest.ResponseRecorder, r *http.Request) {
	registeredModules[testRouterModName] = testRouterModule{
		routes: map[string]HandlerFunc{path: h},
	}

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "http://localhost/prefix"+path, nil)

	return w, r
}

func TestRouter(t *testing.T) {
	called := false

	w, r := testRouterCallbackSetup("/called", func(ctx *Context, w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})

	_, router, _ := testRouterSetup()

	router.ServeHTTP(w, r)

	if !called {
		t.Error("Expected handler to be called.")
	}
}

func TestRouter_NotFound(t *testing.T) {
	ab, router, _ := testRouterSetup()
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://localhost/wat", nil)

	router.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Error("Wrong code:", w.Code)
	}
	if body := w.Body.String(); body != "404 Page not found" {
		t.Error("Wrong body:", body)
	}

	called := false
	ab.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	router.ServeHTTP(w, r)
	if !called {
		t.Error("Should be called.")
	}
}

func TestRouter_BadRequest(t *testing.T) {
	err := ClientDataErr{"what"}
	w, r := testRouterCallbackSetup("/badrequest",
		func(ctx *Context, w http.ResponseWriter, r *http.Request) error {
			return err
		},
	)

	ab, router, logger := testRouterSetup()
	logger.Reset()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Error("Wrong code:", w.Code)
	}
	if body := w.Body.String(); body != "400 Bad request" {
		t.Error("Wrong body:", body)
	}

	if str := logger.String(); !strings.Contains(str, err.Error()) {
		t.Error(str)
	}

	called := false
	ab.BadRequestHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	logger.Reset()
	router.ServeHTTP(w, r)
	if !called {
		t.Error("Should be called.")
	}

	if str := logger.String(); !strings.Contains(str, err.Error()) {
		t.Error(str)
	}
}

func TestRouter_Error(t *testing.T) {
	err := errors.New("error")
	w, r := testRouterCallbackSetup("/error",
		func(ctx *Context, w http.ResponseWriter, r *http.Request) error {
			return err
		},
	)

	ab, router, logger := testRouterSetup()
	logger.Reset()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Error("Wrong code:", w.Code)
	}
	if body := w.Body.String(); body != "500 An error has occurred" {
		t.Error("Wrong body:", body)
	}

	if str := logger.String(); !strings.Contains(str, err.Error()) {
		t.Error(str)
	}

	called := false
	ab.ErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	logger.Reset()
	router.ServeHTTP(w, r)
	if !called {
		t.Error("Should be called.")
	}

	if str := logger.String(); !strings.Contains(str, err.Error()) {
		t.Error(str)
	}
}

func TestRouter_Redirect(t *testing.T) {
	err := ErrAndRedirect{
		Err:          errors.New("error"),
		Location:     "/",
		FlashSuccess: "yay",
		FlashError:   "nay",
	}

	w, r := testRouterCallbackSetup("/error",
		func(ctx *Context, w http.ResponseWriter, r *http.Request) error {
			return err
		},
	)

	ab, router, logger := testRouterSetup()

	session := mockClientStore{}
	ab.SessionStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return session }

	logger.Reset()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Error("Wrong code:", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != err.Location {
		t.Error("Wrong location:", loc)
	}
	if succ, ok := session.Get(FlashSuccessKey); !ok || succ != err.FlashSuccess {
		t.Error(succ, ok)
	}
	if fail, ok := session.Get(FlashErrorKey); !ok || fail != err.FlashError {
		t.Error(fail, ok)
	}
}

func TestRouter_redirectIfLoggedIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Path       string
		LoggedIn   bool
		HalfAuthed bool

		ShouldRedirect bool
	}{
		// These routes will be accessed depending on logged in and half auth's value
		{"/auth", false, false, false},
		{"/auth", true, false, true},
		{"/auth", true, true, false},
		{"/oauth2/facebook", false, false, false},
		{"/oauth2/facebook", true, false, true},
		{"/oauth2/facebook", true, true, false},
		{"/oauth2/callback/facebook", false, false, false},
		{"/oauth2/callback/facebook", true, false, true},
		{"/oauth2/callback/facebook", true, true, false},
		// These are logout routes and never redirect
		{"/logout", true, false, false},
		{"/logout", true, true, false},
		{"/oauth2/logout", true, false, false},
		{"/oauth2/logout", true, true, false},
		// These routes should always redirect despite half auth
		{"/register", true, true, true},
		{"/recover", true, true, true},
		{"/register", false, false, false},
		{"/recover", false, false, false},
	}

	storer := mockStorer{"john@john.com": Attributes{
		StoreEmail:    "john@john.com",
		StorePassword: "password",
	}}
	ab := New()
	ab.Storer = storer

	for i, test := range tests {
		session := mockClientStore{}
		cookies := mockClientStore{}
		ctx := ab.NewContext()
		ctx.SessionStorer = session
		ctx.CookieStorer = cookies

		if test.LoggedIn {
			session[SessionKey] = "john@john.com"
		}
		if test.HalfAuthed {
			session[SessionHalfAuthKey] = "true"
		}

		r, _ := http.NewRequest("GET", test.Path, nil)
		w := httptest.NewRecorder()
		handled := redirectIfLoggedIn(ctx, w, r)

		if test.ShouldRedirect && (!handled || w.Code != http.StatusFound) {
			t.Errorf("%d) It should have redirected the request: %q %t %d", i, test.Path, handled, w.Code)
		} else if !test.ShouldRedirect && (handled || w.Code != http.StatusOK) {
			t.Errorf("%d) It should have NOT redirected the request: %q %t %d", i, test.Path, handled, w.Code)
		}
	}
}

type deathStorer struct{}

func (d deathStorer) Create(key string, attributes Attributes) error { return nil }
func (d deathStorer) Put(key string, attributes Attributes) error    { return nil }
func (d deathStorer) Get(key string) (interface{}, error)            { return nil, errors.New("explosion") }

func TestRouter_redirectIfLoggedInError(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.LogWriter = ioutil.Discard
	ab.Storer = deathStorer{}

	session := mockClientStore{SessionKey: "john"}
	cookies := mockClientStore{}
	ctx := ab.NewContext()
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies

	r, _ := http.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()
	handled := redirectIfLoggedIn(ctx, w, r)

	if !handled {
		t.Error("It should have been handled.")
	}
	if w.Code != http.StatusInternalServerError {
		t.Error("It should have internal server error'd:", w.Code)
	}
}

type notFoundStorer struct{}

func (n notFoundStorer) Create(key string, attributes Attributes) error { return nil }
func (n notFoundStorer) Put(key string, attributes Attributes) error    { return nil }
func (n notFoundStorer) Get(key string) (interface{}, error)            { return nil, ErrUserNotFound }

func TestRouter_redirectIfLoggedInUserNotFound(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.LogWriter = ioutil.Discard
	ab.Storer = notFoundStorer{}

	session := mockClientStore{SessionKey: "john"}
	cookies := mockClientStore{}
	ctx := ab.NewContext()
	ctx.SessionStorer = session
	ctx.CookieStorer = cookies

	r, _ := http.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()
	handled := redirectIfLoggedIn(ctx, w, r)

	if handled {
		t.Error("It should not have been handled.")
	}
	if _, ok := session.Get(SessionKey); ok {
		t.Error("It should have removed the bad session cookie")
	}
}
