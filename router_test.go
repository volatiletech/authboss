package authboss

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testRouterMod struct {
	handler HandlerFunc
	routes  RouteTable
}

func (t testRouterMod) Initialize() error       { return nil }
func (t testRouterMod) Routes() RouteTable      { return t.routes }
func (t testRouterMod) Storage() StorageOptions { return nil }

func testRouterSetup() (http.Handler, *bytes.Buffer) {
	Cfg = NewConfig()
	Cfg.MountPath = "/prefix"
	Cfg.SessionStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return mockClientStore{} }
	Cfg.CookieStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return mockClientStore{} }
	logger := &bytes.Buffer{}
	Cfg.LogWriter = logger

	return NewRouter(), logger
}

func testRouterCallbackSetup(path string, h HandlerFunc) (w *httptest.ResponseRecorder, r *http.Request) {
	modules = map[string]Modularizer{
		"test": testRouterMod{
			routes: map[string]HandlerFunc{
				path: h,
			},
		},
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

	router, _ := testRouterSetup()

	router.ServeHTTP(w, r)

	if !called {
		t.Error("Expected handler to be called.")
	}
}

func TestRouter_NotFound(t *testing.T) {
	router, _ := testRouterSetup()
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
	Cfg.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	router, logger := testRouterSetup()
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
	Cfg.BadRequestHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	router, logger := testRouterSetup()
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
	Cfg.ErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	router, logger := testRouterSetup()

	session := mockClientStore{}
	Cfg.SessionStoreMaker = func(w http.ResponseWriter, r *http.Request) ClientStorer { return session }

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
