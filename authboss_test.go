package authboss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthBossInit(t *testing.T) {
	t.Parallel()

	ab := New()
	err := ab.Init()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAuthbossUpdatePassword(t *testing.T) {
	t.Parallel()

	user := &mockUser{}
	storer := newMockServerStorer()

	ab := New()
	ab.Config.Storage.Server = storer

	if err := ab.UpdatePassword(context.Background(), user, "hello world"); err != nil {
		t.Error(err)
	}

	if len(user.Password) == 0 {
		t.Error("password was not updated")
	}
}

func TestAuthbossMiddleware(t *testing.T) {
	t.Parallel()

	ab := New()
	ab.Core.Logger = mockLogger{}

	mid := Middleware(ab)

	r := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	w := ab.NewResponse(rec)

	called := false
	hadUser := false
	server := mid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		hadUser = r.Context().Value(CTXKeyUser) != nil
		w.WriteHeader(http.StatusOK)
	}))

	var err error
	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}
	server.ServeHTTP(w, r)
	if called || hadUser {
		t.Error("should not be called or have a user when no session variables have been provided")
	}
	if rec.Code != http.StatusNotFound {
		t.Error("want a not found code")
	}

	ab.Storage.SessionState = mockClientStateReadWriter{
		state: mockClientState{SessionKey: "test@test.com"},
	}
	ab.Storage.Server = &mockServerStorer{
		Users: map[string]*mockUser{
			"test@test.com": &mockUser{},
		},
	}

	r = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	w = ab.NewResponse(rec)

	r, err = ab.LoadClientState(w, r)
	if err != nil {
		t.Fatal(err)
	}
	server.ServeHTTP(w, r)
	if !called {
		t.Error("it should have been called")
	}
	if !hadUser {
		t.Error("it should have had a user loaded")
	}
	if rec.Code != http.StatusOK {
		t.Error("want a not found code")
	}
}
