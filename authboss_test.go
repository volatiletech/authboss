package authboss

import (
	"database/sql"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMain(main *testing.M) {
	RegisterModule("testmodule", testMod)
	Cfg.LogWriter = ioutil.Discard
	Init()
	code := main.Run()
	os.Exit(code)
}

func TestAuthBossInit(t *testing.T) {
	Cfg = NewConfig()
	Cfg.LogWriter = ioutil.Discard
	err := Init()
	if err != nil {
		t.Error("Unexpected error:", err)
	}
}

func TestAuthBossCurrentUser(t *testing.T) {
	Cfg = NewConfig()
	Cfg.LogWriter = ioutil.Discard
	Cfg.Storer = mockStorer{"joe": Attributes{"email": "john@john.com", "password": "lies"}}
	Cfg.SessionStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{SessionKey: "joe"}
	}
	Cfg.CookieStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return mockClientStore{}
	}

	if err := Init(); err != nil {
		t.Error("Unexpected error:", err)
	}

	rec := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "localhost", nil)

	userStruct := CurrentUserP(rec, req)
	us := userStruct.(*mockUser)

	if us.Email != "john@john.com" || us.Password != "lies" {
		t.Error("Wrong user found!")
	}
}

func TestAuthbossUpdatePassword(t *testing.T) {
	Cfg = NewConfig()
	session := mockClientStore{}
	cookies := mockClientStore{}
	Cfg.SessionStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return session
	}
	Cfg.CookieStoreMaker = func(_ http.ResponseWriter, _ *http.Request) ClientStorer {
		return cookies
	}

	called := false
	Cfg.Callbacks.After(EventPasswordReset, func(ctx *Context) error {
		called = true
		return nil
	})

	user1 := struct {
		Password string
	}{}
	user2 := struct {
		Password sql.NullString
	}{}

	r, _ := http.NewRequest("GET", "http://localhost", nil)

	called = false
	err := UpdatePassword(nil, r, "newpassword", &user1, func() error { return nil })
	if err != nil {
		t.Error(err)
	}

	if len(user1.Password) == 0 {
		t.Error("Password not updated")
	}
	if !called {
		t.Error("Callbacks should have been called.")
	}

	called = false
	err = UpdatePassword(nil, r, "newpassword", &user2, func() error { return nil })
	if err != nil {
		t.Error(err)
	}

	if !user2.Password.Valid || len(user2.Password.String) == 0 {
		t.Error("Password not updated")
	}
	if !called {
		t.Error("Callbacks should have been called.")
	}

	called = false
	oldPassword := user1.Password
	err = UpdatePassword(nil, r, "", &user1, func() error { return nil })
	if err != nil {
		t.Error(err)
	}

	if user1.Password != oldPassword {
		t.Error("Password not updated")
	}
	if called {
		t.Error("Callbacks should not have been called")
	}
}

func TestAuthbossUpdatePasswordFail(t *testing.T) {
	user1 := struct {
		Password string
	}{}

	anErr := errors.New("AnError")
	err := UpdatePassword(nil, nil, "update", &user1, func() error { return anErr })
	if err != anErr {
		t.Error("Expected an specific error:", err)
	}
}
